# SPDX-License-Identifier: 0BSD
# Copyright (C) 2026 by outis
#Requires -Version 5.1

<#
.SYNOPSIS
    latro: collects timeline-relevant Windows triage artefacts into one zip,
    for retrieval through Microsoft Defender for Endpoint (MDE) Live Response.

.DESCRIPTION
    Upload to the Defender Live Response library and run it on a device. It
    writes <hostname>_<UTC timestamp>Z.zip under the Defender for Endpoint
    sensor's Temp folder (ProgramData\Microsoft\Windows Defender Advanced Threat
    Protection\Temp\Collections), falling back to a LiveResponseCollector folder
    in Windows\SystemTemp or the account's temp folder, and prints a
    per-artefact summary, the getfile command for the zip, and getfile commands
    for locked machine-wide files it could not read, with the SHA-256 of the
    zip (or of each volume) to check the download against. A zip larger than
    the volume size set in CONFIG is split into standard split volumes
    (<name>.zip.001, .002, ...). The zip holds collection.csv, one row per file
    the run attempted: its outcome, size, bytes copied, SHA-256 and times.

    Best effort: anything that can't be read is skipped and counted in the
    summary; the run never stops on an error. It stops only to protect the
    output or the host: a full disk, or free space below the reserve set in
    CONFIG (the zip of what was collected until then is kept, labelled
    partial, but not offered for getfile). getfile commands are printed only
    for a complete output: the whole zip or every one of its volumes. Files
    whose content isn't on the disk (cloud-only, offline) are not read, so
    nothing is downloaded. No child processes are started, and the output is
    left in place for retrieval.

.EXAMPLE
    run collector.ps1

    In a Live Response session, after uploading the script to the library.

.EXAMPLE
    .\collector.ps1

    From an elevated Windows PowerShell 5.1 prompt, e.g. for testing.

.NOTES
    Version: $CollectorVersion below (semver); changes are in CHANGELOG.md.
    Requires Windows PowerShell 5.1 (in-box modules only); no network access.
    License: 0BSD.

.LINK
    https://github.com/rbqbjyur/latro
#>

# Every empty catch {} in this script is deliberate: it guards a step whose
# failure leaves the documented default in place (a fact stays unknown, a close
# is skipped) and must never stop the rest (best effort - see the project's
# design rules). Every skip of real work has its own catch that records the
# outcome.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '',
    Justification = 'Each empty catch guards a step whose failure leaves the documented default in place (a fact stays unknown, a close is skipped); it must never stop the rest of the run.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'Internal helpers of a non-interactive Live Response script: no -WhatIf or -Confirm.')]
param()

# ============================== CONFIG ==============================

$CollectorVersion = '2.4.1'

# No script-wide error suppression: every unit of work has its own try/catch,
# so an error nobody anticipated shows (in the Live Response transcript) rather
# than vanishing. Progress bars are off: they have no place in a transcript.
$ProgressPreference = 'SilentlyContinue'

# Resolve the system drive from the environment so the script is not tied to a C:
# install; every artefact path below is taken relative to it (or to a profile).
$systemDrive = $env:SystemDrive                 # e.g. C:
if (-not $systemDrive) { $systemDrive = [System.IO.Path]::GetPathRoot([Environment]::SystemDirectory).TrimEnd('\') }

$hostName = $env:COMPUTERNAME
# UTC, so the name is unambiguous across time zones; trailing 'Z' marks it as UTC.
$runStart  = (Get-Date).ToUniversalTime()
$timestamp = $runStart.ToString('yyyyMMdd_HHmmss', [Globalization.CultureInfo]::InvariantCulture) + 'Z'

# Where the output goes, in order of preference: the first folder that can be
# created and holds the zip wins. Only the last folder in each path is ever
# created - a candidate whose parent doesn't exist is skipped. Each run adds its
# own zip, so repeated collections accumulate side by side.
$outputFolders = @(
    # The Defender for Endpoint sensor's own Temp (Live Response keeps its script
    # transcripts there too).
    Join-Path $systemDrive 'ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Temp\Collections'
    # The SYSTEM-only temp folder of newer Windows builds (SYSTEM and Administrators).
    Join-Path $systemDrive 'Windows\SystemTemp\LiveResponseCollector'
    # The running account's temp folder (for SYSTEM: C:\Windows\SystemTemp on
    # builds where GetTempPath returns it, else C:\Windows\Temp).
    Join-Path ([System.IO.Path]::GetTempPath()) 'LiveResponseCollector'
)
$zipName = "${hostName}_${timestamp}.zip"

# Largest output file. A bigger zip is split in place at the end into standard
# split volumes - <name>.zip.001, .002, ... (a byte split of the one zip: join
# them, or open .001 in 7-Zip) - so each getfile stays well within its 3 GB and
# time limits. A zip that fits is left as it is.
$zipVolumeSize = 1GB

# Seconds to wait before a failed volume is written again, or a failed rename
# tried again, while splitting (e.g. a file still held by a scanner).
$splitRetryPause = 2

# Free space the run leaves on the output folder's drive, so the run itself
# doesn't fill the drive the host writes to (services, event logs). Checked
# before each file and after each 1 MB block copied: collection stops once the
# drive is below it, and the zip of what was collected until then is kept but
# not offered for getfile (see MAIN). A split starts only if a volume fits
# above it. What the host itself writes meanwhile is beyond the run's control.
$freeSpaceReserve = 1GB

# The per-file record inside the zip, at its root beside the drive folders: one
# row per file the run attempted (see $fileRecordColumns for the columns).
$fileRecordName = 'collection.csv'

# Where user profiles live, relative to the system drive: modern first, then
# legacy (XP). Each folder under a root is one profile (see Get-UserProfilePath).
$profileRoots = @('Users', 'Documents and Settings')

# The registry's list of profiles, read only to name profiles outside
# $profileRoots, which are not searched (Get-ProfileOutsideSearchedRoot). The
# service accounts' entries are left out: rows name their paths explicitly.
$profileListKey     = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$serviceAccountSids = @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')   # SYSTEM, LocalService, NetworkService

# Reasons a gap is normal for the host, given by the artefact rows'
# AbsentByDefault spans so the same reason always reads the same in the summary.
# Only where the knowledge base holds the artefact absent there by default on
# settled ground - never usage or changeable state, as an artefact that is
# merely empty or absent may have been removed and belongs under Warnings.
$gapReasons = @{
    ServerOnly     = 'Windows Server only'
    WindowsVersion = 'not on this Windows version'
    OffByDefault   = 'off by default'
}

# Artefacts to collect: one row per summary line. Add an artefact by adding a row.
#   Name     Summary label.
#   Group    1 = drive root (NTFS metafiles), 2 = other system files, 3 = user-specific.
#   System   Path pattern(s) relative to the system drive (or to each drive, see
#            Drives).
#   Drives   Which drives the System patterns apply to: 'System' (the default; the
#            system drive only), 'All' (every ready local drive - fixed or
#            removable, any file system) or 'NTFS' (those formatted NTFS, for the
#            NTFS metafiles, which FAT/exFAT have no file equivalent of). For
#            per-drive artefacts such as the Recycle Bin.
#   User     Path pattern(s) relative to each user profile.
#   TransactionLogs  Also collect each match's registry transaction logs
#            (<file>.LOG*: .LOG, .LOG1, .LOG2): $true for every pattern of the
#            row, or a list of file-name patterns for the patterns whose last
#            segment matches one (a row holding a hive beside other files).
#            Those never get a printed getfile command.
#   Literal  Use the path as-is, without listing it. For NTFS metafiles, which
#            PowerShell can neither see nor open: they stay as 'Not accessible'
#            placeholders so future raw/sensor-based collection slots in cleanly.
#   GetFile  Literal rows only: the Defender sensor's getfile can fetch it, so the
#            command is printed at the end if the read failed.
#   FollowUp Which of the row's locked files get a printed getfile command:
#            'System' (machine-wide paths; the default) or 'User' (user-profile
#            paths).
#   CountBy  'Folder' counts one unit per folder holding matches (e.g. per browser
#            profile) instead of one per file.
#   SupportingFiles  CountBy rows: file-name patterns of supporting files
#            (journals, ESE logs). A unit counts as collected only if every main
#            file in it was read; supporting files alone don't count while a
#            main file is present.
#   PresentByDefault  Where the knowledge base holds this artefact present by
#            default, so a Missing status is unusual and listed under Warnings: a
#            list of spans @{ Lineage = 'client' or 'server'; From = '<version>';
#            Before = '<version>' }, From the first OS version it holds on
#            (inclusive), Before the first it no longer does (exclusive), either
#            left out for no bound; versions as the host's NtVersion reads them (6.2
#            for Windows 8, 10.0.17763 for Windows Server 2019), the release named in
#            a comment. Written from devtools/presence-snapshot.csv, which the path
#            check compares them with. Rows without it may be present or not:
#            Missing is shown, but not warned about.
#   AbsentByDefault  Where the knowledge base holds it absent by default on
#            settled ground: spans as above, each with Why = <a reason from
#            $gapReasons>, given as the note "(<Why>)" when the artefact is
#            Missing.
#   ExpectLocked  Condition under which "not accessible" is normal; the summary
#            then notes "(requires <Requires>)", but only if every file of the
#            row that couldn't be opened failed with ExpectedOpenError. Unknown
#            host facts never count as expected, so unusual gaps stand out (they
#            go to Warnings).
#   ExpectedOpenError  The error the expected lock gives when a file is opened
#            (Get-OpenErrorKind): 'SharingViolation' (the default: held open by
#            Windows) or 'AccessDenied' (NTFS metafiles, which the file API
#            refuses to every account). Any other error is unusual.
#   Requires What reading this artefact's locked files would take, shown in that
#            note; defaults to 'NTFS parser' (matches the README's table).
#   RegistryFolders  Folders named by registry values (Key, Value), each searched
#            with its Pattern. Local drive paths only: shares are skipped (no
#            network access).
# Within a row, patterns run from the modern, standard location to legacy and
# alternative ones: current Windows first, then older Windows forms (Windows 7,
# XP), then the previous install kept in Windows.old after a feature update.
# Legacy forms are part of the same artefact, so they share its summary line.
# Pattern syntax: see Resolve-PathPattern. Collection, progress and summary all
# run in Group order, then by Name alphabetically ignoring non-alphanumerics (e.g.
# the leading '$'). That order is applied at run time, so a row's position in
# this list doesn't matter - but keep it in that order for readability.
$artefacts = @(
    # 1. Drive root: the timeline-relevant NTFS metafiles (the "NTFS Triforce").
    # A metafile that isn't there (e.g. no USN journal: "Could not find file")
    # is not access denied, so it isn't explained away.
    @{ Name = '$LogFile';    Group = 1; Drives = 'NTFS'; ExpectLocked = { <# NTFS metafile #> $true }; ExpectedOpenError = 'AccessDenied'; Literal = $true; System = '$LogFile' }   # no getfile route (reported as empty)
    @{ Name = '$MFT';        Group = 1; Drives = 'NTFS'; ExpectLocked = { <# NTFS metafile #> $true }; ExpectedOpenError = 'AccessDenied'; Literal = $true; GetFile = $true; System = '$MFT' }
    @{ Name = '$MFTMirr';    Group = 1; Drives = 'NTFS'; ExpectLocked = { <# NTFS metafile #> $true }; ExpectedOpenError = 'AccessDenied'; Literal = $true; System = '$MFTMirr' }   # no getfile line: $MFT's is the one printed
    @{ Name = '$UsnJrnl:$J'; Group = 1; Drives = 'NTFS'; ExpectLocked = { <# NTFS metafile #> $true }; ExpectedOpenError = 'AccessDenied'; Literal = $true; System = '$Extend\$UsnJrnl:$J' }   # no getfile route

    # 2. Other system files.
    # Application compatibility / program execution records: Amcache.hve and the
    # Program Compatibility Assistant files (Windows 11 22H2+), then their
    # predecessors - RecentFileCache.bcf (Windows 7) and Syscache.hve (Windows 7 /
    # Server 2008 R2), both replaced by Amcache.hve in Windows 8 - then Windows.old.
    @{ Name = 'Application Compatibility'; Group = 2; PresentByDefault = @(@{ Lineage = 'client'; From = '6.2' } <# Windows 8 on #>, @{ Lineage = 'server'; From = '6.1' } <# Windows Server 2008 R2 on #>); TransactionLogs = @('*.hve', 'RecentFileCache.bcf')
       ExpectLocked = { <# Syscache.hve is a loaded hive before Windows 8 #> $hostInfo.Build -and $hostInfo.Build -lt 9200 }
       System = @(
           'Windows\AppCompat\Programs\Amcache.hve'
           'Windows\AppCompat\Programs\Inventory*.db'
           'Windows\appcompat\pca\*'
           'Windows\AppCompat\Programs\RecentFileCache.bcf'               # Windows 7
           'System Volume Information\Syscache.hve'                       # Windows 7 / Server 2008 R2
           'Windows.old\Windows\AppCompat\Programs\Amcache.hve'
           'Windows.old\Windows\AppCompat\Programs\RecentFileCache.bcf'
       ) }
    # BITS job database (qmgr.db) and its ESE logs: downloads and persistence.
    @{ Name = 'BITS';          Group = 2; ExpectLocked = { <# qmgr.db, held by the BITS service while it runs #> $true }; System = 'ProgramData\Microsoft\Network\Downloader\**\*' }
    # Defender text logs (MPLog etc.) and detection history; not the quarantine
    # (file content). Defender event logs are covered by Event Logs.
    @{ Name = 'Defender Logs'; Group = 2; PresentByDefault = @(@{ Lineage = 'client'; From = '6.2' } <# Windows 8 on #>, @{ Lineage = 'server'; From = '10.0.14393' } <# Windows Server 2016 on #>); System = @(
        'ProgramData\Microsoft\Windows Defender\Support\**\*'
        'ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\**\*'
        'ProgramData\Microsoft\Windows Defender\Scans\History\Service\Detections.log'
        'Windows\Temp\MpCmdRun.log'
        'ProgramData\Microsoft\Microsoft AntiMalware\Support\**\*'      # older Defender / SCEP
        'Windows.old\Windows\Temp\MpCmdRun.log'
    ) }
    # DHCP Server audit log; only where the DHCP Server role is installed and its
    # audit logging is on.
    @{ Name = 'DHCP Server Logs'; Group = 2; System = 'Windows\System32\dhcp\DhcpSrvLog-*.log' }
    # DNS Server: the Dns folder (the debug log, once it is enabled) and the
    # analytical log; only where the DNS Server role is installed.
    @{ Name = 'DNS Server Logs'; Group = 2; System = @(
        'Windows\System32\dns\**\*'
        'Windows\System32\winevt\Logs\Microsoft-Windows-DNSServer%4Analytical.etl'
    ) }
    @{ Name = 'Event Logs'; Group = 2; PresentByDefault = @(@{ Lineage = 'client'; From = '5.0' } <# Windows 2000 Professional on #>, @{ Lineage = 'server'; From = '5.0' } <# Windows 2000 Server on #>); System = @(
        'Windows\System32\winevt\logs\*.evtx'
        'Windows\System32\config\*.evt'                                  # XP
        'Windows.old\Windows\System32\winevt\logs\*.evtx'
    ) }
    # Event trace logs (.etl) under LogFiles\WMI, RtBackup among them.
    @{ Name = 'Event Trace Logs'; Group = 2; System = 'Windows\System32\LogFiles\WMI\**\*' }
    # Exchange Server's transport logs; only where Exchange Server is installed.
    @{ Name = 'Exchange Server Logs'; Group = 2; System = 'Program Files\Microsoft\Exchange Server\*\TransportRoles\Logs\**\*.log' }
    @{ Name = 'Firewall Log'; Group = 2; AbsentByDefault = @(@{ Lineage = 'client'; Why = $gapReasons.OffByDefault } <# every client release #>, @{ Lineage = 'server'; Why = $gapReasons.OffByDefault } <# every server release #>); System = @(                     # logging off by default
        'Windows\System32\LogFiles\Firewall\pfirewall.*'
        'Windows.old\Windows\System32\LogFiles\Firewall\pfirewall.*'
    ) }
    # Group Policy: local policy and scripts, and the cached copies of domain GPOs
    # (incl. Group Policy Preferences XML such as ScheduledTasks.xml) - persistence
    # and deployment evidence.
    @{ Name = 'Group Policy'; Group = 2; PresentByDefault = @(@{ Lineage = 'client'; From = '5.0' } <# Windows 2000 Professional on #>, @{ Lineage = 'server'; From = '5.0' } <# Windows 2000 Server on #>)
       System = @(
           'Windows\System32\GroupPolicy\**\*'
           'ProgramData\Microsoft\Group Policy\History\**\*'
           'Windows.old\Windows\System32\GroupPolicy\*.ini'
           'Windows.old\Windows\System32\GroupPolicy\*.pol'
           'Windows.old\Windows\System32\GroupPolicy\*\Scripts\**\*'
       )
       User = 'AppData\Local\Microsoft\Group Policy\History\**\*' }
    # IIS: the sites' logs and HTTP.sys's error logs; only where IIS is installed.
    @{ Name = 'IIS Logs'; Group = 2; System = @(
        'inetpub\logs\LogFiles\*.log'
        'inetpub\logs\LogFiles\*\**\*.log'                             # per site
        'Windows\System32\LogFiles\HTTPERR\*.log'                       # HTTP.sys
        'Windows\System32\LogFiles\W3SVC*\*.log'
        'Windows.old\Windows\System32\LogFiles\W3SVC*\*.log'
    ) }
    # INF files: the setup information files of drivers and components installed.
    @{ Name = 'INF files'; Group = 2; PresentByDefault = @(@{ Lineage = 'client'; From = '10.0.16299' } <# Windows 10 1709 on #>, @{ Lineage = 'server'; From = '10.0.14393' } <# Windows Server 2016 on #>); System = 'Windows\INF\*.inf' }
    # The Malicious Software Removal Tool's log.
    @{ Name = 'MSRT Log'; Group = 2; PresentByDefault = @(@{ Lineage = 'client'; From = '10.0.19045'; Before = '10.0.22000' } <# Windows 10 22H2 to before Windows 11 21H2 #>); System = 'Windows\debug\mrt.log' }
    # Active Directory's database on a domain controller, held open while it runs.
    @{ Name = 'NTDS'; Group = 2; ExpectLocked = { <# ntds.dit, opened exclusively while the domain controller runs #> $hostInfo.DomainController }; System = 'Windows\NTDS\ntds.dit' }
    @{ Name = 'Prefetch'; Group = 2; PresentByDefault = @(@{ Lineage = 'client'; From = '6.2' } <# Windows 8 on #>); System = @(
        'Windows\Prefetch\*.pf'
        'Windows.old\Windows\Prefetch\*.pf'
    ) }
    # Transaction logs hold un-flushed changes, so Registry Explorer / RegRipper /
    # plaso can replay a dirty hive and recover the most recent entries. RegBack
    # copies are usually empty on current Windows, but older snapshots when present.
    @{ Name = 'Registry Hives (system)'; Group = 2; PresentByDefault = @(@{ Lineage = 'client'; From = '4.0' } <# Windows NT 4.0 Workstation on #>, @{ Lineage = 'server'; From = '4.0' } <# Windows NT 4.0 Server on #>); ExpectLocked = { <# loaded hives #> $true }; TransactionLogs = $true; System = @(
        'Windows\System32\config\SAM'
        'Windows\System32\config\SECURITY'
        'Windows\System32\config\SOFTWARE'
        'Windows\System32\config\SYSTEM'
        'Windows\System32\config\COMPONENTS'
        'Windows\System32\config\ELAM'
        'Windows\System32\AppLocker\AppCache.dat'
        'Windows\System32\config\RegBack\SAM'
        'Windows\System32\config\RegBack\SECURITY'
        'Windows\System32\config\RegBack\SOFTWARE'
        'Windows\System32\config\RegBack\SYSTEM'
        'Windows\System32\config\RegBack\SYSTEM1'
        'System Volume Information\_restore*\RP*\snapshot\_REGISTRY_*'  # XP restore points
        'Windows.old\Windows\System32\config\SAM'
        'Windows.old\Windows\System32\config\SECURITY'
        'Windows.old\Windows\System32\config\SOFTWARE'
        'Windows.old\Windows\System32\config\SYSTEM'
        'Windows.old\Windows\System32\config\RegBack\SAM'
        'Windows.old\Windows\System32\config\RegBack\SECURITY'
        'Windows.old\Windows\System32\config\RegBack\SOFTWARE'
        'Windows.old\Windows\System32\config\RegBack\SYSTEM'
        'Windows.old\Windows\System32\config\RegBack\SYSTEM1'
    ) }
    # XP restore-point logs (rp.log: each restore point's creation time and description).
    @{ Name = 'Restore Point Logs'; Group = 2; PresentByDefault = @(@{ Lineage = 'client'; From = '5.1'; Before = '6.0' } <# Windows XP to before Windows Vista #>); System = 'System Volume Information\_restore*\RP*\rp.log' }
    # Configuration Manager (SCCM) client logs; only on ConfigMgr-managed hosts.
    @{ Name = 'SCCM Client Logs';   Group = 2; System = 'Windows\CCM\Logs\*' }
    # XML task definitions, plus PowerShell scheduled jobs (definitions and output).
    @{ Name = 'Scheduled Tasks'; Group = 2; PresentByDefault = @(@{ Lineage = 'client'; From = '5.1' } <# Windows XP on #>, @{ Lineage = 'server'; From = '5.2' } <# Windows Server 2003 on #>)
       System = @(
           'Windows\System32\Tasks\**\*'
           'Windows\SysWOW64\Tasks\**\*'
           'Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\**\*'
           'Windows\SysWOW64\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\**\*'
           'Windows\Tasks\*.job'                                         # legacy at.exe / Task Scheduler 1.0
           'Windows\Tasks\SchedLgU.txt'                                  # legacy Task Scheduler log
           'Windows\SchedLgU.txt'                                        # legacy Task Scheduler log
           'Windows.old\Windows\System32\Tasks\**\*'
           'Windows.old\Windows\Tasks\*.job'
           'Windows.old\Windows\SchedLgU.txt'
       )
       User = 'AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\**\*' }
    # Device/driver install logs.
    @{ Name = 'SetupAPI'; Group = 2; PresentByDefault = @(@{ Lineage = 'client'; From = '5.1'; Before = '10.0.26100' } <# Windows XP to before Windows 11 24H2 #>); System = @(
        'Windows\INF\setupapi*.log'
        'Windows\setupapi.log'                                           # XP
        'Windows.old\Windows\INF\setupapi*.log'
    ) }
    # The shadow copy catalogue at each NTFS volume's root: one entry per shadow
    # copy, with its creation time. Not the shadow copies' stores (content).
    @{ Name = 'Shadow Copy Catalog'; Group = 2; Drives = 'NTFS'; ExpectLocked = { <# access denied even to SYSTEM #> $true }; ExpectedOpenError = 'AccessDenied'; System = 'System Volume Information\{3808876b-c176-4e48-b7ae-04046e6cc752}' }   # no getfile route (reported as empty)
    # SQL Server's error logs, per instance; only where SQL Server is installed.
    @{ Name = 'SQL Server Logs'; Group = 2; System = @(
        'Program Files\Microsoft SQL Server\*\MSSQL\LOG\ERRORLOG*'
        'Program Files (x86)\Microsoft SQL Server\*\MSSQL\LOG\ERRORLOG*'
    ) }
    # SRUDB.dat plus its ESE logs and checkpoint, for dirty-database recovery.
    @{ Name = 'SRUM'; Group = 2; PresentByDefault = @(@{ Lineage = 'client'; From = '6.2' } <# Windows 8 on #>, @{ Lineage = 'server'; From = '10.0.17763' } <# Windows Server 2019 on #>); ExpectLocked = { <# often held open #> $true }; System = @(
        'Windows\System32\SRU\**\*'
        'Windows.old\Windows\System32\SRU\**\*'
    ) }
    # User Access Logging (Windows Server): clients and users per role, with first
    # and last access times. ESE databases plus their logs, needed to repair them.
    @{ Name = 'User Access Logging (SUM)'; Group = 2; PresentByDefault = @(@{ Lineage = 'server'; From = '10.0.14393' } <# Windows Server 2016 on #>); AbsentByDefault = @(@{ Lineage = 'client'; Why = $gapReasons.ServerOnly } <# every client release #>); ExpectLocked = { <# Current.mdb held by the UAL service #> $true }; System = 'Windows\System32\LogFiles\Sum\**\*' }
    # Windows Search's index: the ESE database Windows.edb with its logs and
    # checkpoint, and the SQLite databases Windows.db and Windows-gather.db with
    # their WALs, counted as one unit with the databases as its main files.
    @{ Name = 'Windows Search index'; Group = 2; PresentByDefault = @(@{ Lineage = 'client'; From = '6.0' } <# Windows Vista on #>); CountBy = 'Folder'; SupportingFiles = @('edb.chk', 'edb*.log', 'edbres*.jrs', '*-wal'); System = @(
           'ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb'
           'ProgramData\Microsoft\Search\Data\Applications\Windows\edb.chk'
           'ProgramData\Microsoft\Search\Data\Applications\Windows\edb*.log'
           'ProgramData\Microsoft\Search\Data\Applications\Windows\edbres*.jrs'
           'ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.db'
           'ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.db-wal'
           'ProgramData\Microsoft\Search\Data\Applications\Windows\Windows-gather.db'
           'ProgramData\Microsoft\Search\Data\Applications\Windows\Windows-gather.db-wal'
       ) }

    # 3. User-specific. Service accounts (SYSTEM, LocalService, NetworkService) are
    # not user profiles; where they matter, their paths are listed under System.
    # .NET CLR usage logs: one log per process that loaded the CLR (e.g. .NET tooling).
    @{ Name = '.NET CLR Usage Logs'; Group = 3
       System = @(
           'Windows\System32\config\systemprofile\AppData\Local\Microsoft\CLR_*\**\*.log'
           'Windows.old\Windows\System32\config\systemprofile\AppData\Local\Microsoft\CLR_*\**\*.log'
       )
       User = 'AppData\Local\Microsoft\CLR_*\**\*.log' }
    # Browser bookmarks: one pattern per browser (or channel), counted per user x
    # browser x profile, in Browser History's order; legacy Edge's Spartan.edb;
    # XP profile paths last.
    @{ Name = 'Browser Bookmarks'; Group = 3; PresentByDefault = @(@{ Lineage = 'client'; From = '5.1' } <# Windows XP on #>); CountBy = 'Folder'
       User = @(
           'AppData\Local\Microsoft\Edge\User Data\*\Bookmarks*'                        # Edge
           'AppData\Local\Microsoft\Edge Beta\User Data\*\Bookmarks*'                   # Edge Beta
           'AppData\Local\Microsoft\Edge Dev\User Data\*\Bookmarks*'                    # Edge Dev
           'AppData\Local\Microsoft\Edge SxS\User Data\*\Bookmarks*'                    # Edge Canary
           'AppData\Local\Google\Chrome\User Data\*\Bookmarks*'                         # Chrome
           'AppData\Local\Google\Chrome Beta\User Data\*\Bookmarks*'                    # Chrome Beta
           'AppData\Local\Google\Chrome Dev\User Data\*\Bookmarks*'                     # Chrome Dev
           'AppData\Local\Google\Chrome SxS\User Data\*\Bookmarks*'                     # Chrome Canary
           'AppData\Local\Chromium\User Data\*\Bookmarks*'                              # Chromium
           'AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Bookmarks*'           # Brave
           'AppData\Local\Vivaldi\User Data\*\Bookmarks*'                               # Vivaldi
           'AppData\Local\Yandex\YandexBrowser\User Data\*\Bookmarks*'                  # Yandex
           'AppData\Local\Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data\*\Bookmarks*' # Arc
           'AppData\Local\CocCoc\Browser\User Data\*\Bookmarks*'                        # Coc Coc
           'AppData\Local\Tencent\QQBrowser\User Data\*\Bookmarks*'                     # QQ Browser
           'AppData\Local\UCBrowser\User Data*\*\Bookmarks*'                            # UC Browser
           'AppData\Local\WaveBrowser\User Data\*\Bookmarks*'                           # Wave Browser
           'AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Bookmarks*' # Prisma Access Browser
           'AppData\Local\Supermium\User Data\*\Bookmarks*'                             # Supermium
           'AppData\Local\Packages\Microsoft.MicrosoftEdge_*\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\120712-0049\DBStore\Spartan.edb' # legacy Edge
           'Local Settings\Application Data\Google\Chrome\User Data\*\Bookmarks*'       # XP: Chrome
           'Local Settings\Application Data\Google\Chrome Beta\User Data\*\Bookmarks*'  # XP: Chrome Beta
           'Local Settings\Application Data\Google\Chrome Dev\User Data\*\Bookmarks*'   # XP: Chrome Dev
           'Local Settings\Application Data\Google\Chrome SxS\User Data\*\Bookmarks*'   # XP: Chrome Canary
           'Local Settings\Application Data\Chromium\User Data\*\Bookmarks*'            # XP: Chromium
           'Local Settings\Application Data\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Bookmarks*' # XP: Prisma Access
           'Application Data\Supermium\User Data\*\Bookmarks*'                          # XP: Supermium
       ) }
    # Browser cookies: one pattern per browser, counted per user x browser x
    # profile (with their journals); Firefox; IE's cookie folders; XP profile
    # paths last.
    @{ Name = 'Browser Cookies'; Group = 3; PresentByDefault = @(@{ Lineage = 'client'; From = '5.0' } <# Windows 2000 Professional on #>, @{ Lineage = 'server'; From = '5.0' } <# Windows 2000 Server on #>); ExpectLocked = { <# IE's cookie index.dat, locked from boot #> $true }; CountBy = 'Folder'
       SupportingFiles = @('*-journal', '*-wal', '*-shm')
       User = @(
           'AppData\Local\Microsoft\Edge\User Data\*\Network\Cookies*'                      # Edge
           'AppData\Local\Microsoft\Edge Beta\User Data\*\Network\Cookies*'                 # Edge Beta
           'AppData\Local\Microsoft\Edge Dev\User Data\*\Network\Cookies*'                  # Edge Dev
           'AppData\Local\Microsoft\Edge SxS\User Data\*\Network\Cookies*'                  # Edge Canary
           'AppData\Local\Google\Chrome\User Data\*\Cookies*'                           # Chrome
           'AppData\Local\Google\Chrome\User Data\*\Network\Cookies*'                   # Chrome
           'AppData\Local\Google\Chrome Beta\User Data\*\Cookies*'                      # Chrome Beta
           'AppData\Local\Google\Chrome Dev\User Data\*\Cookies*'                       # Chrome Dev
           'AppData\Local\Google\Chrome SxS\User Data\*\Cookies*'                       # Chrome Canary
           'AppData\Local\Chromium\User Data\*\Cookies*'                                # Chromium
           'AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Cookies*'             # Brave
           'AppData\Local\Vivaldi\User Data\*\Cookies*'                                 # Vivaldi
           'AppData\Local\Yandex\YandexBrowser\User Data\*\Cookies*'                    # Yandex
           'AppData\Local\Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data\*\Network\Cookies*' # Arc
           'AppData\Local\CocCoc\Browser\User Data\*\Cookies*'                          # Coc Coc
           'AppData\Local\Tencent\QQBrowser\User Data\*\Cookies*'                       # QQ Browser
           'AppData\Local\UCBrowser\User Data*\*\Cookies*'                              # UC Browser
           'AppData\Roaming\360se6\User Data\*\Cookies*'                                # 360 Secure Browser
           'AppData\Local\WaveBrowser\User Data\*\Cookies*'                             # Wave Browser
           'AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Cookies*'  # Prisma Access Browser
           'AppData\Local\Supermium\User Data\*\Cookies*'                               # Supermium
           'AppData\Roaming\Mozilla\Firefox\Profiles\*\cookies.sqlite*'                 # Firefox
           'AppData\Roaming\Microsoft\Windows\Cookies\**\*'                             # IE
           'Local Settings\Application Data\Google\Chrome\User Data\*\Cookies*'         # XP: Chrome
           'Local Settings\Application Data\Google\Chrome Beta\User Data\*\Cookies*'    # XP: Chrome Beta
           'Local Settings\Application Data\Google\Chrome Dev\User Data\*\Cookies*'     # XP: Chrome Dev
           'Local Settings\Application Data\Google\Chrome SxS\User Data\*\Cookies*'     # XP: Chrome Canary
           'Local Settings\Application Data\Chromium\User Data\*\Cookies*'              # XP: Chromium
           'Local Settings\Application Data\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Cookies*' # XP: Prisma Access
           'Application Data\Supermium\User Data\*\Cookies*'                            # XP: Supermium
           'Application Data\Mozilla\Firefox\Profiles\*\cookies.sqlite*'                # XP: Firefox
           'Cookies\**\*'                                                               # XP: IE
       ) }
    # Browser extensions: Chrome's Extension Activity, Firefox's extensions.json and
    # addons.sqlite (with its journal or WAL), per user x profile.
    @{ Name = 'Browser Extensions'; Group = 3; CountBy = 'Folder'; SupportingFiles = @('*-journal', '*-wal', '*-shm')
       User = @(
           'AppData\Local\Google\Chrome\User Data\*\Extension Activity'                     # Chrome
           'AppData\Roaming\Mozilla\Firefox\Profiles\*\extensions.json'                     # Firefox
           'AppData\Roaming\Mozilla\Firefox\Profiles\*\addons.sqlite*'                      # Firefox
           'Application Data\Mozilla\Firefox\Profiles\*\addons.sqlite*'                     # XP: Firefox
       ) }
    # Form data: the browsers' form and autofill databases, per user x profile.
    @{ Name = 'Browser Form Data'; Group = 3; CountBy = 'Folder'; SupportingFiles = @('*-journal', '*-wal', '*-shm')
       User = @(
           'AppData\Local\Microsoft\Edge\User Data\*\Web Data*'                             # Edge
           'AppData\Local\Microsoft\Edge Beta\User Data\*\Web Data*'                        # Edge Beta
           'AppData\Local\Microsoft\Edge Dev\User Data\*\Web Data*'                         # Edge Dev
           'AppData\Local\Microsoft\Edge SxS\User Data\*\Web Data*'                         # Edge Canary
           'AppData\Local\Google\Chrome\User Data\*\Web Data*'                              # Chrome
           'AppData\Local\Google\Chrome Beta\User Data\*\Web Data*'                         # Chrome Beta
           'AppData\Local\Google\Chrome Dev\User Data\*\Web Data*'                          # Chrome Dev
           'AppData\Local\Google\Chrome SxS\User Data\*\Web Data*'                          # Chrome Canary
           'AppData\Local\Chromium\User Data\*\Web Data*'                                   # Chromium
           'AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Web Data*'                # Brave
           'AppData\Local\Vivaldi\User Data\*\Web Data*'                                    # Vivaldi
           'AppData\Local\Yandex\YandexBrowser\User Data\*\Web Data*'                       # Yandex
           'AppData\Local\Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data\*\Web Data*' # Arc
           'AppData\Local\CocCoc\Browser\User Data\*\Web Data*'                             # Coc Coc
           'AppData\Local\Tencent\QQBrowser\User Data\*\Web Data*'                          # QQ Browser
           'AppData\Local\UCBrowser\User Data*\*\Web Data*'                                 # UC Browser
           'AppData\Roaming\360se6\User Data\*\Web Data*'                                   # 360 Secure Browser
           'AppData\Local\WaveBrowser\User Data\*\Web Data*'                                # Wave Browser
           'AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Web Data*'     # Prisma Access Browser
           'AppData\Local\Supermium\User Data\*\Web Data*'                                  # Supermium
           'AppData\Roaming\Mozilla\Firefox\Profiles\*\formhistory.sqlite*'                 # Firefox
           'Local Settings\Application Data\Google\Chrome\User Data\*\Web Data*'            # XP: Chrome
           'Local Settings\Application Data\Google\Chrome Beta\User Data\*\Web Data*'       # XP: Chrome Beta
           'Local Settings\Application Data\Google\Chrome Dev\User Data\*\Web Data*'        # XP: Chrome Dev
           'Local Settings\Application Data\Google\Chrome SxS\User Data\*\Web Data*'        # XP: Chrome Canary
           'Local Settings\Application Data\Chromium\User Data\*\Web Data*'                 # XP: Chromium
           'Local Settings\Application Data\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Web Data*' # XP: Prisma Access Browser
           'Application Data\Supermium\User Data\*\Web Data*'                               # XP: Supermium
           'Application Data\Mozilla\Firefox\Profiles\*\formhistory.sqlite*'                # XP: Firefox
       ) }
    # Browser history: one pattern per browser (or channel), counted per user x
    # browser x profile. History DB only (plus its journal). Maintained browsers
    # first, then IE / legacy Edge (WebCache, index.dat) and other discontinued
    # browsers or formats, then XP profile paths.
    @{ Name = 'Browser History'; Group = 3; PresentByDefault = @(@{ Lineage = 'client'; From = '5.0' } <# Windows 2000 Professional on #>, @{ Lineage = 'server'; From = '5.0' } <# Windows 2000 Server on #>); ExpectLocked = { <# a logged-on user's WebCache #> $true }; CountBy = 'Folder'
       SupportingFiles = @('*-journal', '*-wal', '*-shm', '*Provider Cache', '*.log', '*.chk', '*.jrs', '*.jfm')
       System = @(
           'Windows\System32\config\systemprofile\AppData\Local\Google\Chrome\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\Google\Chrome Beta\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\Google\Chrome Dev\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\Google\Chrome SxS\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\Chromium\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\Supermium\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\WaveBrowser\User Data\*\History*'
       )
       User = @(
           'AppData\Local\Microsoft\Edge\User Data\*\History*'                                   # Edge
           'AppData\Local\Microsoft\Edge\User Data\*\Shortcuts*'                                   # Edge
           'AppData\Local\Microsoft\Edge Beta\User Data\*\History*'                              # Edge Beta
           'AppData\Local\Microsoft\Edge Beta\User Data\*\Shortcuts*'                              # Edge Beta
           'AppData\Local\Microsoft\Edge Dev\User Data\*\History*'                               # Edge Dev
           'AppData\Local\Microsoft\Edge Dev\User Data\*\Shortcuts*'                               # Edge Dev
           'AppData\Local\Microsoft\Edge SxS\User Data\*\History*'                               # Edge Canary
           'AppData\Local\Microsoft\Edge SxS\User Data\*\Shortcuts*'                               # Edge Canary
           'AppData\Local\Google\Chrome\User Data\*\History*'                                    # Chrome
           'AppData\Local\Google\Chrome\User Data\*\Shortcuts*'                                    # Chrome
           'AppData\Local\Google\Chrome\User Data\*\Archived History*'                                    # Chrome
           'AppData\Local\Google\Chrome Beta\User Data\*\History*'                               # Chrome Beta
           'AppData\Local\Google\Chrome Beta\User Data\*\Shortcuts*'                               # Chrome Beta
           'AppData\Local\Google\Chrome Dev\User Data\*\History*'                                # Chrome Dev
           'AppData\Local\Google\Chrome Dev\User Data\*\Shortcuts*'                                # Chrome Dev
           'AppData\Local\Google\Chrome SxS\User Data\*\History*'                                # Chrome Canary
           'AppData\Local\Google\Chrome SxS\User Data\*\Shortcuts*'                                # Chrome Canary
           'AppData\Local\Chromium\User Data\*\History*'                                         # Chromium
           'AppData\Local\Chromium\User Data\*\Shortcuts*'                                         # Chromium
           'AppData\Local\BraveSoftware\Brave-Browser\User Data\*\History*'                      # Brave
           'AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Shortcuts*'                      # Brave
           'AppData\Local\Vivaldi\User Data\*\History*'                                          # Vivaldi
           'AppData\Roaming\Opera Software\Opera Stable\History*'                                # Opera (single profile)
           'AppData\Roaming\Opera Software\Opera Stable\*\History*'                              # Opera (profiles)
           'AppData\Local\Yandex\YandexBrowser\User Data\*\History*'                             # Yandex
           'AppData\Local\Yandex\YandexBrowser\User Data\*\Shortcuts*'                             # Yandex
           'AppData\Local\Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data\*\History*'   # Arc
           'AppData\Local\Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data\*\Shortcuts*'   # Arc
           'AppData\Local\CocCoc\Browser\User Data\*\History*'                                   # Coc Coc
           'AppData\Local\CocCoc\Browser\User Data\*\Shortcuts*'                                   # Coc Coc
           'AppData\Local\Tencent\QQBrowser\User Data\*\History*'                                # QQ Browser
           'AppData\Local\Tencent\QQBrowser\User Data\*\Shortcuts*'                                # QQ Browser
           'AppData\Local\UCBrowser\User Data*\*\History*'                                     # UC Browser
           'AppData\Local\UCBrowser\User Data*\*\Shortcuts*'                                   # UC Browser
           'AppData\Roaming\360se6\User Data\*\360History*'                                      # 360 Secure Browser
           'AppData\Roaming\360se6\User Data\*\Shortcuts*'                                       # 360 Secure Browser
           'AppData\Local\WaveBrowser\User Data\*\History*'                                      # Wave Browser
           'AppData\Local\WaveBrowser\User Data\*\Shortcuts*'                                      # Wave Browser
           'AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\History*'           # Prisma Access Browser
           'AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Shortcuts*'           # Prisma Access Browser
           'AppData\Local\Supermium\User Data\*\History*'                                        # Supermium
           'AppData\Local\Supermium\User Data\*\Shortcuts*'                                        # Supermium
           'AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite*'                           # Firefox
           'AppData\Local\Microsoft\Windows\WebCache\*'                                          # IE 10/11, legacy Edge
           'AppData\Local\Microsoft\Windows\History\**\index.dat'                                # IE 9 and earlier
           'AppData\Roaming\Microsoft\Windows\IEDownloadHistory\index.dat'                       # IE 9 downloads
           'AppData\Roaming\Mozilla\Firefox\Profiles\*\downloads.sqlite*'                        # Firefox < 26 downloads
           'AppData\Roaming\Opera\Opera\global_history.dat'                                      # Opera <= 12
           'AppData\Roaming\Opera\Opera\typed_history.xml'                                       # Opera <= 12
           'AppData\Roaming\Apple Computer\Safari\History.plist'                                 # Safari for Windows
           'AppData\Roaming\Apple Computer\Safari\Downloads.plist'                               # Safari for Windows
           'Local Settings\Application Data\Google\Chrome\User Data\*\History*'                  # XP: Chrome
           'Local Settings\Application Data\Google\Chrome\User Data\*\Shortcuts*'                  # XP: Chrome
           'Local Settings\Application Data\Google\Chrome Beta\User Data\*\History*'             # XP: Chrome Beta
           'Local Settings\Application Data\Google\Chrome Beta\User Data\*\Shortcuts*'             # XP: Chrome Beta
           'Local Settings\Application Data\Google\Chrome Dev\User Data\*\History*'              # XP: Chrome Dev
           'Local Settings\Application Data\Google\Chrome Dev\User Data\*\Shortcuts*'              # XP: Chrome Dev
           'Local Settings\Application Data\Google\Chrome SxS\User Data\*\History*'              # XP: Chrome Canary
           'Local Settings\Application Data\Google\Chrome SxS\User Data\*\Shortcuts*'              # XP: Chrome Canary
           'Local Settings\Application Data\Chromium\User Data\*\History*'                       # XP: Chromium
           'Local Settings\Application Data\Chromium\User Data\*\Shortcuts*'                       # XP: Chromium
           'Local Settings\Application Data\Palo Alto Networks\PrismaAccessBrowser\User Data\*\History*'   # XP: Prisma Access
           'Local Settings\Application Data\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Shortcuts*'   # XP: Prisma Access
           'Application Data\Supermium\User Data\*\History*'                                     # XP: Supermium
           'Application Data\Supermium\User Data\*\Shortcuts*'                                     # XP: Supermium
           'Application Data\Mozilla\Firefox\Profiles\*\places.sqlite*'                          # XP: Firefox
           'Application Data\Mozilla\Firefox\Profiles\*\downloads.sqlite*'                       # XP: Firefox < 26 downloads
           'Application Data\Mozilla\Firefox\Profiles\*\history.dat'                             # XP: Firefox history.dat
           'Application Data\Opera\Opera\global_history.dat'                                      # XP: Opera <= 12
           'Application Data\Opera\Opera\typed_history.xml'                                       # XP: Opera <= 12
           'Application Data\Apple Computer\Safari\History.plist'                                 # XP: Safari
           'Local Settings\History\History.IE5\**\index.dat'                                     # XP: IE
       ) }
    # Browser preferences: one pattern per browser (or channel), counted per user
    # x browser x profile; Firefox's prefs.js; XP profile paths last.
    @{ Name = 'Browser Preferences'; Group = 3; CountBy = 'Folder'
       User = @(
           'AppData\Local\Microsoft\Edge\User Data\*\Preferences'                       # Edge
           'AppData\Local\Microsoft\Edge\User Data\*\Secure Preferences'                # Edge
           'AppData\Local\Microsoft\Edge\User Data\*\Sync Data\SyncData.sqlite3'        # Edge
           'AppData\Local\Microsoft\Edge Beta\User Data\*\Preferences'                  # Edge Beta
           'AppData\Local\Microsoft\Edge Beta\User Data\*\Secure Preferences'           # Edge Beta
           'AppData\Local\Microsoft\Edge Beta\User Data\*\Sync Data\SyncData.sqlite3'   # Edge Beta
           'AppData\Local\Microsoft\Edge Dev\User Data\*\Preferences'                   # Edge Dev
           'AppData\Local\Microsoft\Edge Dev\User Data\*\Secure Preferences'            # Edge Dev
           'AppData\Local\Microsoft\Edge Dev\User Data\*\Sync Data\SyncData.sqlite3'    # Edge Dev
           'AppData\Local\Microsoft\Edge SxS\User Data\*\Preferences'                   # Edge Canary
           'AppData\Local\Microsoft\Edge SxS\User Data\*\Secure Preferences'            # Edge Canary
           'AppData\Local\Microsoft\Edge SxS\User Data\*\Sync Data\SyncData.sqlite3'    # Edge Canary
           'AppData\Local\Google\Chrome\User Data\*\Preferences'                        # Chrome
           'AppData\Local\Google\Chrome\User Data\*\Secure Preferences'                 # Chrome
           'AppData\Local\Google\Chrome\User Data\*\Sync Data\SyncData.sqlite3'         # Chrome
           'AppData\Local\Google\Chrome Beta\User Data\*\Preferences'                   # Chrome Beta
           'AppData\Local\Google\Chrome Beta\User Data\*\Secure Preferences'            # Chrome Beta
           'AppData\Local\Google\Chrome Beta\User Data\*\Sync Data\SyncData.sqlite3'    # Chrome Beta
           'AppData\Local\Google\Chrome Dev\User Data\*\Preferences'                    # Chrome Dev
           'AppData\Local\Google\Chrome Dev\User Data\*\Secure Preferences'             # Chrome Dev
           'AppData\Local\Google\Chrome Dev\User Data\*\Sync Data\SyncData.sqlite3'     # Chrome Dev
           'AppData\Local\Google\Chrome SxS\User Data\*\Preferences'                    # Chrome Canary
           'AppData\Local\Google\Chrome SxS\User Data\*\Secure Preferences'             # Chrome Canary
           'AppData\Local\Google\Chrome SxS\User Data\*\Sync Data\SyncData.sqlite3'     # Chrome Canary
           'AppData\Local\Chromium\User Data\*\Preferences'                             # Chromium
           'AppData\Local\Chromium\User Data\*\Secure Preferences'                      # Chromium
           'AppData\Local\Chromium\User Data\*\Sync Data\SyncData.sqlite3'              # Chromium
           'AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Preferences'          # Brave
           'AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Secure Preferences'   # Brave
           'AppData\Local\Vivaldi\User Data\*\Preferences'                              # Vivaldi
           'AppData\Local\Vivaldi\User Data\*\Secure Preferences'                       # Vivaldi
           'AppData\Local\Yandex\YandexBrowser\User Data\*\Preferences'                 # Yandex
           'AppData\Local\Yandex\YandexBrowser\User Data\*\Secure Preferences'          # Yandex
           'AppData\Local\Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data\*\Preferences' # Arc
           'AppData\Local\Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data\*\Sync Data\**\*' # Arc
           'AppData\Local\CocCoc\Browser\User Data\*\Preferences'                       # Coc Coc
           'AppData\Local\CocCoc\Browser\User Data\*\Sync Data\**\*'                    # Coc Coc
           'AppData\Local\Tencent\QQBrowser\User Data\*\Preferences'                    # QQ Browser
           'AppData\Local\Tencent\QQBrowser\User Data\*\Sync Data\**\*'                 # QQ Browser
           'AppData\Local\UCBrowser\User Data*\*\Preferences'                           # UC Browser
           'AppData\Local\UCBrowser\User Data*\*\Sync Data\**\*'                        # UC Browser
           'AppData\Roaming\360se6\User Data\*\Preferences'                             # 360 Secure Browser
           'AppData\Roaming\360se6\User Data\*\Secure Preferences'                      # 360 Secure Browser
           'AppData\Roaming\360se6\User Data\*\Sync Data\**\*'                          # 360 Secure Browser
           'AppData\Local\WaveBrowser\User Data\*\Preferences'                          # Wave Browser
           'AppData\Local\WaveBrowser\User Data\*\Sync Data\SyncData.sqlite3'           # Wave Browser
           'AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Preferences' # Prisma Access Browser
           'AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Secure Preferences' # Prisma Access Browser
           'AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Sync Data\SyncData.sqlite3' # Prisma Access Browser
           'AppData\Local\Supermium\User Data\*\Preferences'                            # Supermium
           'AppData\Local\Supermium\User Data\*\Secure Preferences'                     # Supermium
           'AppData\Local\Supermium\User Data\*\Sync Data\**\*'                         # Supermium
           'AppData\Roaming\Mozilla\Firefox\Profiles\*\prefs.js'                        # Firefox
           'AppData\Roaming\Mozilla\Firefox\Profiles\*\signedinuser.json'               # Firefox
           'Local Settings\Application Data\Google\Chrome\User Data\*\Preferences'      # XP: Chrome
           'Local Settings\Application Data\Google\Chrome Beta\User Data\*\Preferences' # XP: Chrome Beta
           'Local Settings\Application Data\Google\Chrome Dev\User Data\*\Preferences'  # XP: Chrome Dev
           'Local Settings\Application Data\Google\Chrome SxS\User Data\*\Preferences'  # XP: Chrome Canary
           'Local Settings\Application Data\Chromium\User Data\*\Preferences'           # XP: Chromium
           'Local Settings\Application Data\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Preferences' # XP: Prisma Access
           'Application Data\Supermium\User Data\*\Preferences'                         # XP: Supermium
       ) }
    # Saved logins: the browsers' saved-login stores, per user x profile.
    @{ Name = 'Browser Saved Logins'; Group = 3; CountBy = 'Folder'
       User = @(
           'AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Login Data'               # Brave
           'AppData\Local\Vivaldi\User Data\*\Login Data'                                   # Vivaldi
           'AppData\Local\WaveBrowser\User Data\*\Login Data'                               # Wave Browser
           'AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Login Data'    # Prisma Access Browser
           'AppData\Roaming\Mozilla\Firefox\Profiles\*\logins.json'                         # Firefox
           'Local Settings\Application Data\Google\Chrome\User Data\*\Login Data'           # XP: Chrome
           'Local Settings\Application Data\Google\Chrome Beta\User Data\*\Login Data'      # XP: Chrome Beta
           'Local Settings\Application Data\Google\Chrome Dev\User Data\*\Login Data'       # XP: Chrome Dev
           'Local Settings\Application Data\Google\Chrome SxS\User Data\*\Login Data'       # XP: Chrome Canary
           'Local Settings\Application Data\Chromium\User Data\*\Login Data'                # XP: Chromium
           'Local Settings\Application Data\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Login Data' # XP: Prisma Access Browser
           'Application Data\Mozilla\Firefox\Profiles\*\logins.json'                        # XP: Firefox
       ) }
    # Browser sessions: each Chromium-family profile's Sessions folder and its
    # Current/Last Session and Tabs files, Firefox's session store and
    # its backups, IE's recovery and tab roaming folders; XP profile paths last.
    # Counted per file: a profile's sessions are several files.
    @{ Name = 'Browser Sessions'; Group = 3; PresentByDefault = @(@{ Lineage = 'client'; From = '6.1' } <# Windows 7 on #>); ExpectLocked = { <# a running browser's current session files #> $true }
       User = @(
           'AppData\Local\Microsoft\Edge\User Data\*\Sessions\*'                        # Edge
           'AppData\Local\Microsoft\Edge\User Data\*\Current Session'                   # Edge
           'AppData\Local\Microsoft\Edge\User Data\*\Current Tabs'                      # Edge
           'AppData\Local\Microsoft\Edge\User Data\*\Last Session'                      # Edge
           'AppData\Local\Microsoft\Edge\User Data\*\Last Tabs'                         # Edge
           'AppData\Local\Microsoft\Edge Beta\User Data\*\Sessions\*'                   # Edge Beta
           'AppData\Local\Microsoft\Edge Beta\User Data\*\Current Session'              # Edge Beta
           'AppData\Local\Microsoft\Edge Beta\User Data\*\Current Tabs'                 # Edge Beta
           'AppData\Local\Microsoft\Edge Beta\User Data\*\Last Session'                 # Edge Beta
           'AppData\Local\Microsoft\Edge Beta\User Data\*\Last Tabs'                    # Edge Beta
           'AppData\Local\Microsoft\Edge Dev\User Data\*\Sessions\*'                    # Edge Dev
           'AppData\Local\Microsoft\Edge Dev\User Data\*\Current Session'               # Edge Dev
           'AppData\Local\Microsoft\Edge Dev\User Data\*\Current Tabs'                  # Edge Dev
           'AppData\Local\Microsoft\Edge Dev\User Data\*\Last Session'                  # Edge Dev
           'AppData\Local\Microsoft\Edge Dev\User Data\*\Last Tabs'                     # Edge Dev
           'AppData\Local\Microsoft\Edge SxS\User Data\*\Sessions\*'                    # Edge Canary
           'AppData\Local\Microsoft\Edge SxS\User Data\*\Current Session'               # Edge Canary
           'AppData\Local\Microsoft\Edge SxS\User Data\*\Current Tabs'                  # Edge Canary
           'AppData\Local\Microsoft\Edge SxS\User Data\*\Last Session'                  # Edge Canary
           'AppData\Local\Microsoft\Edge SxS\User Data\*\Last Tabs'                     # Edge Canary
           'AppData\Local\Google\Chrome\User Data\*\Sessions\*'                         # Chrome
           'AppData\Local\Google\Chrome\User Data\*\Current Session'                    # Chrome
           'AppData\Local\Google\Chrome\User Data\*\Current Tabs'                       # Chrome
           'AppData\Local\Google\Chrome\User Data\*\Last Session'                       # Chrome
           'AppData\Local\Google\Chrome\User Data\*\Last Tabs'                          # Chrome
           'AppData\Local\Google\Chrome Beta\User Data\*\Sessions\*'                    # Chrome Beta
           'AppData\Local\Google\Chrome Beta\User Data\*\Current Session'               # Chrome Beta
           'AppData\Local\Google\Chrome Beta\User Data\*\Current Tabs'                  # Chrome Beta
           'AppData\Local\Google\Chrome Beta\User Data\*\Last Session'                  # Chrome Beta
           'AppData\Local\Google\Chrome Beta\User Data\*\Last Tabs'                     # Chrome Beta
           'AppData\Local\Google\Chrome Dev\User Data\*\Sessions\*'                     # Chrome Dev
           'AppData\Local\Google\Chrome Dev\User Data\*\Current Session'                # Chrome Dev
           'AppData\Local\Google\Chrome Dev\User Data\*\Current Tabs'                   # Chrome Dev
           'AppData\Local\Google\Chrome Dev\User Data\*\Last Session'                   # Chrome Dev
           'AppData\Local\Google\Chrome Dev\User Data\*\Last Tabs'                      # Chrome Dev
           'AppData\Local\Google\Chrome SxS\User Data\*\Sessions\*'                     # Chrome Canary
           'AppData\Local\Google\Chrome SxS\User Data\*\Current Session'                # Chrome Canary
           'AppData\Local\Google\Chrome SxS\User Data\*\Current Tabs'                   # Chrome Canary
           'AppData\Local\Google\Chrome SxS\User Data\*\Last Session'                   # Chrome Canary
           'AppData\Local\Google\Chrome SxS\User Data\*\Last Tabs'                      # Chrome Canary
           'AppData\Local\Chromium\User Data\*\Sessions\*'                              # Chromium
           'AppData\Local\Chromium\User Data\*\Current Session'                         # Chromium
           'AppData\Local\Chromium\User Data\*\Current Tabs'                            # Chromium
           'AppData\Local\Chromium\User Data\*\Last Session'                            # Chromium
           'AppData\Local\Chromium\User Data\*\Last Tabs'                               # Chromium
           'AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Sessions\*'           # Brave
           'AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Current Session'      # Brave
           'AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Current Tabs'         # Brave
           'AppData\Local\Vivaldi\User Data\*\Sessions\*'                               # Vivaldi
           'AppData\Local\Yandex\YandexBrowser\User Data\*\Sessions\*'                  # Yandex
           'AppData\Local\Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data\*\Sessions\*' # Arc
           'AppData\Local\CocCoc\Browser\User Data\*\Sessions\*'                        # Coc Coc
           'AppData\Local\CocCoc\Browser\User Data\*\Current Session'                   # Coc Coc
           'AppData\Local\CocCoc\Browser\User Data\*\Current Tabs'                      # Coc Coc
           'AppData\Local\CocCoc\Browser\User Data\*\Last Session'                      # Coc Coc
           'AppData\Local\CocCoc\Browser\User Data\*\Last Tabs'                         # Coc Coc
           'AppData\Local\Tencent\QQBrowser\User Data\*\Sessions\*'                     # QQ Browser
           'AppData\Local\Tencent\QQBrowser\User Data\*\Current Session'                # QQ Browser
           'AppData\Local\Tencent\QQBrowser\User Data\*\Current Tabs'                   # QQ Browser
           'AppData\Local\Tencent\QQBrowser\User Data\*\Last Session'                   # QQ Browser
           'AppData\Local\Tencent\QQBrowser\User Data\*\Last Tabs'                      # QQ Browser
           'AppData\Local\UCBrowser\User Data*\*\Sessions\*'                            # UC Browser
           'AppData\Local\UCBrowser\User Data*\*\Current Session'                       # UC Browser
           'AppData\Local\UCBrowser\User Data*\*\Current Tabs'                          # UC Browser
           'AppData\Local\UCBrowser\User Data*\*\Last Session'                          # UC Browser
           'AppData\Local\UCBrowser\User Data*\*\Last Tabs'                             # UC Browser
           'AppData\Roaming\360se6\User Data\*\Sessions\*'                              # 360 Secure Browser
           'AppData\Roaming\360se6\User Data\*\Current Session'                         # 360 Secure Browser
           'AppData\Roaming\360se6\User Data\*\Current Tabs'                            # 360 Secure Browser
           'AppData\Roaming\360se6\User Data\*\Last Session'                            # 360 Secure Browser
           'AppData\Roaming\360se6\User Data\*\Last Tabs'                               # 360 Secure Browser
           'AppData\Local\WaveBrowser\User Data\*\Sessions\*'                           # Wave Browser
           'AppData\Local\WaveBrowser\User Data\*\Current Session'                      # Wave Browser
           'AppData\Local\WaveBrowser\User Data\*\Current Tabs'                         # Wave Browser
           'AppData\Local\WaveBrowser\User Data\*\Last Session'                         # Wave Browser
           'AppData\Local\WaveBrowser\User Data\*\Last Tabs'                            # Wave Browser
           'AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Sessions\*' # Prisma Access Browser
           'AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Current Session' # Prisma Access Browser
           'AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Current Tabs'    # Prisma Access Browser
           'AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Last Session'    # Prisma Access Browser
           'AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\Last Tabs'       # Prisma Access Browser
           'AppData\Local\Supermium\User Data\*\Sessions\*'                             # Supermium
           'AppData\Local\Supermium\User Data\*\Current Session'                        # Supermium
           'AppData\Local\Supermium\User Data\*\Current Tabs'                           # Supermium
           'AppData\Local\Supermium\User Data\*\Last Session'                           # Supermium
           'AppData\Local\Supermium\User Data\*\Last Tabs'                              # Supermium
           'AppData\Roaming\Mozilla\Firefox\Profiles\*\sessionstore*'                   # Firefox
           'AppData\Roaming\Mozilla\Firefox\Profiles\*\sessionstore-backups\**\*'       # Firefox
           'AppData\Local\Microsoft\Internet Explorer\Recovery\**\*'                    # IE
           'AppData\Local\Microsoft\Internet Explorer\TabRoaming\**\*'                  # IE
           'Local Settings\Application Data\Google\Chrome\User Data\*\Current Session'      # XP: Chrome
           'Local Settings\Application Data\Google\Chrome\User Data\*\Current Tabs'         # XP: Chrome
           'Local Settings\Application Data\Google\Chrome\User Data\*\Last Session'         # XP: Chrome
           'Local Settings\Application Data\Google\Chrome\User Data\*\Last Tabs'            # XP: Chrome
           'Application Data\Supermium\User Data\*\Sessions\*'                          # XP: Supermium
           'Application Data\Mozilla\Firefox\Profiles\*\sessionstore*'                  # XP: Firefox
           'Local Settings\Application Data\Microsoft\Internet Explorer\Recovery\**\*'  # XP: IE
       ) }
    # Web storage: sites' local storage (Chromium's LevelDB, IE's DOMStore).
    @{ Name = 'Browser Web Storage'; Group = 3; PresentByDefault = @(@{ Lineage = 'client'; From = '6.1' } <# Windows 7 on #>, @{ Lineage = 'server'; From = '6.0' } <# Windows Server 2008 on #>); CountBy = 'Folder'
       User = @(
           'AppData\Local\Microsoft\Edge\User Data\*\Local Storage\leveldb\**\*'            # Edge
           'AppData\Local\Microsoft\Edge Beta\User Data\*\Local Storage\leveldb\**\*'       # Edge Beta
           'AppData\Local\Microsoft\Edge Dev\User Data\*\Local Storage\leveldb\**\*'        # Edge Dev
           'AppData\Local\Microsoft\Edge SxS\User Data\*\Local Storage\leveldb\**\*'        # Edge Canary
           'AppData\Local\Google\Chrome\User Data\*\Local Storage\**\*'                     # Chrome
           'AppData\Local\Google\Chrome Beta\User Data\*\Local Storage\leveldb\**\*'        # Chrome Beta
           'AppData\Local\Google\Chrome Dev\User Data\*\Local Storage\leveldb\**\*'         # Chrome Dev
           'AppData\Local\Google\Chrome SxS\User Data\*\Local Storage\leveldb\**\*'         # Chrome Canary
           'AppData\Local\Chromium\User Data\*\Local Storage\leveldb\**\*'                  # Chromium
           'AppData\Local\Microsoft\Internet Explorer\DOMStore\**\*'                        # IE
           'AppData\LocalLow\Microsoft\Internet Explorer\DOMStore\**\*'                     # IE
           'Local Settings\Application Data\Microsoft\Internet Explorer\DOMStore\**\*'      # XP: IE
       ) }
    # Credential Manager's vault: the credentials Windows keeps for a user (web and
    # Windows credentials), each file with its own times.
    @{ Name = 'Credential Manager'; Group = 3; User = 'AppData\Local\Microsoft\Vault\*\*.vcrd' }
    # File History catalogs (Catalog1/2.edb): metadata about backed-up files, not
    # the files themselves; only present when File History is enabled.
    @{ Name = 'File History Catalogs'; Group = 3; User = 'AppData\Local\Microsoft\Windows\FileHistory\Configuration\Catalog*.edb' }
    @{ Name = 'JumpLists'; Group = 3; PresentByDefault = @(@{ Lineage = 'client'; From = '6.1' } <# Windows 7 on #>); AbsentByDefault = @(@{ Lineage = 'client'; Before = '6.1'; Why = $gapReasons.WindowsVersion } <# client releases before Windows 7 #>); User = @(
        'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms'
        'AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms'
    ) }
    # Shortcuts: recent files, Office recent, desktop and Start Menu (top level only).
    @{ Name = 'LNK'; Group = 3; PresentByDefault = @(@{ Lineage = 'client'; From = '5.1'; Before = '6.0' } <# Windows XP to before Windows Vista #>, @{ Lineage = 'client'; From = '6.1' } <# Windows 7 on #>)
       System = @(
           'ProgramData\Microsoft\Windows\Start Menu\Programs\*.lnk'
           'System Volume Information\_restore*\RP*\*.lnk'               # XP restore points
       )
       User = @(
           'AppData\Roaming\Microsoft\Windows\Recent\*.lnk'
           'AppData\Roaming\Microsoft\Office\Recent\**\*'
           'Desktop\*.lnk'
           'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*.lnk'
           'Recent\**\*'                                                 # XP
       ) }
    # OneDrive: settings (file lists, sync database) and client activity logs (.odl,
    # .odlgz, .odlsent, .aodl, .loggz) with the .keystore needed to decode their
    # obfuscated strings, and the sync diagnostics log, then the older SkyDrive
    # and Windows 8.1 built-in client locations. Not the client's own program
    # files or the synced files; its ETW traces are OneDrive ETL Traces.
    # OneDrive's ETW traces (.etl) of Windows 8.1's built-in client.
    @{ Name = 'OneDrive ETL Traces'; Group = 3; User = 'AppData\Local\Microsoft\Windows\SkyDrive\logs\*.etl' }
    @{ Name = 'OneDrive Metadata'; Group = 3; User = @(
        'AppData\Local\Microsoft\OneDrive\settings\**\*'
        'AppData\Local\Microsoft\OneDrive\logs\**\*.odl*'
        'AppData\Local\Microsoft\OneDrive\logs\**\*.aodl'
        'AppData\Local\Microsoft\OneDrive\logs\**\*.loggz'
        'AppData\Local\Microsoft\OneDrive\logs\**\*.keystore'
        'AppData\Local\Microsoft\OneDrive\logs\Personal\SyncDiagnostics.log'
        'AppData\Local\Microsoft\SkyDrive\logs\**\*'                       # SkyDrive
        'AppData\Local\Microsoft\Windows\OneDrive\logs\**\*'              # Windows 8.1
        'AppData\Local\Microsoft\Windows\SkyDrive\logs\SyncDiagnostics.log'   # Windows 8.1
    ) }
    # PSReadLine history for every host (console, VS Code, ...), including SYSTEM's.
    @{ Name = 'PowerShell History'; Group = 3
       System = @(
           'Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*_history.txt'
           'Windows\SysWOW64\config\systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*_history.txt'
       )
       User = 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*_history.txt' }
    # Transcripts go to the user's Documents - possibly moved into OneDrive (Known
    # Folder Move) - directly or, with policy transcription, in date subfolders.
    # Policy can also redirect them to a central folder (Windows PowerShell and PS 7);
    # System lists other places they are commonly found (SYSTEM runs, C:\PSTranscript).
    @{ Name = 'PowerShell Transcripts'; Group = 3
       System = @(
           'Windows\System32\*\PowerShell_transcript.*.txt'
           'Windows\SysWOW64\*\PowerShell_transcript.*.txt'
           'PSTranscript\20*\PowerShell_transcript.*.txt'
       )
       User = @(
           'Documents\PowerShell_transcript.*.txt'
           'Documents\20*\PowerShell_transcript.*.txt'
           'OneDrive*\Documents\PowerShell_transcript.*.txt'
           'OneDrive*\Documents\20*\PowerShell_transcript.*.txt'
       )
       RegistryFolders = @(
           @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Value = 'OutputDirectory'; Pattern = '**\PowerShell_transcript.*.txt' }
           @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\Transcription';     Value = 'OutputDirectory'; Pattern = '**\PowerShell_transcript.*.txt' }
       ) }
    # Recycle Bin metadata only ($I records; INFO2 on XP), no deleted-file content.
    @{ Name = 'Recycle Bin'; Group = 3; PresentByDefault = @(@{ Lineage = 'client'; From = '5.0' } <# Windows 2000 Professional on #>, @{ Lineage = 'server'; From = '5.0' } <# Windows 2000 Server on #>); Drives = 'All'; System = @(
        '$Recycle.Bin\*\$I*'
        '$Recycle.Bin\$I*'                                               # FAT/exFAT: no per-SID folders
        'RECYCLE*\**\INFO2'                                              # XP (RECYCLER / RECYCLED)
    ) }
    # User hives, plus the service accounts' hives: DEFAULT is the SYSTEM account's
    # (HKU\.DEFAULT / S-1-5-18), the others LocalService and NetworkService.
    @{ Name = 'Registry Hives (user)'; Group = 3; PresentByDefault = @(@{ Lineage = 'client'; From = '4.0' } <# Windows NT 4.0 Workstation on #>, @{ Lineage = 'server'; From = '4.0' } <# Windows NT 4.0 Server on #>); ExpectLocked = { <# logged-on users' and service hives #> $true }; TransactionLogs = $true; FollowUp = 'User'   # users' hives, not the built-in service accounts'
       System = @(
           'Windows\System32\config\DEFAULT'
           'Windows\System32\config\systemprofile\NTUSER.DAT'
           'Windows\ServiceProfiles\LocalService\NTUSER.DAT'
           'Windows\ServiceProfiles\NetworkService\NTUSER.DAT'
           'Windows.old\Windows\System32\config\DEFAULT'
           'Windows.old\Windows\System32\config\systemprofile\NTUSER.DAT'
           'Windows.old\Windows\ServiceProfiles\LocalService\NTUSER.DAT'
           'Windows.old\Windows\ServiceProfiles\NetworkService\NTUSER.DAT'
       )
       User = @(
           'NTUSER.DAT'
           'AppData\Local\Microsoft\Windows\UsrClass.dat'
           'Local Settings\Application Data\Microsoft\Windows\UsrClass.dat'   # XP
       ) }
    @{ Name = 'Startup Folders'; Group = 3
       System = 'ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\**\*'
       User   = 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\**\*' }
    # Teams client logs only (sign-ins, calls, meetings); no message stores or caches.
    # New Teams (work/school), the Windows 11 built-in Teams, then classic Teams.
    @{ Name = 'Teams Logs'; Group = 3; User = @(
        'AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\Logs\*'
        'AppData\Local\Packages\MicrosoftTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\Logs\*'
        'AppData\Roaming\Microsoft\Teams\logs.txt'                              # classic Teams
        'AppData\Roaming\Microsoft\Teams\old_logs_*.txt'                        # classic Teams
    ) }
    # Explorer's thumbnail cache index only, not the cached thumbnails (content).
    @{ Name = 'Thumbcache'; Group = 3; PresentByDefault = @(@{ Lineage = 'client'; From = '6.0' } <# Windows Vista on #>); User = 'AppData\Local\Microsoft\Windows\Explorer\thumbcache_idx.db' }
    # WER: only the .wer report metadata, never the crash dumps (bulk binary content).
    @{ Name = 'WER'; Group = 3
       System = 'ProgramData\Microsoft\Windows\WER\**\*.wer'
       User   = 'AppData\Local\Microsoft\Windows\WER\**\*.wer' }
    # Windows Timeline's activity database.
    @{ Name = 'Windows Timeline'; Group = 3; User = 'AppData\Local\ConnectedDevicesPlatform\**\ActivitiesCache.db*' }
)

# The columns of collection.csv, one row per file the run attempted and one per
# folder it couldn't list:
#   Artefact     the summary row the file or folder belongs to ('User profiles'
#                for a profile root that couldn't be listed)
#   Outcome      collected | size changed | incomplete | not accessible
#                (see Copy-FileToZip) | not local (content not on the disk,
#                not read: Test-FileItemIsNotLocal) | folder not listed |
#                artefact failed (the row's collection failed as a whole) |
#                not collected (the run stopped to keep the free-space reserve
#                during or before this artefact, one row per artefact: the
#                zip is partial); for the last three every cell but Artefact,
#                Outcome, Source and Detail is empty
#   Source       the file's path on the device, or the folder's
#   Entry        its path inside the zip ('' when nothing was written)
#   Size         its size in bytes when opened ('' if it couldn't be opened)
#   BytesCopied  the bytes written to the zip entry
#   SHA-256      of those bytes, lower-case hex ('' when nothing was written)
#   Created, Modified, Accessed  the file's own times, read just before the open
#                (Get-FileOwnTime), UTC (ISO 8601, Z); '' where unknown or the
#                file was never listed (NTFS metafiles)
#   Detail       the error, for a failure ("access denied" or the error, for a
#                folder not listed; why it wasn't read, for a file not local)
# Empty files and file symbolic links are not attempted and have no row (owner's
# decision): the record lists what was collected and what couldn't be read. A
# folder not listed has one row per artefact that met it, as each of those
# counts it once in its summary line; a file has one row in all.
$fileRecordColumns = @('Artefact', 'Outcome', 'Source', 'Entry', 'Size', 'BytesCopied', 'SHA-256', 'Created', 'Modified', 'Accessed', 'Detail')

# ============================= FUNCTIONS =============================
#
# Conventions: a function returns its outcome; it never records one in script
# state. Where a function meets a folder it can't list, it adds that folder to
# the list its caller passes as -FoldersNotListed, so the side effect is named at
# every call site. Script-scope state is limited to caches, the run log and the
# console (see MAIN).

# --- Text helpers ---

# An error's message on one line (some end with a line break), for the console,
# the log and the per-file record. A .NET call made from PowerShell that throws
# arrives wrapped ('Exception calling "Open" with "4" argument(s): "..."'); the
# wrapper (an ExtendedTypeSystemException: calling, getting or setting) is
# taken off, so the message is the underlying error's own.
function Get-OneLineMessage {
    param($ErrorRecord)
    $exception = $ErrorRecord.Exception
    while ($exception -is [System.Management.Automation.ExtendedTypeSystemException] -and $exception.InnerException) {
        $exception = $exception.InnerException
    }
    return (($exception.Message -replace '\s*[\r\n]+\s*', ' ').Trim())
}

# One CSV line: every cell quoted, a quote inside a cell doubled (RFC 4180).
function ConvertTo-CsvLine {
    param([string[]]$Cells)
    $quotedCells = foreach ($cell in $Cells) { '"' + ([string]$cell -replace '"', '""') + '"' }
    return ($quotedCells -join ',')
}

# Numbers on the console and in the run log, in the console frame's formats
# and the invariant culture, so the host's locale never changes them: counts
# with a comma as the thousands
# separator ('1,204'); sizes in IEC binary units with two decimals ('8.41 GiB',
# 1 MiB = 1,048,576 bytes); bytes in full where exactness matters ('412,000,000
# bytes'); durations as h:mm:ss ('0:11:15'). collection.csv keeps plain
# numbers: it is data, not text to read.
function Format-Count {
    param([long]$Count)
    return $Count.ToString('N0', [Globalization.CultureInfo]::InvariantCulture)
}

function Format-ByteCount {
    param([long]$Bytes)
    return ((Format-Count -Count $Bytes) + ' bytes')
}

# A size in the largest IEC binary unit it reaches (KiB to TiB), e.g.
# '1.00 GiB'; under 1 KiB in bytes.
function Format-Size {
    param([long]$Bytes)
    $units = @(@{ Name = 'TiB'; Bytes = 1TB }, @{ Name = 'GiB'; Bytes = 1GB }, @{ Name = 'MiB'; Bytes = 1MB }, @{ Name = 'KiB'; Bytes = 1KB })
    foreach ($unit in $units) {
        if ($Bytes -ge $unit.Bytes) { return (($Bytes / $unit.Bytes).ToString('N2', [Globalization.CultureInfo]::InvariantCulture) + ' ' + $unit.Name) }
    }
    return (Format-ByteCount -Bytes $Bytes)
}

# A size in mebibytes, e.g. '185.64' (the total line's own unit, MiB).
function Format-Mebibyte {
    param([long]$Bytes)
    return (($Bytes / 1MB).ToString('N2', [Globalization.CultureInfo]::InvariantCulture))
}

function Format-Duration {
    param([timespan]$Duration)
    return [string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0}:{1:D2}:{2:D2}', [long][math]::Floor($Duration.TotalHours), $Duration.Minutes, $Duration.Seconds)
}

# A file time for the per-file record: ISO 8601 in UTC with a trailing Z and
# 100 ns precision (the file system's own precision); empty when unknown.
function Format-RecordTime {
    param($DateTimeUtc)
    if ($null -eq $DateTimeUtc) { return '' }
    return ([DateTime]$DateTimeUtc).ToUniversalTime().ToString('o')
}

# --- Links and names ---

# True if a folder (a DirectoryInfo from Get-Item or Get-ChildItem) is a
# junction or symbolic link. Folder links are never followed, as the reference
# collector doesn't follow them: a link can point outside the searched
# location, and Windows' own ones duplicate real folders ("All Users",
# "Default User", the XP compatibility links such as "Local Settings" or
# "Application Data" inside profiles). PowerShell 5.1 leaves LinkType empty
# for a link that denies listing to everyone, as Windows' own compatibility
# links do, so a reparse point whose type can't be read and whose listing is
# denied counts as a link too. Other reparse points that can be listed (e.g.
# OneDrive cloud folders) are ordinary folders.
function Test-FolderItemIsLink {
    param($Item)
    $linkType = $Item.LinkType
    if ($linkType -eq 'Junction' -or $linkType -eq 'SymbolicLink') { return $true }
    if ($linkType -or -not ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { return $false }
    $entries = $null
    try {
        $entries = [System.IO.Directory]::EnumerateFileSystemEntries($Item.FullName).GetEnumerator()
        $null = $entries.MoveNext()
        return $false
    } catch [System.UnauthorizedAccessException] {
        return $true
    } catch {
        return $false
    } finally {
        if ($entries) { try { $entries.Dispose() } catch {} }
    }
}

# True if a file (a FileInfo from a listing) is a symbolic link. A file link is
# never followed: its content would arrive from outside the searched location
# under a name inside it (the reference collector skips them too). It is left
# out entirely, like an empty file. Only symbolic links count: a file reparse
# point of another kind (a OneDrive file, a deduplicated file) is a file, read
# unless its content isn't on the disk (Test-FileItemIsNotLocal), and a hard
# link can't be told from the file itself.
function Test-FileItemIsSymbolicLink {
    param($Item)
    if (-not ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { return $false }
    try { return ($Item.LinkType -eq 'SymbolicLink') } catch { return $false }
}

# True if a file's content isn't on the disk: a OneDrive Files On-Demand
# placeholder, or a file moved to offline storage. Reading it would make the
# provider fetch the content, over the network, and change the host, so it is
# not read (owner, 2026-10-24); getfile can't fetch it either. Attributes, from
# the listing: Offline (0x1000), RecallOnOpen (0x40000), RecallOnDataAccess
# (0x400000; .NET Framework has no names for the last two).
function Test-FileItemIsNotLocal {
    param($Item)
    $notLocalAttributes = 0x1000 -bor 0x40000 -bor 0x400000
    try { return (([int64]$Item.Attributes -band $notLocalAttributes) -ne 0) } catch { return $false }
}

# The target of a link item, or '' if it can't be read.
function Get-LinkTarget {
    param($Item)
    try { return [string](@($Item.Target)[0]) } catch { return '' }
}

# True if a name in Path ends with a dot or a space (e.g. 'dir.' or 'space ').
# PowerShell's listing normalises such a path to the name without them, so it
# lists another folder (or none): these folders are listed with .NET through
# the \\?\ prefix instead (Get-ChildFolderWithExtendedPrefix,
# Get-ChildFileWithExtendedPrefix).
function Test-NameEndsInDotOrSpace {
    param([string]$Path)
    return ($Path -match '[. ](\\|$)')
}

# A folder path safe to list: a bare drive ('C:') means that drive's current
# directory to PowerShell, so it becomes the drive root ('C:\').
function ConvertTo-ListablePath {
    param([string]$Path)
    if ($Path -match '^[A-Za-z]:$') { return $Path + '\' }
    return $Path
}

# --- Folder listing ---

# Record a folder that exists but could not be listed (access denied, an I/O
# error) in FoldersNotListed, so what it holds counts as not accessible rather
# than missing. A folder that doesn't exist is no failure: that is what Missing
# means. Only the first error of a listing is recorded.
function Add-FolderNotListed {
    param([string]$Path, $ErrorRecords, [System.Collections.Generic.List[object]]$FoldersNotListed)
    foreach ($record in @($ErrorRecords)) {
        if (-not $record) { continue }
        if ($record.CategoryInfo.Category -eq 'ObjectNotFound') { continue }
        $reason = if ($record.CategoryInfo.Category -eq 'PermissionDenied') { 'access denied' } else { Get-OneLineMessage -ErrorRecord $record }
        $FoldersNotListed.Add([pscustomobject]@{ Path = $Path; Reason = $reason })
        return
    }
}

# Add folders not listed (Path, Reason) to Table, an ordered folder path ->
# reason table, keeping the first reason met for each folder. Walks the list
# with foreach: Windows PowerShell 5.1 throws "Argument types do not match"
# for @() applied to a List[object] variable (round 2).
function Add-FolderToNotListedTable {
    param($Table, $Folders)
    foreach ($folder in $Folders) {
        if ($folder -and -not $Table.Contains($folder.Path)) { $Table[$folder.Path] = $folder.Reason }
    }
}

# The reason a .NET listing through \\?\ failed, in the words the console uses;
# '' when the folder simply doesn't exist.
function Get-ExtendedListingFailureReason {
    param($ErrorRecord)
    $innermost = $ErrorRecord.Exception
    while ($innermost.InnerException) { $innermost = $innermost.InnerException }
    if ($innermost -is [System.IO.DirectoryNotFoundException]) { return '' }
    if ($innermost -is [System.NotSupportedException] -or $innermost -is [System.ArgumentException]) {
        return 'its name ends in a dot or a space, which this .NET version cannot list'
    }
    if ($innermost -is [System.UnauthorizedAccessException]) { return 'access denied' }
    return (Get-OneLineMessage -ErrorRecord $ErrorRecord)
}

# Full paths of the subfolders (other than links) of a folder whose name
# PowerShell would normalise (Test-NameEndsInDotOrSpace), listed with .NET
# through \\?\. A listing that fails is recorded in FoldersNotListed.
function Get-ChildFolderWithExtendedPrefix {
    param([string]$Path, [string]$Filter = '*', [System.Collections.Generic.List[object]]$FoldersNotListed)
    try {
        $folder = New-Object System.IO.DirectoryInfo ('\\?\' + $Path)
        foreach ($subfolder in $folder.EnumerateDirectories($Filter)) {
            if (Test-FolderItemIsLink -Item $subfolder) { continue }
            $subfolder.FullName.Substring(4)   # without the \\?\ prefix
        }
    } catch {
        $reason = Get-ExtendedListingFailureReason -ErrorRecord $_
        if ($reason) { $FoldersNotListed.Add([pscustomobject]@{ Path = $Path; Reason = $reason }) }
    }
}

# The files of such a folder (see Get-ChildFolderWithExtendedPrefix), as
# matches: @{ Path = the plain path; Item = the FileInfo from the listing }.
function Get-ChildFileWithExtendedPrefix {
    param([string]$Path, [string]$Filter = '*', [System.Collections.Generic.List[object]]$FoldersNotListed)
    try {
        $folder = New-Object System.IO.DirectoryInfo ('\\?\' + $Path)
        foreach ($file in $folder.EnumerateFiles($Filter)) {
            [pscustomobject]@{ Path = $file.FullName.Substring(4); Item = $file }
        }
    } catch {
        $reason = Get-ExtendedListingFailureReason -ErrorRecord $_
        if ($reason) { $FoldersNotListed.Add([pscustomobject]@{ Path = $Path; Reason = $reason }) }
    }
}

# Full paths of the subfolders of Path matching Filter, skipping links (see
# Test-FolderItemIsLink). A folder that can't be listed is recorded in
# FoldersNotListed.
function Get-ChildFolder {
    param([string]$Path, [string]$Filter = '*', [System.Collections.Generic.List[object]]$FoldersNotListed)
    if (Test-NameEndsInDotOrSpace -Path $Path) {
        return (Get-ChildFolderWithExtendedPrefix -Path $Path -Filter $Filter -FoldersNotListed $FoldersNotListed)
    }
    $listingErrors = $null
    try {
        Get-ChildItem -LiteralPath $Path -Filter $Filter -Directory -Force -ErrorAction SilentlyContinue -ErrorVariable listingErrors |
            Where-Object { -not (Test-FolderItemIsLink -Item $_) } |
            ForEach-Object { $_.FullName }
    } catch { $listingErrors = @($_) }
    Add-FolderNotListed -Path $Path -ErrorRecords $listingErrors -FoldersNotListed $FoldersNotListed
}

# The files of Path matching Filter, as matches (@{ Path; Item }). A folder
# that can't be listed is recorded in FoldersNotListed.
function Get-ChildFile {
    param([string]$Path, [string]$Filter = '*', [System.Collections.Generic.List[object]]$FoldersNotListed)
    if (Test-NameEndsInDotOrSpace -Path $Path) {
        return (Get-ChildFileWithExtendedPrefix -Path $Path -Filter $Filter -FoldersNotListed $FoldersNotListed)
    }
    $listingErrors = $null
    try {
        Get-ChildItem -LiteralPath (ConvertTo-ListablePath -Path $Path) -Filter $Filter -File -Force -ErrorAction SilentlyContinue -ErrorVariable listingErrors |
            ForEach-Object { [pscustomobject]@{ Path = $_.FullName; Item = $_ } }
    } catch { $listingErrors = @($_) }
    Add-FolderNotListed -Path $Path -ErrorRecords $listingErrors -FoldersNotListed $FoldersNotListed
}

# A folder and every folder below it, never following links, with no depth
# limit. Folders that can't be listed are recorded in FoldersNotListed.
function Get-FolderTree {
    param([string]$Path, [System.Collections.Generic.List[object]]$FoldersNotListed)
    $Path
    foreach ($subfolder in (Get-ChildFolder -Path (ConvertTo-ListablePath -Path $Path) -FoldersNotListed $FoldersNotListed)) {
        Get-FolderTree -Path $subfolder -FoldersNotListed $FoldersNotListed
    }
}

# True if Path is a junction or symbolic link (see Test-FolderItemIsLink).
# Cached in $script:folderLinkCache, as the same folders are checked for many
# patterns.
function Test-FolderPathIsLink {
    param([string]$Path)
    if ($script:folderLinkCache.ContainsKey($Path)) { return $script:folderLinkCache[$Path] }
    $isLink = $false
    try {
        if (Test-NameEndsInDotOrSpace -Path $Path) {
            # Get-Item would return the folder without the trailing dot or space.
            $item = New-Object System.IO.DirectoryInfo ('\\?\' + $Path)
            if ($item.Exists) { $isLink = Test-FolderItemIsLink -Item $item }
        } else {
            $isLink = Test-FolderItemIsLink -Item (Get-Item -LiteralPath $Path -Force -ErrorAction Stop)
        }
    } catch { $isLink = $false }   # a folder that can't be read is listed later, and recorded then
    $script:folderLinkCache[$Path] = $isLink
    return $isLink
}

# A folder path with each folder name in its on-disk case (e.g. a pattern's
# '$Recycle.Bin' is '$RECYCLE.BIN' on a FAT drive), so zip entries keep the
# original paths. A name that can't be found is kept as given. Cached in
# $script:onDiskCasePathCache, so each folder is looked up once. Silent on
# failure: it only decides the case, and the listings that follow record a
# folder that can't be read.
function Get-OnDiskCasePath {
    param([string]$Path)
    $Path = $Path.TrimEnd('\')
    if ($script:onDiskCasePathCache.ContainsKey($Path)) { return $script:onDiskCasePathCache[$Path] }
    $result = $Path
    $lastSeparator = $Path.LastIndexOf('\')
    if ($lastSeparator -gt 0) {
        $parentPath = Get-OnDiskCasePath -Path $Path.Substring(0, $lastSeparator)
        $name       = $Path.Substring($lastSeparator + 1)
        $result     = $parentPath + '\' + $name
        try {
            $match = Get-ChildItem -LiteralPath (ConvertTo-ListablePath -Path $parentPath) -Filter $name -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq $name } | Select-Object -First 1   # -eq: not a short-name (8.3) match
            if ($match) { $result = $parentPath + '\' + $match.Name }
        } catch { $result = $parentPath + '\' + $name }
    }
    $script:onDiskCasePathCache[$Path] = $result
    return $result
}

# Expand a path pattern, relative to Root, into matches (@{ Path; Item }; none
# if absent). Segments are separated by '\'. The last segment is a file-name
# filter (wildcards allowed; a plain name matches just that file). A folder
# segment containing * or ? matches subfolders; '**' as the last folder segment
# means "anywhere below here" (recursive, no depth limit). Folder links are
# never followed (Test-FolderItemIsLink). A folder that can't be listed is
# recorded in FoldersNotListed. -Literal returns one match for Root\Pattern
# unchecked, without listing it (Item is $null).
function Resolve-PathPattern {
    param([string]$Root, [string]$Pattern, [switch]$Literal, [System.Collections.Generic.List[object]]$FoldersNotListed)

    $base = $Root.TrimEnd('\')
    if ($Literal) { return [pscustomobject]@{ Path = ($base + '\' + $Pattern); Item = $null } }
    $base = Get-OnDiskCasePath -Path $base

    $segments    = $Pattern -split '\\'
    $folderPaths = @($base)
    $recurse     = $false
    foreach ($segment in ($segments | Select-Object -SkipLast 1)) {
        if ($segment -eq '**') {
            $recurse = $true
        } elseif ($segment -match '[*?]') {
            $folderPaths = @(foreach ($folderPath in $folderPaths) {
                Get-ChildFolder -Path (ConvertTo-ListablePath -Path $folderPath) -Filter $segment -FoldersNotListed $FoldersNotListed
            })
        } else {
            $folderPaths = @(foreach ($folderPath in $folderPaths) {
                $nextPath = Get-OnDiskCasePath -Path ($folderPath + '\' + $segment)
                if (-not (Test-FolderPathIsLink -Path $nextPath)) { $nextPath }
            })
        }
    }
    if ($recurse) {
        $folderPaths = @(foreach ($folderPath in $folderPaths) { Get-FolderTree -Path $folderPath -FoldersNotListed $FoldersNotListed })
    }
    foreach ($folderPath in $folderPaths) {
        Get-ChildFile -Path $folderPath -Filter $segments[-1] -FoldersNotListed $FoldersNotListed
    }
}

# --- Registry and host facts ---

# A registry value with environment variables expanded, or $null if the key or
# value is absent or unreadable.
function Get-RegistryValue {
    param([string]$Path, [string]$Name)
    try {
        $value = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
        if ($value) { return [Environment]::ExpandEnvironmentVariables($value) }
    } catch { return $null }
    return $null
}

# Facts about the host for the OS line and the summary notes. The name and type
# come from CIM (Win32_OperatingSystem's caption is right for Windows 11) and
# the release (e.g. 23H2) from the registry; if CIM fails, the registry alone,
# correcting its ProductName, which still says "Windows 10" on Windows 11.
# Decisions use the OS version (NtVersion: 6.1.7601, 10.0.19045), the build and
# the lineage (client for a workstation, server for a server or domain
# controller), never the name, which is localised. A fact that can't be
# determined stays $null, and conditions treat $null as "not expected".
function Get-HostInfo {
    $currentVersionKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $info = @{ Caption = $null; Version = $null; Build = $null; NtVersion = $null; Lineage = $null; DomainController = $null }
    try {
        $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        # ProductType 1 workstation, 2 domain controller, 3 server; any other
        # value leaves the lineage unknown (the registry below may still give it).
        $productType = $operatingSystem.ProductType
        if ($productType -eq 1)     { $info.Lineage = 'client'; $info.DomainController = $false }
        elseif ($productType -eq 2) { $info.Lineage = 'server'; $info.DomainController = $true }
        elseif ($productType -eq 3) { $info.Lineage = 'server'; $info.DomainController = $false }
        $info.Build            = [int]$operatingSystem.BuildNumber
        $info.NtVersion        = [version]$operatingSystem.Version
        $info.Caption          = $operatingSystem.Caption.Trim()   # last: an empty Caption throws, the facts above stand
    } catch {}   # no CIM: the registry below
    try {
        $currentVersion = Get-ItemProperty -LiteralPath $currentVersionKey -ErrorAction Stop
        $info.Version = if ($currentVersion.DisplayVersion) { $currentVersion.DisplayVersion } else { $currentVersion.ReleaseId }
        if (-not $info.Build) { $info.Build = [int]$currentVersion.CurrentBuild }
        if ($null -eq $info.NtVersion -and $currentVersion.CurrentBuild) {
            # CurrentMajorVersionNumber from Windows 10 on; CurrentVersion (6.1) before.
            $majorMinor = if ($null -ne $currentVersion.CurrentMajorVersionNumber) { "$($currentVersion.CurrentMajorVersionNumber).$($currentVersion.CurrentMinorVersionNumber)" } else { $currentVersion.CurrentVersion }
            $info.NtVersion = [version]"$majorMinor.$($currentVersion.CurrentBuild)"
        }
        if ($null -eq $info.Lineage) {
            # InstallationType Client, Server or Server Core; any other value leaves it unknown.
            if ($currentVersion.InstallationType -like 'Client*')     { $info.Lineage = 'client' }
            elseif ($currentVersion.InstallationType -like 'Server*') { $info.Lineage = 'server' }
        }
        if (-not $info.Caption -and $currentVersion.ProductName) {
            $info.Caption = $currentVersion.ProductName
            if ($info.Build -ge 22000) { $info.Caption = $info.Caption -replace 'Windows 10', 'Windows 11' }
        }
    } catch {}   # no registry: the CIM facts stand
    # A build or name read as 0 or empty (a missing value) is not known.
    if (-not $info.Build)   { $info.Build   = $null }
    if (-not $info.Caption) { $info.Caption = $null }
    return $info
}

# True if a row's condition (a scriptblock over $hostInfo) holds. A missing or
# failing condition counts as "not expected".
function Test-HostCondition {
    param($Condition)
    if (-not $Condition) { return $false }
    try { return [bool](& $Condition) } catch { return $false }
}

# Whether a row's pattern also takes its matches' registry transaction logs
# (<file>.LOG*): every pattern of a row with TransactionLogs = $true, or, with a
# list of file-name patterns, those whose last segment matches one (-like).
function Test-TransactionLogPattern {
    param($Artefact, [string]$Pattern)
    $transactionLogs = $Artefact.TransactionLogs
    if ($null -eq $transactionLogs) { return $false }
    if ($transactionLogs -is [bool]) { return $transactionLogs }
    $lastSegment = ($Pattern -split '\\')[-1]
    foreach ($fileNamePattern in $transactionLogs) {
        if ($lastSegment -like $fileNamePattern) { return $true }
    }
    return $false
}

# The first of a row's spans (PresentByDefault or AbsentByDefault) that holds
# for this host: its lineage, and its OS version at or after From and before
# Before (a bound left out is none). $null if none does, or if the host's
# version or lineage is not known.
function Find-HostSpan {
    param($Spans)
    if ($null -eq $hostInfo.NtVersion -or $null -eq $hostInfo.Lineage) { return $null }
    foreach ($span in $Spans) {
        if ($span.Lineage -ne $hostInfo.Lineage) { continue }
        if ($span.From -and $hostInfo.NtVersion -lt [version]$span.From) { continue }
        if ($span.Before -and $hostInfo.NtVersion -ge [version]$span.Before) { continue }
        return $span
    }
    return $null
}

# --- Drives and profiles ---

# Every ready local drive, for per-drive artefacts: fixed and removable alike,
# with its file system; network drives and drives that aren't ready (no media,
# locked) are left out. The system drive is always present and comes first;
# if the drive list can't be read, it is searched alone, its file system
# 'unknown'.
function Get-LocalDrive {
    $drives = New-Object 'System.Collections.Generic.List[object]'
    try {
        foreach ($driveInfo in [System.IO.DriveInfo]::GetDrives()) {
            try {
                if ($driveInfo.DriveType -eq [System.IO.DriveType]::Network -or
                    $driveInfo.DriveType -eq [System.IO.DriveType]::NoRootDirectory) { continue }
                if ($driveInfo.IsReady) {
                    $drives.Add([pscustomobject]@{ Root = $driveInfo.Name.TrimEnd('\'); Format = $driveInfo.DriveFormat })
                }
            } catch { continue }   # a drive that can't be read is skipped (best effort)
        }
    } catch { $drives.Clear() }   # no drive list at all: the system drive alone, below
    if (-not ($drives | Where-Object { $_.Root -eq $systemDrive })) {
        $drives.Insert(0, [pscustomobject]@{ Root = $systemDrive; Format = 'unknown' })   # never lose the system drive
    }
    return @($drives | Sort-Object -Property { $_.Root -ne $systemDrive }, Root)
}

# Drive roots ('C:', 'D:') for a row's Drives field: the system drive only by
# default, every local drive ('All'), or those formatted NTFS ('NTFS', which
# includes a drive whose file system is unknown, so it isn't skipped unseen),
# from $script:localDrives. The system drive always comes first.
function Get-DriveRoot {
    param([string]$Kind = 'System')
    if ($Kind -ne 'All' -and $Kind -ne 'NTFS') { return $systemDrive }
    foreach ($drive in $script:localDrives) {
        if ($Kind -eq 'All' -or $drive.Format -eq 'NTFS' -or $drive.Format -eq 'unknown') { $drive.Root }
    }
}

# User profiles: every folder under each profile root, in $profileRoots order
# (deliberately not the registry's ProfileList). A root that is itself a link
# (Documents and Settings -> Users on current Windows) is resolved to its target,
# and only if that can be read and stays on the system drive, so no profile is
# listed twice. Links inside a root ("All Users", "Default User") are skipped by
# Get-ChildFolder. Service accounts are not profiles: rows list their paths.
function Get-UserProfilePath {
    param([System.Collections.Generic.List[object]]$FoldersNotListed)
    $seenRoots = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($rootName in $profileRoots) {
        $rootPath = Join-Path $systemDrive $rootName
        try {
            $rootItem = Get-Item -LiteralPath $rootPath -Force -ErrorAction Stop
            if (Test-FolderItemIsLink -Item $rootItem) {
                # A link whose target can't be read (Windows' compatibility link
                # behind its deny-list) or that leaves the drive is skipped.
                $target = Get-LinkTarget -Item $rootItem
                if (-not $target -or $target -notlike "$systemDrive\*") { continue }
                $rootPath = $target
            }
            if ($seenRoots.Add($rootPath.TrimEnd('\'))) {
                Get-ChildFolder -Path $rootPath -FoldersNotListed $FoldersNotListed
            }
        } catch {
            # No such root (e.g. no Documents and Settings) is nothing to list;
            # any other failure is a folder not listed.
            Add-FolderNotListed -Path $rootPath -ErrorRecords @($_) -FoldersNotListed $FoldersNotListed
        }
    }
}

# Profile folders the registry's ProfileList names that this run doesn't
# search: not found as a profile (UserProfilePaths) and not directly under a
# $profileRoots folder (e.g. a profile moved to another drive). Profiles stay
# the folders under those roots (Get-UserProfilePath); this only names the
# ones outside them, so the gap is seen. A profile listed under a root but no
# longer on disk is not named. The service accounts' entries
# ($serviceAccountSids) are skipped, as rows name their paths; so is an entry
# without a ProfileImagePath (no folder to name).
# Returns @{ Paths; Error } (Error '' when ProfileList was read).
function Get-ProfileOutsideSearchedRoot {
    param([string[]]$UserProfilePaths)
    $result = @{ Paths = New-Object 'System.Collections.Generic.List[string]'; Error = '' }
    $searchedRoots = @($profileRoots | ForEach-Object { Join-Path $systemDrive $_ })
    try {
        foreach ($profileKey in (Get-ChildItem -LiteralPath $profileListKey -ErrorAction Stop)) {
            if ($serviceAccountSids -contains $profileKey.PSChildName) { continue }
            $profilePath = Get-RegistryValue -Path $profileKey.PSPath -Name 'ProfileImagePath'
            if (-not $profilePath) { continue }
            $profilePath = $profilePath.TrimEnd('\')
            $parentPath  = Split-Path -Path $profilePath -Parent
            if ($UserProfilePaths -contains $profilePath -or $searchedRoots -contains $parentPath) { continue }
            $result.Paths.Add($profilePath)
        }
    } catch {
        $result.Error = Get-OneLineMessage -ErrorRecord $_
    }
    return $result
}

# Counting unit for CountBy 'Folder': the folder a match sits in at the pattern's
# own depth (its folder segments before any '**'), counted from Root. E.g. the
# browser profile folder for 'User Data\*\History*', or the History folder for
# 'History\**\index.dat', however deep the file itself is.
function Get-CountByFolderPath {
    param([string]$Root, [string]$Pattern, [string]$Path)
    $folderSegments = @($Pattern -split '\\' | Select-Object -SkipLast 1)
    $depth = [array]::IndexOf($folderSegments, '**')
    if ($depth -lt 0) { $depth = $folderSegments.Count }
    $base = $Root.TrimEnd('\')
    if ($depth -eq 0) { return $base }
    $pathSegments = @($Path.Substring($base.Length + 1) -split '\\')
    return $base + '\' + (($pathSegments | Select-Object -First $depth) -join '\')
}

# --- Zip ---

# True if an error (or any exception inside it) is "disk full" (ERROR_DISK_FULL,
# ERROR_HANDLE_DISK_FULL), i.e. the zip can't grow - as opposed to a locked file.
function Test-DiskFull {
    param($ErrorRecord)
    $exception = $ErrorRecord.Exception
    while ($exception) {
        if (($exception.HResult -band 0xFFFF) -in 39, 112) { return $true }
        $exception = $exception.InnerException
    }
    return $false
}

# The kind of error that stopped a file from opening, so a summary note only
# explains the failures it is about (see the ExpectedOpenError row field):
# 'SharingViolation' (held open by another process: ERROR_SHARING_VIOLATION,
# ERROR_LOCK_VIOLATION), 'AccessDenied', or 'Other' (anything else, e.g. a file
# that is gone).
function Get-OpenErrorKind {
    param($ErrorRecord)
    # Whole HRESULTs (the Win32 error as .NET reports it), not their low word:
    # 0x80004005 (E_FAIL) also ends in 5.
    $exception = $ErrorRecord.Exception
    while ($exception) {
        if ($exception -is [System.UnauthorizedAccessException])  { return 'AccessDenied' }
        if ($exception.HResult -in 0x80070020, 0x80070021)         { return 'SharingViolation' }
        if ($exception.HResult -eq 0x80070005)                     { return 'AccessDenied' }
        $exception = $exception.InnerException
    }
    return 'Other'
}

# The zip entry name for a file path: C:\Users\bob\file.lnk -> C/Users/bob/file.lnk
function ConvertTo-ZipEntryName {
    param([string]$Path)
    return (($Path -replace '^([A-Za-z]):', '$1') -replace '\\', '/')
}

# Lower-case hex of a finished hasher's digest.
function ConvertTo-HexDigest {
    param($Hasher)
    return (($Hasher.Hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

# A file's own created, modified and accessed times (UTC), from the file
# system's record of the file itself (GetFileAttributesEx, through \\?\ as for
# the open), not from the folder listing's copy, which NTFS updates lazily
# (round 2: the listing's last-access lagged the file's own). Read just before
# the open, which doesn't happen here: opening and reading the file move its
# last-access time. Returns @{ Created; Modified; Accessed }, $null for any
# time that can't be read.
function Get-FileOwnTime {
    param([string]$Path)
    $times = @{ Created = $null; Modified = $null; Accessed = $null }
    try {
        try {
            $file = [System.IO.FileInfo]::new('\\?\' + $Path)
        } catch [System.NotSupportedException], [System.ArgumentException] {
            # .NET Framework before 4.6.2 refuses \\?\ paths: as in Copy-FileToZip,
            # the plain path only if it names the same file.
            if (Test-NameEndsInDotOrSpace -Path $Path) { return $times }
            $file = [System.IO.FileInfo]::new($Path)
        }
        $file.Refresh()
        # A FileInfo for a file that is gone reports 1601-01-01, not an error.
        if (-not $file.Exists) { return $times }
        $times.Created  = $file.CreationTimeUtc
        $times.Modified = $file.LastWriteTimeUtc
        $times.Accessed = $file.LastAccessTimeUtc
    } catch {}   # times that can't be read stay unknown
    return $times
}

# True if the free space on the output drive is below $freeSpaceReserve.
# OutputDrive is a DriveInfo, or $null when the free space couldn't be read at
# the start (warned about then). A read that fails now counts as not below: a
# full disk is still caught by the write that fails (Test-DiskFull).
function Test-BelowFreeSpaceReserve {
    param($OutputDrive)
    if (-not $OutputDrive) { return $false }
    try { return ($OutputDrive.AvailableFreeSpace -lt $freeSpaceReserve) } catch { return $false }
}

# Copy one file straight into the zip, opening it with shared access so files
# held open by other processes (e.g. Edge History) can usually still be read.
# The bytes are hashed as they are copied. LastWriteTimeUtc is the file's own
# modified time read before the open (Get-FileOwnTime), for the entry's time;
# $null to read it now (a Literal path). OutputDrive: see
# Test-BelowFreeSpaceReserve, checked before the open and after every block.
# Returns @{ Outcome; SizeWhenOpened; BytesCopied; Sha256; Error; OpenErrorKind;
# DiskFull; BelowReserve }:
#   Outcome  'collected' (every byte of the size when opened),
#            'size changed' (collected, but a live file grew or shrank meanwhile),
#            'incomplete' (the read failed part-way, or the run stopped during
#            it: the entry stays in the zip, incomplete, as Create mode can't
#            remove one) or
#            'not accessible' (the file could not be opened, or wasn't opened
#            because the run stopped first: BelowReserve).
#   OpenErrorKind  when the open failed: Get-OpenErrorKind's answer; else ''.
#   DiskFull      $true when the zip can't grow: collection must stop.
#   BelowReserve  $true when the output drive's free space fell below the
#                 reserve: collection must stop. Found before the open, the
#                 file isn't opened; found during the copy, the entry is closed
#                 as it stands ('incomplete').
function Copy-FileToZip {
    param($Zip, [string]$Path, [string]$EntryName, $LastWriteTimeUtc, $OutputDrive)

    $result = @{ Outcome = 'not accessible'; SizeWhenOpened = $null; BytesCopied = [long]0; Sha256 = ''; Error = ''; OpenErrorKind = ''; DiskFull = $false; BelowReserve = $false }
    if (Test-BelowFreeSpaceReserve -OutputDrive $OutputDrive) {
        $result.BelowReserve = $true
        return $result
    }
    $source       = $null
    $destination  = $null
    $entryCreated = $false
    $hasher       = $null
    # Opened through \\?\ always: .NET normalises a plain path, dropping a trailing
    # dot or space (report. would open report, another file) and limiting it to
    # 260 characters.
    $openPath = '\\?\' + $Path
    try {
        try {
            $source = [System.IO.File]::Open($openPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
        } catch [System.NotSupportedException], [System.ArgumentException] {
            # .NET Framework before 4.6.2 refuses \\?\ paths. A plain path is safe
            # only if no name in it ends with a dot or a space; otherwise it would
            # open another file, so this one counts as not accessible.
            if (Test-NameEndsInDotOrSpace -Path $Path) { throw }
            $openPath = $Path
            $source = [System.IO.File]::Open($openPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
        }
        try { $result.SizeWhenOpened = $source.Length } catch {}   # stays unknown
        # UTC: zip stores a zone-less date/time, so keep it in the always-UTC convention.
        $entryTime = $null
        try {
            $entryTime = if ($null -ne $LastWriteTimeUtc) { $LastWriteTimeUtc } else { [System.IO.File]::GetLastWriteTimeUtc($openPath) }
        } catch {}   # the entry keeps the zip's default time
        $entry = $Zip.CreateEntry($EntryName, [System.IO.Compression.CompressionLevel]::Fastest)
        $entryCreated = $true
        if ($null -ne $entryTime) {
            try { $entry.LastWriteTime = $entryTime } catch {}   # a time the zip format can't hold (before 1980): the default stays
        }
        $destination = $entry.Open()
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        while (($bytesRead = $source.Read($script:copyBuffer, 0, $script:copyBuffer.Length)) -gt 0) {
            $destination.Write($script:copyBuffer, 0, $bytesRead)
            $null = $hasher.TransformBlock($script:copyBuffer, 0, $bytesRead, $null, 0)
            $result.BytesCopied += $bytesRead
            if (Test-BelowFreeSpaceReserve -OutputDrive $OutputDrive) {
                # Stop copying; the entry is closed below as it stands, as the
                # zip of what was collected is kept.
                $result.BelowReserve = $true
                break
            }
        }
        $null = $hasher.TransformFinalBlock($script:copyBuffer, 0, 0)
        $result.Sha256  = ConvertTo-HexDigest -Hasher $hasher
        # Closing the entry writes its last compressed block, its sizes and its
        # CRC: part of the copy, so a failure here is a failed copy, not a
        # clean-up to ignore.
        $destination.Dispose()
        $destination = $null
        if ($result.BelowReserve) {
            $result.Outcome = 'incomplete'
            $result.Error   = 'not finished: the run stopped to keep the free-space reserve'
        } elseif ($null -ne $result.SizeWhenOpened -and $result.BytesCopied -ne $result.SizeWhenOpened) {
            $result.Outcome = 'size changed'
        } else {
            $result.Outcome = 'collected'
        }
    } catch {
        $result.Error = Get-OneLineMessage -ErrorRecord $_
        if (-not $source) { $result.OpenErrorKind = Get-OpenErrorKind -ErrorRecord $_ }
        if (Test-DiskFull -ErrorRecord $_) {
            $result.DiskFull = $true
        } elseif ($entryCreated) {
            $result.Outcome = 'incomplete'
            # The hash of the bytes passed to the entry, so the record still
            # describes them (already there if only closing the entry failed).
            if ($hasher -and -not $result.Sha256) { try { $null = $hasher.TransformFinalBlock($script:copyBuffer, 0, 0); $result.Sha256 = ConvertTo-HexDigest -Hasher $hasher } catch {} }   # no hash then
        }
    } finally {
        # Only after a failure is the entry still open here: its close can fail
        # again, and must not escape.
        if ($destination) { try { $destination.Dispose() } catch {} }
        if ($source)      { try { $source.Dispose() } catch {} }
        if ($hasher)      { try { $hasher.Dispose() } catch {} }
    }
    return $result
}

# --- The per-file record (collection.csv) ---

# One collection.csv line for a file attempted or a folder not listed (columns:
# $fileRecordColumns).
# FileTimes is Get-FileOwnTime's result, or $null for a file never listed.
function New-FileRecordLine {
    param([string]$Artefact, [string]$Outcome, [string]$Source, [string]$Entry, $Size, $BytesCopied, [string]$Sha256, $FileTimes, [string]$Detail)
    $created = ''; $modified = ''; $accessed = ''
    if ($FileTimes) {
        $created  = Format-RecordTime -DateTimeUtc $FileTimes.Created
        $modified = Format-RecordTime -DateTimeUtc $FileTimes.Modified
        $accessed = Format-RecordTime -DateTimeUtc $FileTimes.Accessed
    }
    $sizeText        = if ($null -ne $Size) { [string]$Size } else { '' }
    $bytesCopiedText = if ($null -ne $BytesCopied) { [string]$BytesCopied } else { '' }
    return (ConvertTo-CsvLine -Cells @($Artefact, $Outcome, $Source, $Entry, $sizeText, $bytesCopiedText, $Sha256, $created, $modified, $accessed, $Detail))
}

# Write collection.csv into the zip (UTF-8 without BOM, CRLF), as its last
# entry. Throws if the zip can't take it, closing the entry included (the
# caller tells a full disk from other failures).
function Write-FileRecord {
    param($Zip, [string]$EntryName, [string[]]$Lines)
    $entryStream = $null
    $writer      = $null
    try {
        $entry = $Zip.CreateEntry($EntryName, [System.IO.Compression.CompressionLevel]::Optimal)
        $entry.LastWriteTime = [DateTime]::UtcNow
        $entryStream = $entry.Open()
        $writer = New-Object System.IO.StreamWriter($entryStream, $script:utf8NoBom)
        $writer.NewLine = "`r`n"
        $writer.WriteLine((ConvertTo-CsvLine -Cells $fileRecordColumns))
        foreach ($line in $Lines) { $writer.WriteLine($line) }
        # Disposing the writer closes the entry, which writes its last block:
        # inside the try, so a failure reaches the caller.
        $writer.Dispose()
        $writer      = $null
        $entryStream = $null
    } finally {
        if ($writer)      { try { $writer.Dispose() } catch {} }
        if ($entryStream) { try { $entryStream.Dispose() } catch {} }
    }
}

# --- Collecting one artefact ---

# Tally -> status string:
#   no candidates -> Missing; none read -> Not accessible; else "N collected[, M not accessible]"
function Format-SummaryStatus {
    param([int]$Candidates, [int]$Collected, [int]$Failed)
    if     ($Candidates -eq 0) { return 'Missing' }
    elseif ($Collected -eq 0)  { return 'Not accessible' }
    elseif ($Failed -gt 0)     { return "$(Format-Count -Count $Collected) collected, $(Format-Count -Count $Failed) not accessible" }
    else                       { return "$(Format-Count -Count $Collected) collected" }
}

# The places one artefact row is searched: @{ Root; Scope; Pattern } for each
# drive root and System pattern, each registry-named folder, and each user
# profile and User pattern.
function Get-ArtefactSource {
    param([hashtable]$Artefact, [string[]]$UserProfilePaths)
    foreach ($driveRoot in (Get-DriveRoot -Kind $Artefact.Drives)) {
        foreach ($pattern in $Artefact.System) { @{ Root = $driveRoot; Scope = 'System'; Pattern = $pattern } }
    }
    foreach ($registryFolder in $Artefact.RegistryFolders) {
        $folderPath = Get-RegistryValue -Path $registryFolder.Key -Name $registryFolder.Value
        # Absolute local drive paths only (any letter): skips shares and relative
        # paths. Also skips the root of the system drive, as a recursive search
        # would walk the whole drive; another drive's root is fine - small
        # partitions are sometimes set aside for transcripts.
        if ($folderPath -match '^[A-Za-z]:\\' -and $folderPath.TrimEnd('\') -ne $systemDrive) {
            @{ Root = $folderPath; Scope = 'System'; Pattern = $registryFolder.Pattern }
        }
    }
    foreach ($profilePath in $UserProfilePaths) {
        foreach ($pattern in $Artefact.User) { @{ Root = $profilePath; Scope = 'User'; Pattern = $pattern } }
    }
}

# Collect one artefact row: resolve its patterns in every source, stream every
# match into the zip as it is found, and work out the row's summary line. Each
# source is isolated: a failure there skips only that source.
# Returns the row's result:
#   Status, Note          the summary line and its note ('' if none)
#   IsUnusualGap          whether the row belongs under "Unusual gaps"
#   UnreadableFiles       files found but not read: Path, Scope, Literal, GetFile,
#                         FollowUp, IsTransactionLog (for the getfile follow-ups)
#   FoldersNotListed      Path, Reason
#   SizeDifferences       Path, BytesCopied, SizeWhenOpened, ReadError,
#                         CopyStopped (the run stopped during the copy)
#   FileRecordLines       the row's collection.csv lines
#   CollectedFileCount    files written whole (or as a live file changed)
#   ZipEntryCount         zip entries written (collected, size changed, incomplete)
#   NotLocalFileCount     files not read because their content isn't on the disk
#   StopReason            '' or why collection must stop: 'Full' (the zip
#                         can't grow) or 'BelowReserve' (Test-BelowFreeSpaceReserve;
#                         the row then notes where the run stopped)
function Add-ArtefactToZip {
    param($Zip, [hashtable]$Artefact, [string[]]$UserProfilePaths, $OutputDrive)

    $tally = @{ Candidates = 0; Collected = 0; Failed = 0 }
    # The "(requires ...)" note needs at least one file that failed with the
    # row's expected lock, and none not read for another reason (another open
    # error, content not on the disk). Supporting files of a CountBy row don't
    # decide it.
    $expectedOpenError          = if ($Artefact.ExpectedOpenError) { $Artefact.ExpectedOpenError } else { 'SharingViolation' }
    $failuresExplainedByLock    = 0
    $failuresNotExplainedByLock = 0
    $countByFolderUnits = @{}   # CountBy 'Folder': folder -> @{ Main; Any } (whether its main / any file was read)
    $unreadableFiles  = New-Object 'System.Collections.Generic.List[object]'
    $foldersNotListed = New-Object 'System.Collections.Generic.List[object]'
    $sizeDifferences  = New-Object 'System.Collections.Generic.List[object]'
    $fileRecordLines  = New-Object 'System.Collections.Generic.List[string]'
    $partialCopyCount   = 0
    $collectedFileCount = 0
    $zipEntryCount      = 0
    $notLocalFileCount  = 0
    $stopReason         = ''
    $followUpScope    = if ($Artefact.FollowUp) { $Artefact.FollowUp } else { 'System' }

    :sources foreach ($source in (Get-ArtefactSource -Artefact $Artefact -UserProfilePaths $UserProfilePaths)) {
        try {
            # The hive first, then its transaction logs (marked, so the follow-ups skip them).
            $patterns = @(@{ Text = $source.Pattern; IsTransactionLog = $false })
            if (Test-TransactionLogPattern -Artefact $Artefact -Pattern $source.Pattern) { $patterns += @{ Text = ($source.Pattern + '.LOG*'); IsTransactionLog = $true } }
            foreach ($pattern in $patterns) {
                $matchedFiles = @(Resolve-PathPattern -Root $source.Root -Pattern $pattern.Text -Literal:([bool]$Artefact.Literal) -FoldersNotListed $foldersNotListed)
                foreach ($matchedFile in $matchedFiles) {
                    # Empty files and file symbolic links are left out entirely:
                    # not read, not counted, not recorded.
                    if ($matchedFile.Item -and $matchedFile.Item.Length -eq 0) { continue }
                    if ($matchedFile.Item -and (Test-FileItemIsSymbolicLink -Item $matchedFile.Item)) { continue }
                    $entryName = ConvertTo-ZipEntryName -Path $matchedFile.Path
                    if (-not $script:zipEntryNames.Add($entryName)) { continue }   # the same file, matched by an earlier pattern
                    # The file's own times, read before the open moves its last-access time.
                    $fileTimes        = $null
                    $lastWriteTimeUtc = $null
                    if ($matchedFile.Item) {
                        $fileTimes        = Get-FileOwnTime -Path $matchedFile.Path
                        $lastWriteTimeUtc = $fileTimes.Modified
                    }
                    if ($matchedFile.Item -and (Test-FileItemIsNotLocal -Item $matchedFile.Item)) {
                        # Not read, so its provider doesn't fetch it (Test-FileItemIsNotLocal).
                        $copy = @{ Outcome = 'not local'; SizeWhenOpened = $null; BytesCopied = $null; Sha256 = ''
                                   Error = 'content not on the disk (cloud-only or offline): not read'; DiskFull = $false; BelowReserve = $false }
                        $notLocalFileCount++
                    } else {
                        $copy = Copy-FileToZip -Zip $Zip -Path $matchedFile.Path -EntryName $entryName -LastWriteTimeUtc $lastWriteTimeUtc -OutputDrive $OutputDrive
                    }
                    if ($copy.DiskFull) { $stopReason = 'Full'; break sources }   # the zip can't grow: stop
                    # Below the reserve before the open: this file wasn't attempted.
                    if ($copy.BelowReserve -and $copy.Outcome -ne 'incomplete') { $stopReason = 'BelowReserve'; break sources }
                    $wasRead      = ($copy.Outcome -eq 'collected' -or $copy.Outcome -eq 'size changed')
                    $entryWritten = ($wasRead -or $copy.Outcome -eq 'incomplete')
                    if ($wasRead)      { $collectedFileCount++ }
                    if ($entryWritten) { $zipEntryCount++ }
                    $entryText = if ($entryWritten) { $entryName } else { '' }
                    $fileRecordLines.Add((New-FileRecordLine -Artefact $Artefact.Name -Outcome $copy.Outcome -Source $matchedFile.Path -Entry $entryText -Size $copy.SizeWhenOpened -BytesCopied $copy.BytesCopied -Sha256 $copy.Sha256 -FileTimes $fileTimes -Detail $copy.Error))
                    if ($copy.Outcome -eq 'size changed' -or $copy.Outcome -eq 'incomplete') {
                        # A copy the run stopped (the free-space reserve) didn't fail to read.
                        $readError = if ($copy.Outcome -eq 'incomplete' -and -not $copy.BelowReserve) { $copy.Error } else { '' }
                        $sizeDifferences.Add([pscustomobject]@{ Path = $matchedFile.Path; BytesCopied = $copy.BytesCopied; SizeWhenOpened = $copy.SizeWhenOpened; ReadError = $readError; CopyStopped = [bool]$copy.BelowReserve })
                        if ($copy.Outcome -eq 'incomplete') { $partialCopyCount++ }
                    }
                    # getfile can't fetch a file that isn't on the disk either.
                    if (-not $wasRead -and $copy.Outcome -ne 'not local') {
                        $unreadableFiles.Add([pscustomobject]@{
                            Path = $matchedFile.Path; Scope = $source.Scope
                            Literal = [bool]$Artefact.Literal; GetFile = [bool]$Artefact.GetFile
                            FollowUp = $followUpScope; IsTransactionLog = $pattern.IsTransactionLog
                        })
                    }
                    $fileName         = Split-Path -Path $matchedFile.Path -Leaf
                    $isSupportingFile = ($Artefact.CountBy -eq 'Folder' -and @($Artefact.SupportingFiles | Where-Object { $fileName -like $_ }).Count -gt 0)
                    $failureIsExpectedLock = ($copy.Outcome -eq 'not accessible' -and $copy.OpenErrorKind -eq $expectedOpenError)
                    if (-not $isSupportingFile) {
                        if ($failureIsExpectedLock) {
                            $failuresExplainedByLock++
                        } elseif (-not $wasRead -and $copy.Outcome -ne 'incomplete') {
                            $failuresNotExplainedByLock++
                        }
                    }
                    # A copy the run stopped (the free-space reserve) wasn't refused
                    # by the host: it is recorded as incomplete, but not counted in
                    # the row's status, which says where the run stopped instead.
                    if ($copy.BelowReserve) { $stopReason = 'BelowReserve'; break sources }
                    if ($Artefact.CountBy -eq 'Folder') {
                        $unitPath = Get-CountByFolderPath -Root $source.Root -Pattern $pattern.Text -Path $matchedFile.Path
                        if (-not $countByFolderUnits.ContainsKey($unitPath)) { $countByFolderUnits[$unitPath] = @{ Main = $null; Any = $false } }
                        if ($isSupportingFile) {
                            $countByFolderUnits[$unitPath].Any = $countByFolderUnits[$unitPath].Any -or $wasRead
                        } else {
                            # Every main file must be read: a profile whose History failed
                            # isn't collected because its Shortcuts or Bookmarks.bak was.
                            $countByFolderUnits[$unitPath].Main = ($countByFolderUnits[$unitPath].Main -ne $false) -and $wasRead
                        }
                    } else {
                        $tally.Candidates++
                        if ($wasRead) { $tally.Collected++ } else { $tally.Failed++ }
                    }
                }
            }
        } catch {
            # A source that failed as a whole (its root unreadable in a way the
            # listings didn't record) counts as one folder not listed.
            $foldersNotListed.Add([pscustomobject]@{ Path = $source.Root; Reason = (Get-OneLineMessage -ErrorRecord $_) })
        }
    }

    if ($Artefact.CountBy -eq 'Folder') {
        # Collected if every main file was read; supporting files only decide when
        # a unit has no main file at all (e.g. a lone journal).
        $tally.Candidates = $countByFolderUnits.Count
        $tally.Collected  = @($countByFolderUnits.Values | Where-Object { $_.Main -eq $true -or ($null -eq $_.Main -and $_.Any) }).Count
        $tally.Failed     = $tally.Candidates - $tally.Collected
    }
    # Each folder that couldn't be listed counts as one item not accessible,
    # and has its own row in the record, so the count can be traced to it.
    $unlistedFolders = [ordered]@{}   # folder path -> the first reason met
    Add-FolderToNotListedTable -Table $unlistedFolders -Folders $foldersNotListed
    foreach ($folderPath in $unlistedFolders.Keys) {
        $fileRecordLines.Add((New-FileRecordLine -Artefact $Artefact.Name -Outcome 'folder not listed' -Source $folderPath -Entry '' -Size $null -BytesCopied $null -Sha256 '' -FileTimes $null -Detail $unlistedFolders[$folderPath]))
    }
    $unlistedFolderCount = $unlistedFolders.Count
    $tally.Candidates += $unlistedFolderCount
    $tally.Failed     += $unlistedFolderCount

    $status = Format-SummaryStatus @tally
    $note   = ''
    $absentSpan = if ($status -eq 'Missing') { Find-HostSpan -Spans $Artefact.AbsentByDefault } else { $null }
    if ($null -ne $absentSpan) {
        $note = "($($absentSpan.Why))"
    } elseif ($status -like '*not accessible*' -and $failuresExplainedByLock -gt 0 -and $failuresNotExplainedByLock -eq 0 -and (Test-HostCondition -Condition $Artefact.ExpectLocked)) {
        $requires = if ($Artefact.Requires) { $Artefact.Requires } else { 'NTFS parser' }
        $note = "(requires $requires)"
    }
    # Unusual gaps for the Warnings section: a folder that couldn't be listed or
    # a copy that failed part-way (always, whatever the note), an unexplained
    # lock, or Missing where the artefact should exist on this host. Missing
    # with no expectation either way (usage, configuration) is shown in the
    # summary but not warned about.
    $isUnusualGap = ($unlistedFolderCount -gt 0 -or $partialCopyCount -gt 0 -or
        (-not $note -and (($status -like '*not accessible*') -or
                          ($status -eq 'Missing' -and $null -ne (Find-HostSpan -Spans $Artefact.PresentByDefault)))))
    # The run stopped in this row to keep the free-space reserve: the rest of
    # it wasn't attempted, which the note and the record say. With nothing
    # counted before the stop, the row reads Not collected (not Missing).
    if ($stopReason -eq 'BelowReserve') {
        if ($tally.Candidates -eq 0) { $status = 'Not collected' }
        $note         = '(the run stopped here)'
        $isUnusualGap = $true
        $fileRecordLines.Add((New-FileRecordLine -Artefact $Artefact.Name -Outcome 'not collected' -Source '' -Entry '' -Size $null -BytesCopied $null -Sha256 '' -FileTimes $null -Detail 'the run stopped during this artefact, to keep the free-space reserve: the rest of it was not attempted'))
    }

    return [pscustomobject]@{
        Name = $Artefact.Name; Status = $status; Note = $note; IsUnusualGap = $isUnusualGap
        UnreadableFiles = $unreadableFiles; FoldersNotListed = $foldersNotListed; SizeDifferences = $sizeDifferences
        FileRecordLines = $fileRecordLines; CollectedFileCount = $collectedFileCount; ZipEntryCount = $zipEntryCount
        NotLocalFileCount = $notLocalFileCount; StopReason = $stopReason
    }
}

# The row result for an artefact whose collection failed as a whole (an error
# outside every source's own handling): Failed, warned about, with the error
# named as a folder not listed and in an 'artefact failed' record row.
function New-FailedArtefactResult {
    param([string]$Name, $ErrorRecord)
    $reason = Get-OneLineMessage -ErrorRecord $ErrorRecord
    return [pscustomobject]@{
        Name = $Name; Status = 'Failed'; Note = ''; IsUnusualGap = $true
        UnreadableFiles  = @()
        FoldersNotListed = @([pscustomobject]@{ Path = $Name; Reason = $reason })
        SizeDifferences  = @()
        FileRecordLines  = @(New-FileRecordLine -Artefact $Name -Outcome 'artefact failed' -Source '' -Entry '' -Size $null -BytesCopied $null -Sha256 '' -FileTimes $null -Detail $reason)
        CollectedFileCount = 0; ZipEntryCount = 0; NotLocalFileCount = 0; StopReason = ''
    }
}

# The row result for an artefact the run didn't reach because it stopped to
# keep the free-space reserve: Not collected, with a 'not collected' record
# row. Not an unusual gap of its own: the stop's warning names where it stopped.
function New-NotCollectedResult {
    param([string]$Name)
    return [pscustomobject]@{
        Name = $Name; Status = 'Not collected'; Note = '(the run stopped before it)'; IsUnusualGap = $false
        UnreadableFiles  = @()
        FoldersNotListed = @()
        SizeDifferences  = @()
        FileRecordLines  = @(New-FileRecordLine -Artefact $Name -Outcome 'not collected' -Source '' -Entry '' -Size $null -BytesCopied $null -Sha256 '' -FileTimes $null -Detail 'the run stopped before this artefact, to keep the free-space reserve')
        CollectedFileCount = 0; ZipEntryCount = 0; NotLocalFileCount = 0; StopReason = ''
    }
}

# --- Output files: opening, splitting, hashing, removing ---

# Open the zip in the first output folder that works. A folder created here but
# then unusable (e.g. the sensor refuses writes) is removed again if still empty.
# The zip's file stream is opened here and handed to the zip, not left to
# ZipFile.Open, so MAIN can close it when the zip's own close fails: .NET
# Framework's ZipArchive.Dispose leaves the stream open when writing the index
# throws, and the zip then can't be deleted until the process ends (round 2.3).
# Returns @{ Zip; ZipStream; ZipPath; Folder } or $null if no folder works.
function Open-OutputZip {
    param([string[]]$CandidateFolders, [string]$ZipName)
    foreach ($candidate in $CandidateFolders) {
        if (-not (Test-Path -LiteralPath (Split-Path -Path $candidate -Parent) -ErrorAction SilentlyContinue)) { continue }
        $existed   = Test-Path -LiteralPath $candidate -ErrorAction SilentlyContinue
        $zipPath   = Join-Path $candidate $ZipName
        $zipStream = $null
        try {
            $null      = New-Item -ItemType Directory -Path $candidate -Force -ErrorAction Stop
            $zipStream = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $zip       = New-Object System.IO.Compression.ZipArchive($zipStream, [System.IO.Compression.ZipArchiveMode]::Create, $false)
            return @{ Zip = $zip; ZipStream = $zipStream; ZipPath = $zipPath; Folder = $candidate }
        } catch {
            if ($zipStream) {
                # The file was created but the zip couldn't be: remove it again.
                try { $zipStream.Dispose() } catch {}
                try { Remove-Item -LiteralPath $zipPath -Force -ErrorAction Stop } catch {}
            }
            if (-not $existed) { try { Remove-Item -LiteralPath $candidate -Force -ErrorAction Stop } catch {} }
        }
    }
    return $null
}

# Why a step of the split failed, in the words the warnings use: "<drive> is
# full" for a full disk (Test-DiskFull), otherwise the error.
function Get-SplitErrorText {
    param($ErrorRecord, [string]$DriveName)
    if (Test-DiskFull -ErrorRecord $ErrorRecord) { return "$DriveName is full" }
    return (Get-OneLineMessage -ErrorRecord $ErrorRecord)
}

# Why Bytes more can't be written on OutputDrive without going below the
# free-space reserve, or '' if they can (or the free space can't be read: the
# write itself then shows a full disk).
function Get-NoRoomReason {
    param($OutputDrive, [long]$Bytes)
    if (-not $OutputDrive) { return '' }
    $freeSpace = $null
    try { $freeSpace = $OutputDrive.AvailableFreeSpace } catch { return '' }
    if ($freeSpace - $Bytes -ge $freeSpaceReserve) { return '' }
    return ('{0} has {1} free, less than {2} above the reserve ({3})' -f $OutputDrive.Name.TrimEnd('\'), (Format-Size -Bytes $freeSpace), (Format-Size -Bytes $Bytes), (Format-Size -Bytes $freeSpaceReserve))
}

# Write the zip's bytes from VolumeStart to its current end into a new volume
# file, then check the file's length on disk. Never overwrites: a file of that
# name that already exists is a failure, and not this run's to delete. A volume
# this call created but couldn't write whole is deleted again (if that fails,
# it stays for the caller's clean-up).
# Returns @{ Error ('' when the volume is written whole); CreatedFile (whether
# this call created the file) }.
function Write-ZipVolume {
    param($ZipStream, [string]$VolumePath, [long]$VolumeStart, [string]$DriveName)
    $result = @{ Error = ''; CreatedFile = $false }
    $volumeStream = $null
    try {
        $volumeStream = [System.IO.File]::Open($VolumePath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $result.CreatedFile = $true
        $ZipStream.Position = $VolumeStart
        $ZipStream.CopyTo($volumeStream, 1MB)
        # Closing the volume writes what is still buffered: part of the write.
        $volumeStream.Dispose()
        $volumeStream = $null
        $expectedLength = $ZipStream.Length - $VolumeStart
        $lengthOnDisk   = ([System.IO.FileInfo]::new($VolumePath)).Length
        if ($lengthOnDisk -ne $expectedLength) {
            $result.Error = '{0} is {1} on disk, not {2}' -f (Split-Path -Path $VolumePath -Leaf), (Format-ByteCount -Bytes $lengthOnDisk), (Format-ByteCount -Bytes $expectedLength)
        }
    } catch {
        $result.Error = Get-SplitErrorText -ErrorRecord $_ -DriveName $DriveName
    } finally {
        if ($volumeStream) { try { $volumeStream.Dispose() } catch {} }
    }
    if ($result.Error -and $result.CreatedFile) {
        try { Remove-Item -LiteralPath $VolumePath -Force -ErrorAction Stop } catch {}   # left for the caller's clean-up
    }
    return $result
}

# Write one volume (Write-ZipVolume); if that fails, write it once more after
# $splitRetryPause seconds (the failed file was deleted). The volume file, if
# either attempt created it, is added to CreatedVolumes (Path, Start), so the
# caller knows every file this split made. Returns '' when the volume is on
# disk whole, otherwise the last attempt's error.
function Write-ZipVolumeWithRetry {
    param($ZipStream, [string]$VolumePath, [long]$VolumeStart, [string]$DriveName, [System.Collections.Generic.List[object]]$CreatedVolumes)
    $firstAttempt  = Write-ZipVolume -ZipStream $ZipStream -VolumePath $VolumePath -VolumeStart $VolumeStart -DriveName $DriveName
    $secondAttempt = $null
    if ($firstAttempt.Error) {
        Start-Sleep -Seconds $splitRetryPause
        $secondAttempt = Write-ZipVolume -ZipStream $ZipStream -VolumePath $VolumePath -VolumeStart $VolumeStart -DriveName $DriveName
    }
    if ($firstAttempt.CreatedFile -or ($secondAttempt -and $secondAttempt.CreatedFile)) {
        $CreatedVolumes.Add([pscustomobject]@{ Path = $VolumePath; Start = $VolumeStart })
    }
    if (-not $firstAttempt.Error) { return '' }
    return $secondAttempt.Error
}

# Rename what is left of the zip, its first volume, to <zip>.001; if that fails,
# try once more after $splitRetryPause seconds. Never overwrites an existing
# file. Returns '' when renamed, otherwise the error.
function Rename-ZipToFirstVolume {
    param([string]$Path, [string]$FirstVolumePath, [string]$DriveName)
    try {
        [System.IO.File]::Move($Path, $FirstVolumePath)
        return ''
    } catch {}   # tried once more below
    Start-Sleep -Seconds $splitRetryPause
    try {
        [System.IO.File]::Move($Path, $FirstVolumePath)
        return ''
    } catch {
        return (Get-SplitErrorText -ErrorRecord $_ -DriveName $DriveName)
    }
}

# Undo a split that failed part-way (see Split-ZipFile), so the zip is whole
# again: in volume order, a volume whose bytes the zip no longer holds (it was
# cut off) is appended back onto the zip's end and then deleted; one whose
# bytes the zip still holds (written but not yet cut off) is only deleted.
# Each append needs the volume's size above the free-space reserve. A volume
# that can't be deleted once its bytes are back stays (the caller reports it).
# Returns '' when the zip has its original length again, otherwise why not.
function Undo-ZipSplit {
    param([string]$Path, [long]$OriginalLength, [System.Collections.Generic.List[object]]$CreatedVolumes, $OutputDrive, [string]$DriveName)
    $zipStream = $null
    try {
        $zipStream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        foreach ($volume in ($CreatedVolumes | Sort-Object -Property Start)) {
            if (-not (Test-Path -LiteralPath $volume.Path -ErrorAction SilentlyContinue)) { continue }   # a failed volume, already deleted
            if ($volume.Start -lt $zipStream.Length) {
                # Not cut off yet: the zip still holds these bytes.
                try { Remove-Item -LiteralPath $volume.Path -Force -ErrorAction Stop } catch {}   # reported by the caller
                continue
            }
            if ($volume.Start -ne $zipStream.Length) {
                return ('the zip ends at {0}, but {1} starts at {2}' -f (Format-ByteCount -Bytes $zipStream.Length), (Split-Path -Path $volume.Path -Leaf), (Format-ByteCount -Bytes $volume.Start))
            }
            $volumeLength = ([System.IO.FileInfo]::new($volume.Path)).Length
            $noRoomReason = Get-NoRoomReason -OutputDrive $OutputDrive -Bytes $volumeLength
            if ($noRoomReason) { return $noRoomReason }
            $volumeStream = $null
            try {
                $volumeStream = [System.IO.File]::Open($volume.Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
                $zipStream.Position = $zipStream.Length
                $volumeStream.CopyTo($zipStream, 1MB)
                $zipStream.Flush()
            } finally {
                if ($volumeStream) { try { $volumeStream.Dispose() } catch {} }
            }
            try { Remove-Item -LiteralPath $volume.Path -Force -ErrorAction Stop } catch {}   # back in the zip; reported by the caller
        }
        if ($zipStream.Length -ne $OriginalLength) {
            return ('the zip is {0}, not its original {1}' -f (Format-ByteCount -Bytes $zipStream.Length), (Format-ByteCount -Bytes $OriginalLength))
        }
        # Closing the zip writes what is still buffered: part of the undo.
        $zipStream.Dispose()
        $zipStream = $null
        return ''
    } catch {
        return (Get-SplitErrorText -ErrorRecord $_ -DriveName $DriveName)
    } finally {
        if ($zipStream) { try { $zipStream.Dispose() } catch {} }
    }
}

# Split a zip larger than VolumeSize, in place, into standard split volumes
# <zip>.001, .002, ... Works from the end so the extra space needed is one
# volume, never a second copy: the last volume is written out, its length on
# disk checked, and only then cut off the zip; and so on, and what is left
# (the first volume) is renamed to .001. A volume that fails is written again
# once, as is the rename (Write-ZipVolumeWithRetry, Rename-ZipToFirstVolume).
# If that fails too, the split is undone (Undo-ZipSplit): the output is always
# every volume or the whole zip, never part of a set.
# A split starts only if one volume fits above the free-space reserve on
# OutputDrive: checked once, before the first cut, as each cut gives back the
# space the next volume takes.
# Returns @{ Outcome; Volumes; Error; CreatedVolumes }:
#   Outcome  'NotNeeded'  the zip fits in one volume; Volumes is the zip.
#            'Split'      Volumes is every volume, in order.
#            'NotStarted' the split didn't start (no room above the reserve, or
#                         the zip couldn't be opened): the zip is untouched.
#            'Undone'     the split failed and was undone: the zip is whole
#                         again (its length checked; MAIN reads it back).
#            'Failed'     it failed and couldn't be undone: neither the zip nor
#                         the volumes are usable.
#   Error           why it didn't split ('' for NotNeeded and Split).
#   CreatedVolumes  paths of the volume files this split created that are on
#                   disk: after Split, the volumes; after Undone, files it
#                   couldn't delete (not part of the output); after Failed,
#                   files to delete. Never a file this run didn't create.
function Split-ZipFile {
    param([string]$Path, [long]$VolumeSize, $OutputDrive)
    $result    = @{ Outcome = 'NotNeeded'; Volumes = @($Path); Error = ''; CreatedVolumes = @() }
    $driveName = [System.IO.Path]::GetPathRoot($Path).TrimEnd('\')
    $zipStream = $null
    try {
        $originalLength = (Get-Item -LiteralPath $Path -Force -ErrorAction Stop).Length
        if ($originalLength -le $VolumeSize) { return $result }
        $noRoomReason = Get-NoRoomReason -OutputDrive $OutputDrive -Bytes $VolumeSize
        if ($noRoomReason) {
            $result.Outcome = 'NotStarted'
            $result.Error   = $noRoomReason
            return $result
        }
        $zipStream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    } catch {
        if ($zipStream) { try { $zipStream.Dispose() } catch {} }
        $result.Outcome = 'NotStarted'
        $result.Error   = Get-SplitErrorText -ErrorRecord $_ -DriveName $driveName
        return $result
    }

    $volumeCount    = [int][math]::Ceiling($originalLength / $VolumeSize)
    $volumePaths    = @(for ($index = 1; $index -le $volumeCount; $index++) { '{0}.{1:D3}' -f $Path, $index })
    $createdVolumes = New-Object 'System.Collections.Generic.List[object]'   # Path, Start: every volume file this split created
    $splitError     = ''
    try {
        for ($index = $volumeCount; $index -ge 2; $index--) {
            $volumeStart = [long]($index - 1) * $VolumeSize
            $volumeError = Write-ZipVolumeWithRetry -ZipStream $zipStream -VolumePath $volumePaths[$index - 1] -VolumeStart $volumeStart -DriveName $driveName -CreatedVolumes $createdVolumes
            if ($volumeError) { $splitError = "volume $index of ${volumeCount}: $volumeError"; break }
            $zipStream.SetLength($volumeStart)   # the cut: only after the volume is on disk whole
        }
        if (-not $splitError) {
            # Closing the zip writes what is still buffered: part of the split.
            $zipStream.Dispose()
            $zipStream = $null
            $renameError = Rename-ZipToFirstVolume -Path $Path -FirstVolumePath $volumePaths[0] -DriveName $driveName
            if ($renameError) { $splitError = "renaming it to $(Split-Path -Path $volumePaths[0] -Leaf): $renameError" }
        }
    } catch {
        $splitError = Get-SplitErrorText -ErrorRecord $_ -DriveName $driveName
    } finally {
        if ($zipStream) { try { $zipStream.Dispose() } catch {} }
    }

    if (-not $splitError) {
        $result.Outcome        = 'Split'
        $result.Volumes        = $volumePaths
        $result.CreatedVolumes = $volumePaths
        return $result
    }
    $undoError = Undo-ZipSplit -Path $Path -OriginalLength $originalLength -CreatedVolumes $createdVolumes -OutputDrive $OutputDrive -DriveName $driveName
    $result.CreatedVolumes = @($createdVolumes | Where-Object { Test-Path -LiteralPath $_.Path -ErrorAction SilentlyContinue } | ForEach-Object { $_.Path })
    if ($undoError) {
        $result.Outcome = 'Failed'
        $result.Error   = "$splitError; undoing it failed: $undoError"
    } else {
        $result.Outcome = 'Undone'
        $result.Error   = $splitError
    }
    return $result
}

# Read the finished zip's index back, as a reader would: its entry count and,
# when the record was written, collection.csv as the last entry. Returns ''
# when both hold, otherwise what didn't. Reads the central directory only.
function Test-ZipReadBack {
    param([string]$Path, [int]$ExpectedEntryCount, [string]$LastEntryName)
    $zipReader = $null
    try {
        $zipReader = [System.IO.Compression.ZipFile]::OpenRead($Path)
        $entries   = $zipReader.Entries
        if ($entries.Count -ne $ExpectedEntryCount) { return ('{0} entries where {1} were written' -f (Format-Count -Count $entries.Count), (Format-Count -Count $ExpectedEntryCount)) }
        if ($LastEntryName -and $entries[$entries.Count - 1].FullName -ne $LastEntryName) { return "the last entry is not $LastEntryName" }
        return ''
    } catch {
        return (Get-OneLineMessage -ErrorRecord $_)
    } finally {
        if ($zipReader) { try { $zipReader.Dispose() } catch {} }
    }
}

# Delete output files that can't be offered (a zip that had to stop, and the
# volumes this run split from it) and say what became of them, for the stop
# message: 'was deleted' / 'were deleted', or which are left and unusable.
# Only files this run created are ever passed here.
function Remove-UnusableOutput {
    param([string[]]$Path)
    foreach ($filePath in $Path) { try { Remove-Item -LiteralPath $filePath -Force -ErrorAction Stop } catch {} }   # checked below
    $leftBehind = @($Path | Where-Object { Test-Path -LiteralPath $_ -ErrorAction SilentlyContinue })
    if ($Path.Count -eq 1) {
        if ($leftBehind.Count -gt 0) { return "could not be deleted and is unusable: $($leftBehind[0])" }
        return 'was deleted'
    }
    if ($leftBehind.Count -gt 0) { return ('could not all be deleted and are unusable: ' + ($leftBehind -join '; ')) }
    return 'were deleted'
}

# The SHA-256 of a file as lower-case hex (as sha256sum writes it), computed in
# this process. Throws if the file can't be read.
function Get-FileSha256 {
    param([string]$Path)
    $stream = $null
    $hasher = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        $null   = $hasher.ComputeHash($stream)
        return (ConvertTo-HexDigest -Hasher $hasher)
    } finally {
        if ($hasher) { try { $hasher.Dispose() } catch {} }
        if ($stream) { try { $stream.Dispose() } catch {} }
    }
}

# --- Console, run log and warnings ---

# Print a line and keep it in the run log beside the zip. Until the output
# folder is known the lines are buffered in $script:logLines, then written out
# in one go (Start-RunLog). A log that can't be written never affects the run;
# the first time it fails, the console says so once ($script:logWriteFailed),
# before the line itself, so the console's last line stays the run's own.
function Write-ConsoleAndLog {
    param([string]$Text = '')
    if ($script:logPath) {
        try {
            [System.IO.File]::AppendAllText($script:logPath, $Text + "`r`n", $script:utf8NoBom)
        } catch {
            if (-not $script:logWriteFailed) {
                $script:logWriteFailed = $true
                Write-Output ('The run log could not be written from here on (' + (Get-OneLineMessage -ErrorRecord $_) + ').')
            }
        }
    } else {
        $script:logLines.Add($Text)
    }
    Write-Output $Text
}

# Create the run log beside the zip (same name, .log) with everything printed
# so far; Write-ConsoleAndLog appends from then on. Returns its path, or '' if
# it couldn't be written (the console still shows everything).
function Start-RunLog {
    param([string]$ZipPath)
    $logPath = [System.IO.Path]::ChangeExtension($ZipPath, '.log')
    try {
        [System.IO.File]::WriteAllText($logPath, (($script:logLines | ForEach-Object { $_ + "`r`n" }) -join ''), $script:utf8NoBom)
        $script:logPath = $logPath
        return $logPath
    } catch { return '' }
}

# Add a warning to the Warnings section: anything the analyst should be wary
# of. Shown early (if known by then) and again with the end-of-run summary.
# Detail lines (e.g. one per unusual gap) are printed under the message.
function Add-CollectorWarning {
    param([string]$Message, [string[]]$Detail = @())
    $script:warnings.Add([pscustomobject]@{ Message = $Message; Detail = @($Detail) })
}

# Print the Warnings section: one line per warning, its detail lines indented
# under it, or "none" under the title when -ShowNone.
function Write-WarningSection {
    param([switch]$ShowNone)
    if ($script:warnings.Count -eq 0) {
        if ($ShowNone) {
            Write-ConsoleAndLog -Text 'Warnings:'
            Write-ConsoleAndLog -Text '  none'
        }
        return
    }
    Write-ConsoleAndLog -Text 'Warnings:'
    foreach ($warning in $script:warnings) {
        Write-ConsoleAndLog -Text "  - $($warning.Message)"
        foreach ($detailLine in $warning.Detail) { Write-ConsoleAndLog -Text "      $detailLine" }
    }
}

# The warning for a run that had to stop (see MAIN): where it stopped, why,
# what became of the zip, and what to do. Reasons: 'Full' (the output drive
# is full), 'BelowReserve' (its free space fell below the reserve: the zip of
# what was collected until then is kept, not offered for getfile),
# 'NotFinished' (the zip's index couldn't be written), 'NotReadable' (the
# finished zip couldn't be read back), 'SplitFailed' (splitting it failed and
# couldn't be undone). Detail is the error, for the last three; ZipFate what
# became of the zip (Remove-UnusableOutput), for all but BelowReserve.
function Get-StopMessage {
    param([string]$StoppedWhile, [string]$Reason, [string]$Detail, [string]$DriveName, [string]$ZipFate)
    switch ($Reason) {
        'Full'         { return "Collection stopped while ${StoppedWhile}: $DriveName is full. The partial zip $ZipFate. Free up space on $DriveName and run the collector again." }
        'BelowReserve' { return "Collection stopped while ${StoppedWhile}: $DriveName has less than $(Format-Size -Bytes $freeSpaceReserve) free, the reserve kept for the host. The zip holds only what was collected until then (the artefacts after it: Not collected) and is not offered for getfile. It is kept here:" }
        'NotFinished'  { return "Collection stopped while ${StoppedWhile}: the zip could not be finished ($Detail). The zip $ZipFate. Run the collector again." }
        'SplitFailed'  { return "The zip could not be split into volumes, nor the split undone ($Detail). The zip and its volumes $ZipFate. Run the collector again." }
        default        { return "Collection stopped while ${StoppedWhile}: the finished zip could not be read back ($Detail). The zip $ZipFate. Run the collector again." }
    }
}

# The end of a run that stops without offering any output: the stop's
# warning, the Warnings section and the Finished line. MAIN returns after it.
function Write-StoppedRunEnd {
    param([string]$Message)
    Add-CollectorWarning -Message $Message
    Write-ConsoleAndLog -Text ''
    Write-WarningSection
    Write-FinishedLine
}

# The OS field's text: the OS name and release, or, when the name couldn't be
# read, 'not determined', with the build where that is known.
function Get-OsFieldText {
    param($HostInfo)
    if ($HostInfo.Caption) { return (@($HostInfo.Caption, $HostInfo.Version | Where-Object { $_ }) -join ' ') }
    if ($HostInfo.Build)   { return ('not determined (build {0})' -f $HostInfo.Build) }
    return 'not determined'
}

# The header fields of the console's opening (the console frame's remote pane
# form), as 'Label : value' with the labels padded to one width: when the run
# started (UTC), the host, the OS, the run log and the drives searched. The OS
# field is always there (Get-OsFieldText: 'not determined' when its name
# couldn't be read, with a warning); the log is left out when none was
# created (a warning says so too).
function Write-RunHeader {
    param([string]$OsText, [string]$LogPath, [string]$DrivesText)
    $fields = [ordered]@{}
    $fields['Started'] = $runStart.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
    $fields['Host']    = $hostName
    $fields['OS']      = $OsText
    if ($LogPath) { $fields['Log'] = $LogPath }
    $fields['Drives']  = $DrivesText
    $labelWidth = ($fields.Keys | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    foreach ($label in $fields.Keys) {
        Write-ConsoleAndLog -Text ('{0} : {1}' -f $label.PadRight($labelWidth), $fields[$label])
    }
}

# The run's last line: when it ended, in UTC as the Started field, and how
# long the run took from $runStart.
function Write-FinishedLine {
    $runEnd = (Get-Date).ToUniversalTime()
    Write-ConsoleAndLog -Text ''
    Write-ConsoleAndLog -Text ('Finished {0}, after {1}' -f $runEnd.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture), (Format-Duration -Duration ($runEnd - $runStart)))
}

# --- The report ---

# The artefact summary: three aligned columns - name, status, and a note where
# the gap is normal for this host (the reason it's missing, or "(requires NTFS
# parser)" for locked files).
function Write-ArtefactSummary {
    param($RowResults)
    Write-ConsoleAndLog -Text ''
    Write-ConsoleAndLog -Text 'Artefact summary:'
    $nameWidth   = ($RowResults | ForEach-Object { $_.Name.Length }   | Measure-Object -Maximum).Maximum
    $statusWidth = ($RowResults | ForEach-Object { $_.Status.Length } | Measure-Object -Maximum).Maximum
    foreach ($row in $RowResults) {
        Write-ConsoleAndLog -Text ((("  {0,-" + $nameWidth + "} {1,-" + $statusWidth + "} {2}") -f $row.Name, $row.Status, $row.Note).TrimEnd())
    }
}

# The lists under the summary, only when there is something to list: folders
# that couldn't be listed (each once, with the first reason met) and copies
# whose size differs from the source's size when it was opened.
function Write-GapList {
    param($FoldersNotListed, $SizeDifferences)
    if ($FoldersNotListed.Count -gt 0) {
        Write-ConsoleAndLog -Text ''
        Write-ConsoleAndLog -Text 'Folders not listed (what they hold is counted as not accessible):'
        foreach ($folderPath in $FoldersNotListed.Keys) { Write-ConsoleAndLog -Text ("  {0}: {1}" -f $folderPath, $FoldersNotListed[$folderPath]) }
    }
    if ($SizeDifferences.Count -gt 0) {
        Write-ConsoleAndLog -Text ''
        Write-ConsoleAndLog -Text 'Copies whose size differs from the source when it was opened:'
        foreach ($difference in $SizeDifferences) {
            $openedText = if ($null -ne $difference.SizeWhenOpened) { "$(Format-ByteCount -Bytes $difference.SizeWhenOpened) when opened" } else { 'size when opened unknown' }
            $line = "  {0}: {1} copied, {2}" -f $difference.Path, (Format-ByteCount -Bytes $difference.BytesCopied), $openedText
            if ($difference.ReadError)   { $line += "; read failed, the zip entry is incomplete ($($difference.ReadError))" }
            if ($difference.CopyStopped) { $line += '; the run stopped during the copy, the zip entry is incomplete' }
            Write-ConsoleAndLog -Text $line
        }
    }
}

# The retrieval block: labels on their own line and bare commands below (the
# paths are long and wrap), so each command can be copied as-is; the SHA-256
# lines in sha256sum's format ("<hash>  <name>"), so they can be checked with
# sha256sum -c once the files are downloaded.
function Write-RetrievalCommand {
    param([string[]]$OutputFiles, $OutputHashes, [string]$LogPath)
    if ($OutputFiles.Count -gt 1) {
        Write-ConsoleAndLog -Text "Retrieve the zip, split into $($OutputFiles.Count) volumes, with:"
    } else {
        Write-ConsoleAndLog -Text 'Retrieve the zip with:'
    }
    foreach ($outputFile in $OutputFiles) { Write-ConsoleAndLog -Text "getfile `"$outputFile`"" }
    Write-ConsoleAndLog -Text $(if ($OutputFiles.Count -gt 1) { 'SHA-256 of each volume:' } else { 'SHA-256 of the zip:' })
    foreach ($outputFile in $OutputFiles) {
        $fileName = Split-Path -Path $outputFile -Leaf
        if ($OutputHashes[$outputFile]) { Write-ConsoleAndLog -Text ("{0}  {1}" -f $OutputHashes[$outputFile], $fileName) }
        else                            { Write-ConsoleAndLog -Text ("not calculated  {0}" -f $fileName) }
    }
    if ($LogPath) {
        Write-ConsoleAndLog -Text 'Retrieve the run log with:'
        Write-ConsoleAndLog -Text "getfile `"$LogPath`""
    }
}

# Follow-up getfile commands for files this script found but couldn't read and
# the Defender sensor may retrieve directly (locked files usually; not files
# whose content isn't on the disk, which aren't listed) - outcome-based: only reads that
# actually failed, in collection order (so metafiles first). Metafiles are
# listed only if flagged GetFile, with no Test-Path (PowerShell can't reliably
# see them); other files must still exist. Kept lean: each row's FollowUp scope
# only (machine-wide by default; for user hives, the users' own, not the
# built-in service accounts'), and no registry transaction logs (inferred from
# the hive). Other locked files, ESE logs included, are listed.
function Write-FollowUpCommand {
    param($UnreadableFiles)
    $followUpPaths = New-Object 'System.Collections.Generic.List[string]'
    foreach ($file in $UnreadableFiles) {
        if ($file.Literal) {
            if ($file.GetFile) { $followUpPaths.Add($file.Path) }
            continue
        }
        if ($file.Scope -ne $file.FollowUp) { continue }
        if ($file.IsTransactionLog)         { continue }
        if (Test-Path -LiteralPath $file.Path -ErrorAction SilentlyContinue) { $followUpPaths.Add($file.Path) }
    }
    if ($followUpPaths.Count -eq 0) { return }
    # Bare commands under a title, so the block can be copied and pasted as-is.
    Write-ConsoleAndLog -Text ''
    Write-ConsoleAndLog -Text 'Additional inaccessible artefacts (could not be read by PowerShell - retrieve directly in this Live Response session):'
    foreach ($followUpPath in $followUpPaths) { Write-ConsoleAndLog -Text "getfile `"$followUpPath`"" }
}

# =============================== MAIN ===============================

# Script-scope state: the run log, the console's warnings, the per-run caches
# and the zip's entry names. Everything else travels in results.
$script:utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$script:logLines  = New-Object 'System.Collections.Generic.List[string]'      # console lines until the log exists
$script:logPath   = $null                                                     # the run log, once created
$script:warnings  = New-Object 'System.Collections.Generic.List[object]'      # Warnings section, in the order found
$script:folderLinkCache     = @{}                                             # folder path -> is a link (Test-FolderPathIsLink)
$script:onDiskCasePathCache = @{}                                             # folder path -> on-disk case (Get-OnDiskCasePath)
$script:zipEntryNames = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)   # every entry written
$script:copyBuffer    = New-Object byte[] (1MB)                               # Copy-FileToZip's buffer, allocated once
$script:localDrives   = @()                                                   # Get-LocalDrive's result, read by Get-DriveRoot
$script:logWriteFailed = $false                                               # the console has said the run log can't be written

# The name and version first, before any status, so they are the first thing
# printed. The blank line above it is console-only, to set it off from Live
# Response's transcript line; the run log starts with the name. The header
# fields follow once the run log exists, so it can name the log (Write-RunHeader).
Write-Output ''
Write-ConsoleAndLog -Text "latro $CollectorVersion"
Write-ConsoleAndLog -Text ''
$hostInfo = Get-HostInfo
$osText   = Get-OsFieldText -HostInfo $hostInfo

# Fix the run order once: group, then name ignoring non-alphanumerics.
# Collection, progress numbering and the summary all follow it.
$artefacts = @($artefacts | Sort-Object -Property { $_.Group }, { $_.Name -replace '[^A-Za-z0-9]', '' })

# The drives searched, so a skipped drive can't pass for one with nothing on it.
$script:localDrives = Get-LocalDrive
$drivesText = (@($script:localDrives | ForEach-Object { '{0} ({1})' -f $_.Root, $_.Format }) -join ', ')

try {
    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
} catch {
    $zipLibraryError = Get-OneLineMessage -ErrorRecord $_
    Write-RunHeader -OsText $osText -LogPath '' -DrivesText $drivesText
    Write-ConsoleAndLog -Text ''
    Write-ConsoleAndLog -Text ('The zip library could not be loaded: ' + $zipLibraryError)
    Write-FinishedLine
    return
}

$output = Open-OutputZip -CandidateFolders $outputFolders -ZipName $zipName
if (-not $output) {
    Write-RunHeader -OsText $osText -LogPath '' -DrivesText $drivesText
    Write-ConsoleAndLog -Text ''
    Write-ConsoleAndLog -Text ('Could not create the output zip in: ' + ($outputFolders -join '; '))
    Write-FinishedLine
    return
}
$zip     = $output.Zip
$zipPath = $output.ZipPath
$logPath = Start-RunLog -ZipPath $zipPath
Write-RunHeader -OsText $osText -LogPath $logPath -DrivesText $drivesText

# The output folder's drive, for the free-space reserve. If its free space
# can't be read, the reserve can't be kept: said up front.
$outputDriveName = [System.IO.Path]::GetPathRoot($zipPath).TrimEnd('\')
$outputDrive     = $null
try {
    $outputDrive = [System.IO.DriveInfo]::new($outputDriveName)
    $null = $outputDrive.AvailableFreeSpace
} catch {
    $outputDrive = $null
}

# Warnings known before collection starts, printed now so they're seen up
# front; the section reads "none" when there are none yet.
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity.IsSystem) {
        Add-CollectorWarning -Message "Not running as SYSTEM but as $($identity.Name): files only SYSTEM can read are counted as not accessible."
    }
} catch {
    Add-CollectorWarning -Message 'The running account could not be determined.'
}
if ($null -eq $hostInfo.NtVersion -or $null -eq $hostInfo.Lineage -or ($hostInfo.Lineage -eq 'server' -and $null -eq $hostInfo.DomainController)) {
    Add-CollectorWarning -Message "Host details could not be fully determined: summary notes and missing-artefact warnings may be incomplete."
} elseif (-not $hostInfo.Caption) {
    Add-CollectorWarning -Message 'The OS name could not be determined; the build and the host type, which the summary notes use, could.'
}
if ($output.Folder -ne $outputFolders[0]) {
    Add-CollectorWarning -Message "Output written to a fallback folder ($($output.Folder)), not the Defender sensor's Temp\Collections."
}
if (-not $logPath) {
    Add-CollectorWarning -Message 'The run log could not be created beside the zip: this console is the only record of the run.'
}
if (-not $outputDrive) {
    Add-CollectorWarning -Message "The free space on $outputDriveName could not be read: the $(Format-Size -Bytes $freeSpaceReserve) reserve is not kept."
}
Write-ConsoleAndLog -Text ''
Write-WarningSection -ShowNone
Write-ConsoleAndLog -Text ''

# Collect every artefact, one progress line each, then write the per-file
# record as the zip's last entry. Each row is isolated: a failure skips only
# that row. The run stops early only to protect the output or the host
# ($stopReason, see Get-StopMessage). Stopped to keep the free-space reserve,
# the zip of what was collected is still finished, with its record, and kept
# as a partial collection; any other stop leaves no usable zip.
$rowResults        = New-Object 'System.Collections.Generic.List[object]'
$fileRecordLines   = New-Object 'System.Collections.Generic.List[string]'
$rootsNotListed    = New-Object 'System.Collections.Generic.List[object]'
$userProfilePaths  = @()
$stoppedWhile      = ''      # what the run was doing when it had to stop
$stopReason        = ''      # why, or '' if it didn't stop
$stopDetail        = ''      # the error behind a NotFinished, NotReadable or SplitFailed stop
$fileRecordWritten = $false
$zipCloseError     = $null
try {
    $userProfilePaths = @(Get-UserProfilePath -FoldersNotListed $rootsNotListed)
    # A profile root that couldn't be listed belongs to no artefact row: its
    # record row says 'User profiles'.
    $profileRootsNotListed = [ordered]@{}   # folder path -> the first reason met
    Add-FolderToNotListedTable -Table $profileRootsNotListed -Folders $rootsNotListed
    foreach ($folderPath in $profileRootsNotListed.Keys) {
        $fileRecordLines.Add((New-FileRecordLine -Artefact 'User profiles' -Outcome 'folder not listed' -Source $folderPath -Entry '' -Size $null -BytesCopied $null -Sha256 '' -FileTimes $null -Detail $profileRootsNotListed[$folderPath]))
    }
    $progressIndex    = 0
    foreach ($artefact in $artefacts) {
        $progressIndex++
        Write-ConsoleAndLog -Text ("[{0}/{1}] Collecting {2}" -f $progressIndex.ToString().PadLeft($artefacts.Count.ToString().Length, '0'), $artefacts.Count, $artefact.Name)
        $rowResult = $null
        try {
            $rowResult = Add-ArtefactToZip -Zip $zip -Artefact $artefact -UserProfilePaths $userProfilePaths -OutputDrive $outputDrive
        } catch {
            $rowResult = New-FailedArtefactResult -Name $artefact.Name -ErrorRecord $_
        }
        $rowResults.Add($rowResult)
        foreach ($line in $rowResult.FileRecordLines) { $fileRecordLines.Add($line) }
        if ($rowResult.StopReason) {
            $stoppedWhile = "collecting $($artefact.Name)"
            $stopReason   = $rowResult.StopReason
            break
        }
    }
    # Stopped to keep the reserve: the rows not reached are in the summary and
    # the record as Not collected, so the partial zip says what it lacks.
    if ($stopReason -eq 'BelowReserve') {
        foreach ($artefact in ($artefacts | Select-Object -Skip $progressIndex)) {
            $rowResult = New-NotCollectedResult -Name $artefact.Name
            $rowResults.Add($rowResult)
            foreach ($line in $rowResult.FileRecordLines) { $fileRecordLines.Add($line) }
        }
    }
    if (-not $stopReason -or $stopReason -eq 'BelowReserve') {
        try {
            Write-FileRecord -Zip $zip -EntryName $fileRecordName -Lines $fileRecordLines
            $fileRecordWritten = $true
        } catch {
            if (Test-DiskFull -ErrorRecord $_) {
                $stoppedWhile = "writing $fileRecordName"
                $stopReason   = 'Full'
            } else {
                Add-CollectorWarning -Message ("$fileRecordName could not be written into the zip (" + (Get-OneLineMessage -ErrorRecord $_) + ').')
            }
        }
    }
} finally {
    # Disposing the zip writes its index (the central directory): a failure
    # leaves an unusable zip, so it is kept and handled below, never ignored.
    # The zip then leaves its file open (see Open-OutputZip): close it, so the
    # zip can be deleted and nothing is written to it when the process ends.
    try {
        $zip.Dispose()
    } catch {
        $zipCloseError = $_
        try { $output.ZipStream.Dispose() } catch {}
    }
}
if ($zipCloseError -and $stopReason -ne 'Full') {
    $stoppedWhile = 'finishing the zip'
    $stopReason   = if (Test-DiskFull -ErrorRecord $zipCloseError) { 'Full' } else { 'NotFinished' }
    $stopDetail   = Get-OneLineMessage -ErrorRecord $zipCloseError
}
# Read the finished zip back before anything is split, hashed or kept: every
# entry written, and the record last.
$zipEntriesWritten = [int]($rowResults | Measure-Object -Property ZipEntryCount -Sum).Sum
if ($fileRecordWritten) { $zipEntriesWritten++ }
$lastEntryName = if ($fileRecordWritten) { $fileRecordName } else { '' }
if (-not $stopReason -or $stopReason -eq 'BelowReserve') {
    $readBackResult = Test-ZipReadBack -Path $zipPath -ExpectedEntryCount $zipEntriesWritten -LastEntryName $lastEntryName
    if ($readBackResult) {
        $stoppedWhile = 'checking the finished zip'
        $stopReason   = 'NotReadable'
        $stopDetail   = $readBackResult
    }
}

# Any other stop leaves no usable zip (a partial or unreadable zip is worse
# than none): delete it, tell the analyst, and stop.
if ($stopReason -and $stopReason -ne 'BelowReserve') {
    $zipFate = Remove-UnusableOutput -Path @($zipPath)
    Write-StoppedRunEnd -Message (Get-StopMessage -StoppedWhile $stoppedWhile -Reason $stopReason -Detail $stopDetail -DriveName $outputDriveName -ZipFate $zipFate)
    return
}
# A partial collection (stopped to keep the reserve) is kept whole and never
# offered for getfile: getfile lines are printed only for a complete output.
$isPartialCollection = ($stopReason -eq 'BelowReserve')

$zipBytes = $null
try { $zipBytes = (Get-Item -LiteralPath $zipPath -Force -ErrorAction Stop).Length } catch { $zipBytes = $null }

# Split a large complete zip into volumes (Split-ZipFile). The output is every
# volume or the whole zip, never part of a set: a split that fails is undone
# and the zip, read back again, is kept whole; one that can't be undone leaves
# nothing usable, so everything this run wrote goes and the analyst runs
# again - as for a full disk.
$outputFiles = @($zipPath)
if (-not $isPartialCollection) {
    $split = Split-ZipFile -Path $zipPath -VolumeSize $zipVolumeSize -OutputDrive $outputDrive
    if ($split.Outcome -eq 'Failed') {
        $outputFate = Remove-UnusableOutput -Path (@($zipPath) + @($split.CreatedVolumes))
        Write-StoppedRunEnd -Message (Get-StopMessage -Reason 'SplitFailed' -Detail $split.Error -ZipFate $outputFate)
        return
    }
    if ($split.Outcome -eq 'Undone') {
        $readBackResult = Test-ZipReadBack -Path $zipPath -ExpectedEntryCount $zipEntriesWritten -LastEntryName $lastEntryName
        if ($readBackResult) {
            $outputFate = Remove-UnusableOutput -Path (@($zipPath) + @($split.CreatedVolumes))
            Write-StoppedRunEnd -Message (Get-StopMessage -Reason 'SplitFailed' -Detail "$($split.Error); the zip put back together could not be read back: $readBackResult" -ZipFate $outputFate)
            return
        }
        Add-CollectorWarning -Message "Splitting the zip into volumes failed ($($split.Error)). The split was undone and the zip, read back again, is kept whole."
    }
    if ($split.Outcome -eq 'NotStarted') {
        Add-CollectorWarning -Message "The zip could not be split into volumes ($($split.Error)) and was kept whole."
    }
    if ($split.Outcome -eq 'Undone' -and $split.CreatedVolumes.Count -gt 0) {
        Add-CollectorWarning -Message 'Volume files left from the undone split could not be deleted; they are not part of the output:' -Detail $split.CreatedVolumes
    }
    $outputFiles = @($split.Volumes)
}
foreach ($outputFile in $outputFiles) {
    try {
        $outputSize = (Get-Item -LiteralPath $outputFile -Force -ErrorAction Stop).Length
        if ($outputSize -gt 3GB) {
            Add-CollectorWarning -Message ("{0} is {1}, over getfile's per-file limit (3 GB in Microsoft's documentation)." -f (Split-Path -Path $outputFile -Leaf), (Format-Size -Bytes $outputSize))
        }
    } catch { continue }   # a size that can't be read: the hash step below reports the file
}

# SHA-256 of every output file of a complete collection (the zip, or each
# volume), so the download can be checked against it. One that can't be
# calculated is a warning, never left out. A partial collection gets none: its
# hash couldn't show that the download holds everything.
$outputHashes = [ordered]@{}   # output file path -> lower-case SHA-256, or $null
if (-not $isPartialCollection) {
    foreach ($outputFile in $outputFiles) {
        $outputHashes[$outputFile] = $null
        try {
            $outputHashes[$outputFile] = Get-FileSha256 -Path $outputFile
        } catch {
            Add-CollectorWarning -Message ("SHA-256 of {0} could not be calculated ({1}): the download can't be checked against it." -f (Split-Path -Path $outputFile -Leaf), (Get-OneLineMessage -ErrorRecord $_))
        }
    }
}
# A partial collection: where it stopped and where the zip is. No getfile
# line and no SHA-256 for it, here or below.
if ($isPartialCollection) {
    Add-CollectorWarning -Message (Get-StopMessage -StoppedWhile $stoppedWhile -Reason 'BelowReserve' -DriveName $outputDriveName) -Detail @($zipPath)
}

# Gather the rows' findings for the warnings and the lists under the summary.
# Folders not listed: the profile roots' first, then each row's.
$foldersNotListed = [ordered]@{}   # folder path -> the first reason met
Add-FolderToNotListedTable -Table $foldersNotListed -Folders $rootsNotListed
foreach ($rowResult in $rowResults) { Add-FolderToNotListedTable -Table $foldersNotListed -Folders $rowResult.FoldersNotListed }
$sizeDifferences  = @($rowResults | ForEach-Object { $_.SizeDifferences })
$partialCopyCount = @($sizeDifferences | Where-Object { $_.ReadError }).Count
$collectedCount   = [int]($rowResults | Measure-Object -Property CollectedFileCount -Sum).Sum
if ($foldersNotListed.Count -gt 0) {
    Add-CollectorWarning -Message ("{0} folder(s) could not be listed; what they hold is counted as not accessible (named under 'Folders not listed')." -f (Format-Count -Count $foldersNotListed.Count))
}
if ($partialCopyCount -gt 0) {
    Add-CollectorWarning -Message ("{0} copy(ies) failed part-way and are incomplete in the zip (named under 'Copies whose size differs')." -f (Format-Count -Count $partialCopyCount))
}
$notLocalCount = [int]($rowResults | Measure-Object -Property NotLocalFileCount -Sum).Sum
if ($notLocalCount -gt 0) {
    Add-CollectorWarning -Message ("{0} file(s) whose content isn't on the disk (cloud-only or offline) were not read, so nothing was downloaded (Outcome 'not local' in $fileRecordName)." -f (Format-Count -Count $notLocalCount))
}
# Profiles the registry knows of outside the folders searched for profiles.
$profilesOutside = Get-ProfileOutsideSearchedRoot -UserProfilePaths $userProfilePaths
$searchedRootsText = (@($profileRoots | ForEach-Object { Join-Path $systemDrive $_ }) -join ', ')
if ($profilesOutside.Error) {
    Add-CollectorWarning -Message "The registry's ProfileList could not be read ($($profilesOutside.Error)): user profiles outside $searchedRootsText can't be ruled out."
} elseif ($profilesOutside.Paths.Count -gt 0) {
    Add-CollectorWarning -Message "User profiles named in the registry's ProfileList but outside $searchedRootsText were not searched:" -Detail $profilesOutside.Paths
}
# Unusual gaps (see Add-ArtefactToZip), one per line, in summary order.
$unusualGaps = @($rowResults | Where-Object { $_.IsUnusualGap } | ForEach-Object { "$($_.Name) ($($_.Status))" })
if ($unusualGaps.Count -gt 0) { Add-CollectorWarning -Message 'Unusual gaps:' -Detail $unusualGaps }

# --- The report: warnings, summary, the lists, the retrieval commands ---

Write-ConsoleAndLog -Text ''
Write-WarningSection -ShowNone
Write-ArtefactSummary -RowResults $rowResults
Write-GapList -FoldersNotListed $foldersNotListed -SizeDifferences $sizeDifferences

$zipSizeText = if ($null -ne $zipBytes) { " ($(Format-Mebibyte -Bytes $zipBytes) MiB compressed)" } else { '' }
Write-ConsoleAndLog -Text ''
if ($isPartialCollection) {
    Write-ConsoleAndLog -Text "Collected $(Format-Count -Count $collectedCount) files before the run stopped$zipSizeText"
} else {
    # getfile lines only for a complete output: the whole zip or every volume.
    Write-ConsoleAndLog -Text "Collected $(Format-Count -Count $collectedCount) files total$zipSizeText"
    Write-RetrievalCommand -OutputFiles $outputFiles -OutputHashes $outputHashes -LogPath $logPath
    Write-FollowUpCommand -UnreadableFiles @($rowResults | ForEach-Object { $_.UnreadableFiles })
}
Write-FinishedLine
