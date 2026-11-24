# Changelog

Notable changes to `collector.ps1`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 2.4.0 - 2026-11-24

### Added
- Browser Form Data: form entries from most Chromium-family browsers'
  `Web Data` and Firefox's `formhistory.sqlite`, counted per browser
  profile.
- Browser Saved Logins: `Login Data` (Brave, Vivaldi, Wave Browser, Prisma
  Access Browser; Chrome and Chromium in XP profiles) and Firefox's
  `logins.json`, counted per browser profile. Other Chromium-family
  browsers' `Login Data`, Chrome's and Edge's current profiles included, is
  not taken.
- Browser Web Storage: sites' local storage (`Local Storage` of Edge,
  Chrome and Chromium; Internet Explorer's `DOMStore`), counted per browser
  profile, and Internet Explorer's per `DOMStore` folder.
- Credential Manager: the users' vault credential files
  (`AppData\Local\Microsoft\Vault\*\*.vcrd`).
- INF files: `Windows\INF\*.inf`.
- NTDS: Active Directory's database, `Windows\NTDS\ntds.dit`. On a domain
  controller, which holds it open, a lock gets "(requires NTFS parser)".
- Windows Search index: `Windows.edb` with its ESE logs and checkpoint, and
  `Windows.db` and `Windows-gather.db` with their `-wal` files, counted as
  one unit whose main files are the databases.
- Browser Sessions: `Current Session`, `Current Tabs`, `Last Session` and
  `Last Tabs` in most Chromium-family browsers' profile folders (Chrome's in
  XP profiles too), and Brave's sessions for every profile (was `Default`
  only).
- Browser Preferences: `Secure Preferences` and `Sync Data`
  (`SyncData.sqlite3`, or the whole folder for some browsers) of most
  Chromium-family browsers, and Firefox's `signedinuser.json`.
- Browser Cookies: `Network\Cookies` for Edge (every channel), Chrome and
  Arc.
- Browser Extensions: Chrome's `Extension Activity` and Firefox's
  `addons.sqlite` (with its journal or WAL), beside `extensions.json`.
- Application Compatibility: `Inventory*.db` in
  `Windows\AppCompat\Programs`.
- Teams Logs: classic Teams' `old_logs_*.txt`.

### Changed
- A missing artefact is warned about where it is present by default on the
  host's Windows release and type (client or server), and explained only
  where it is absent by default there for a known OS or configuration
  reason; anywhere else it reads *Missing*, with no note and no warning.
- Warned about when missing, where they were not before: Browser Cookies,
  Browser History and INF files on every host; the NTFS metafile rows,
  which read *Missing* only when no NTFS drive is found: `$LogFile` and
  `$MFT` on every host, `$MFTMirr` on clients and from Windows Server
  2003, `$UsnJrnl:$J` on clients from Windows 7; Group Policy on servers
  and on clients before Windows Vista; Recycle Bin on servers and on
  clients up to Windows 11 23H2; Browser Bookmarks and LNK on clients from
  Windows XP; Thumbcache and Windows Search index on clients from Windows
  Vista; Browser Sessions and JumpLists on clients from Windows 7; Browser
  Web Storage on clients from Windows 7 and from Windows Server 2008;
  Defender Logs on clients from Windows Vista and from Windows Server 2016;
  Windows Timeline on Windows 10 1803 to 22H2.
- Newly explained: JumpLists, missing on a client before Windows 7, reads
  *(not on this Windows version)*.
- SRUM is also warned about on Windows Server 2019 and later.
- Prefetch is warned about on clients from Windows 8 (was every client).
- User Access Logging is warned about on Windows Server 2016 and later
  (was every server).
- SetupAPI is warned about on clients up to Windows 11 23H2 (was every
  host): no longer on Windows 11 24H2 and later or on servers.
- No longer explained, each now *Missing* with no note: Prefetch and
  OneDrive Metadata on Windows Server ("normal for Windows Server"), Group
  Policy ("not joined to on-premises AD"), SRUM on Windows 7 and Windows
  Server 2008 R2 and Restore Point Logs ("not on this Windows version"),
  File History Catalogs ("off by default").
- When the host's OS version or type can't be determined, no missing
  artefact is warned about or explained (BITS, Event Logs, both Registry
  Hives rows, Scheduled Tasks, SetupAPI and Application Compatibility were
  warned about, and Firewall Log and File History Catalogs explained,
  whatever the host).
- Browser Preferences counts a profile's `Sync Data` folder, and Browser
  Cookies its `Network` folder, as a unit of its own: a profile with files
  both there and in the profile folder counts twice.

## 2.3.0 - 2026-11-20

### Added
- `$MFTMirr` on every NTFS drive: a summary placeholder like `$MFT`'s,
  *Not accessible (requires NTFS parser)*, with no `getfile` line (the one
  for `$MFT` is printed).
- Browser Bookmarks, Browser Cookies, Browser Preferences and Browser
  Extensions (Firefox's `extensions.json`), counted per browser profile, and
  Browser Sessions, counted per file. A lock on Browser Cookies (Internet
  Explorer's cookie `index.dat` is locked from boot) or on Browser Sessions
  (a running browser's current session files) gets "(requires NTFS
  parser)".
- Server logs, found only where the role or product is installed (elsewhere
  they read *Missing*, with no note): DHCP Server Logs (the audit log), DNS
  Server Logs (the `dns` folder and the analytical log), Exchange Server Logs
  (transport logs), IIS Logs (the sites' logs and HTTP.sys's error logs) and
  SQL Server Logs (each instance's `ERRORLOG` files).
- Event Trace Logs: every file under `System32\LogFiles\WMI`, its subfolders
  (`RtBackup` among them) included.
- OneDrive ETL Traces: the `.etl` traces of Windows 8.1's built-in client.
- MSRT Log: `Windows\debug\mrt.log`.
- Shadow Copy Catalog: the shadow copy catalogue at each NTFS drive's root,
  not the shadow copies' stores. Even SYSTEM is denied it, so it reads
  *Not accessible (requires NTFS parser)*; it gets no `getfile` line
  (Live Response's `getfile` reports it as empty).
- Thumbcache: Explorer's `thumbcache_idx.db`, not the cached thumbnails.
- Registry Hives (system): the `COMPONENTS` and `ELAM` hives and AppLocker's
  `AppCache.dat`.
- Registry Hives (user): `UsrClass.dat` in XP profiles.
- Scheduled Tasks: `Windows\Tasks\SchedLgU.txt`.
- OneDrive Metadata: `SyncDiagnostics.log`, from the current client's
  `logs\Personal` folder and from Windows 8.1's built-in client.
- Browser History: `Shortcuts` for the Chromium-family browsers except
  Vivaldi and Opera, Chrome's `Archived History`, UC Browser, Safari's
  `Downloads.plist`, and Firefox's `history.dat` in XP profiles.

### Changed
- Named latro: the console's first line reads `latro 2.3.0` (was
  `Live Response collector v2.2.1`), and the help's synopsis and link name it
  (`https://github.com/rbqbjyur/latro`). The script is still `collector.ps1`.
- The opening lines are `Label : value` fields: `Started`, `Host`, `OS`,
  `Log` (the run log's path, new; left out when no log was created) and
  `Drives` (were `Host <name>, started <UTC>`, `OS ...` and `Drives ...`).
  The two stops before the zip exists (the zip library can't be loaded, the
  output zip can't be created) print the fields without `Log`, then a blank
  line and the error.
- The Warnings section at the start is always printed; when empty, it and
  the closing one read `none` on the line under `Warnings:` (was
  `Warnings: none` at the end, nothing at the start).
- The last line reads `Finished <UTC>, after <h>:<mm>:<ss>` (was
  `Finished <UTC>`).
- Counts have a comma as the thousands separator (e.g. `1,204 collected`).
- Sizes are in IEC binary units with two decimals and a comma as the
  thousands separator. The total line reads `(<n> MiB compressed)` (was
  `MB`), e.g. `(1,234.56 MiB compressed)`; the free-space reserve reads
  `1.00 GiB` (was `1 GiB`); the split's no-room message (`<drive> has <free>
  free, less than <needed> above the reserve (<reserve>)`) gives all three
  sizes in the largest unit each reaches (were GiB, e.g. `0.5 GiB`).
- The warning for a file over getfile's limit gives its size in IEC units
  and reads "over getfile's per-file limit (3 GB in Microsoft's
  documentation)" (was "N GB, over getfile's 3 GB per-file limit").
- Byte counts in the split and undo error messages and in the "Copies whose
  size differs" list are printed in full with thousands separators
  (e.g. `412,000,000 bytes`).
- Internet Explorer's download history is taken from
  `AppData\Roaming\Microsoft\Windows\IEDownloadHistory\index.dat` (was
  `AppData\Local\Microsoft\Windows\IEDownloadHistory\**\index.dat`).
- BITS: a lock on `qmgr.db`, held by the BITS service while it runs, is
  expected: "(requires NTFS parser)", not an unusual gap.
- A missing Windows Timeline is no longer explained, on Windows 11 ("not on
  this Windows version") or on Windows Server ("normal for Windows Server"),
  nor a missing SRUM on Windows Server: each reads *Missing*, with no note.

### Fixed
- The size in the warning for a file over getfile's limit took the host's
  decimal separator, the start and finish times its time separator, and
  the zip's name its calendar (another year under a non-Gregorian one);
  every number and time on the console and in the run log, and the zip's
  name, is now formatted in the invariant culture.
- An OS name that couldn't be read, with the build known, left the `OS`
  line out of the opening with no warning; the `OS` field now reads
  `not determined` (with the build, where known) and a warning says so. A
  missing build was read as build 0 and skipped the "Host details could
  not be fully determined" warning.

## 2.2.1 - 2026-10-27

### Changed
- The size on the "Collected N files" line is labelled as the zip's
  (`MB compressed`).

## 2.2.0 - 2026-10-27

### Added
- A warning naming user profiles that the registry's ProfileList places
  outside the folders searched for profiles (they are not searched), or saying
  that ProfileList couldn't be read.
- `not collected` rows in `collection.csv`, and the *Not collected* status in
  the summary, for artefacts a run that stopped to keep the reserve didn't
  reach.

### Changed
- A run that stops to keep the free-space reserve keeps the zip of what it
  collected: finished with `collection.csv`, read back and named in the
  Warnings as a partial collection, with no `getfile` line and no SHA-256 (it
  was deleted). The file being copied is `incomplete`; the artefact it stopped in
  is noted "(the run stopped here)".
- `getfile` lines are printed only for a complete output: the whole zip or
  every volume.
- Splitting: each volume's length on disk is checked before it is cut off the
  zip; a volume or the final rename that fails is tried once more after
  2 seconds; if that fails, the split is undone and the zip, read back again,
  is kept whole. Only a split that can't be undone deletes the output (it
  always did once the zip had been cut).
- The "(requires NTFS parser)" note applies only when at least one file
  failed as the expected lock does (a sharing violation; access denied for
  the NTFS metafiles) and every file that couldn't be opened did; any other
  failure is an unusual gap.
- An artefact whose collection fails as a whole reads *Failed* in the summary
  (was *Missing*).
- Error text in the warnings, the lists under the summary and
  `collection.csv`'s Detail is the underlying error's own message, without
  PowerShell's `Exception calling "..." with "N" argument(s):` wrapper.

### Fixed
- A failed split deleted every `<zip>.NNN` file beside the zip, including any
  this run hadn't created; it now deletes only its own.
- A full disk while splitting was reported as the system drive being full; it
  names the output drive.

## 2.1.0 - 2026-10-24

### Added
- The closed zip is read back (entry count, `collection.csv` last) before it
  is split, hashed or offered for `getfile`.
- A free-space reserve (1 GiB, CONFIG): collection stops, as for a full disk,
  before the output drive would go below it; a split starts only if a volume
  fits above it.
- Files whose content isn't on the disk (OneDrive cloud-only, offline) are not
  read, so nothing is downloaded: `not local` in `collection.csv`, counted as
  not accessible, and warned about.
- `artefact failed` row in `collection.csv` for an artefact whose collection
  fails as a whole.
- A closing `Finished <UTC>` line in the console and run log.
- Warnings when the run log can't be created or the output drive's free space
  can't be read; one console line when the run log stops being writable.

### Changed
- The `getfile` follow-up heading reads "could not be read by PowerShell"
  (was "locked from PowerShell").
- A drive whose file system can't be read shows as `unknown` (was assumed
  NTFS).

### Fixed
- A failure while closing a zip entry or the zip itself (e.g. disk full while
  writing the index) was ignored: the entry was recorded as collected, and a
  zip that couldn't be opened was hashed and offered for `getfile`. The entry
  is now `incomplete`; a zip that can't be finished is deleted, with a
  warning, as for a full disk.
- A profile root that exists but can't be read was skipped silently; it is
  now a folder not listed.
- On a full disk the partial zip couldn't be deleted: its file stayed open
  until the run ended, kept the drive full, and the write attempted at exit
  started Windows Error Reporting (`wermgr.exe`, a report in the WER queue).
  The file is now closed and the zip deleted.

## 2.0.0 - 2026-10-22

The zip's layout changes: `collection.csv` joins the drive folders at its
root, and empty files and file symbolic links are no longer in it.

### Added
- `collection.csv` at the zip's root: one row per file collected or found but
  not readable - artefact, outcome, source path, zip entry, size, bytes
  copied, SHA-256 of the bytes written, the file's own created, modified and
  accessed times (UTC), and the error for a failure - and one per folder that
  couldn't be listed, with the reason.

### Changed
- Empty (0-byte) files are left out of the zip, the record and every count.
- File symbolic links are not followed, and are left out of the zip, the
  record and every count.
- The printed `getfile` commands leave out only registry transaction logs
  (`.LOG1`/`.LOG2`); other locked files, ESE logs included, are listed.
- "Unusual gaps" lists one artefact per line.
- Code restructured for readability: full-word names, results returned
  instead of script state, no script-wide error suppression. No change to
  what is collected beyond the lines above.

## 1.5.0 - 2026-10-22

### Added
- The SHA-256 of the zip, or of each volume, is printed under its `getfile`
  lines and kept in the run log, in `sha256sum` format.
- Copies whose size differs from the source's size when opened are named under
  the summary, with the bytes copied.

### Fixed
- A folder that exists but can't be listed was counted as Missing; it now
  counts as Not accessible, is warned about and is named under the summary.
- A copy that failed part-way stayed in the zip, incomplete, with nothing to
  say which entry; it is now warned about and named under the summary.
- A file whose name ends with a dot or a space was opened as its namesake
  without them (e.g. `report.` as `report`), so its entry held another file's
  content; every file is now opened through `\\?\`.
- Files in a folder whose name ends with a dot or a space (e.g. `dir.`) were
  silently left out: PowerShell listed the folder without them instead. Such
  folders are now listed through `\\?\`.
- Windows' compatibility links that deny listing (`Default User`, `All Users`,
  `Documents and Settings`) weren't recognised as links, so files under
  `Default User` were collected twice; they are no longer followed.

## 1.4.0 - 2026-10-13

### Added
- A zip over 1 GiB is split in place into standard split volumes
  (`.zip.001`, `.002`, ...), each retrieved with its own `getfile`.

### Removed
- Delete-at-reboot of the output folder. The collector starts no child
  processes (`csc.exe` is no longer run).

## 1.3.0 - 2026-10-13

### Added
- Recycle Bin and NTFS metafiles are collected (or listed for `getfile`) from
  every local drive - fixed or removable, NTFS, FAT or exFAT - not just the
  system drive. Drives that can't be read are skipped.
- A "Drives" line lists the drives searched and their file systems.

### Changed
- Zip entry paths keep each folder name's on-disk case (e.g. `$RECYCLE.BIN`),
  not the case written in the artefact table.

## 1.2.1 - 2026-10-13

### Changed
- Warnings list a missing artefact only if it should exist on the host (e.g.
  event logs, or Prefetch on a workstation), not artefacts that may simply be
  absent, such as PowerShell transcripts.

## 1.2.0 - 2026-10-13

### Added
- Warnings section, shown at the start if known by then and again before the
  summary: unusual gaps, not running as SYSTEM, fallback output folder, zip
  over the 3 GB `getfile` limit, cleanup not queued, full disk.
- Run log: the console output is also written to `<HOSTNAME>_<timestamp>Z.log`
  beside the zip, with a `getfile` command for it at the end.

### Changed
- Summary notes now say why a gap is normal for the host, e.g. "(normal for
  Windows Server)", "(not on this Windows version)", and "(requires NTFS
  parser)" for normally locked files, instead of "(not unusual)".
- "Recycle Bin ($I, INFO2)" renamed "Recycle Bin".
- The `getfile` list now includes logged-on users' locked hives (`NTUSER.DAT`,
  `UsrClass.dat`) instead of the built-in service accounts' hives.

### Fixed
- No `getfile` command is printed for `$LogFile`: Live Response rejects it as
  an empty file.

## 1.1.0 - 2026-10-12

### Added
- OS name and release printed after the banner.
- Summary column marking Missing or Not accessible statuses that are normal for
  the host (e.g. Prefetch on servers, legacy-only artefacts, live hives) as
  `(not unusual)`, so unusual gaps stand out.

### Changed
- Amcache, AppCompat PCA and Syscache merged into one "Application
  Compatibility" line (Syscache and RecentFileCache are Amcache's pre-Windows 8
  predecessors).
- The zip is now written under the Defender for Endpoint
  sensor's Temp folder,
  `ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Temp\Collections\`,
  falling back to a `LiveResponseCollector` folder in `Windows\SystemTemp` or
  the account's temp folder, instead of `%SystemDrive%\LiveResponse\`. The
  printed `getfile` path changes accordingly.

## 1.0.1 - 2026-10-12

### Fixed
- A full system drive now stops collection, deletes the partial (unusable) zip
  and says to free space and run again, instead of reporting every remaining
  file as not accessible.
- Recursive searches no longer follow junctions or symbolic links.
- Browser History counts a profile as collected only if its main database was
  read, not just its journal or logs.
- A policy transcription folder at the system drive's root is skipped instead
  of searching the whole drive.
- Repeat runs no longer queue already-queued files for deletion again;
  `%SystemDrive%` has a fallback; paths of 260+ characters can be opened.

### Changed
- Script header is now PowerShell comment-based help (`Get-Help`).

## 1.0.0 - 2026-10-12

### Added
- Legacy forms of existing artefacts, listed after their current form: `.evt`,
  `setupapi.log`, `.job` and `SchedLgU.txt`, Recycle Bin `INFO2`, XP profile
  paths (`Documents and Settings`), XP restore-point hives and shortcuts, older
  Defender logs, legacy browser history (Firefox `downloads.sqlite`, Opera 12,
  Safari for Windows), and the previous install in `Windows.old`.
- Amcache line (with `RecentFileCache.bcf`), Syscache, Windows Timeline, XP
  restore-point logs, SCCM client logs, OneDrive metadata (settings and logs),
  Group Policy (local and cached domain GPOs), User Access Logging (SUM), Teams
  logs, and IE / legacy Edge history (WebCache, `index.dat`).

### Changed
- Amcache moved out of "Registry Hives (system)" into its own line; "EVTX"
  renamed "Event Logs"; "Recycle Bin ($I)" renamed "Recycle Bin ($I, INFO2)".
- Summary name column sized to the longest artefact name.
- Junctions and symbolic links are skipped by link type, so other reparse
  points (e.g. OneDrive cloud folders) are no longer skipped.

## 0.16.1 - 2026-10-12

### Changed
- Summary line "File History" renamed "File History Catalogs".

## 0.16.0 - 2026-10-12

### Added
- Defender logs (Support logs, detection history), AppCompat PCA, BITS
  database and .NET CLR usage logs.
- Service-account artefacts: `DEFAULT`, systemprofile, LocalService and
  NetworkService hives; SYSTEM's PowerShell history, scheduled jobs, CLR logs
  and Chrome history.
- History of other maintained browsers: Edge and Chrome Beta/Dev/Canary,
  Chromium, Brave, Vivaldi, Opera, Yandex, Arc, Coc Coc, QQ, 360, Wave,
  Prisma Access, Supermium.
- RegBack hives; CustomDestinations JumpLists; Office recent, desktop and Start
  Menu shortcuts; PowerShell scheduled jobs; `SysWOW64\Tasks`; SRUM ESE logs;
  more transcript locations.

### Changed
- EVTX limited to `*.evtx`; firewall logs include rotated `pfirewall.log.old`;
  PowerShell history covers every PSReadLine host (`*_history.txt`).
- User profiles are again the folders under `<SystemDrive>\Users`; the 0.15.0
  ProfilesDirectory lookup is removed.

## 0.15.0 - 2026-10-10

### Added
- PowerShell transcripts from OneDrive-redirected Documents (Known Folder
  Move), from dated subfolders (policy transcription), and from a Group Policy
  transcription `OutputDirectory` on a local drive (Windows PowerShell and
  PowerShell 7).

### Changed
- User profiles are enumerated under the ProfileList `ProfilesDirectory`
  (falls back to `<SystemDrive>\Users`).

## 0.14.0 - 2026-10-10

### Changed
- Artefacts are defined in one table; collection and progress lines now follow
  the summary order.
- Each artefact location is handled independently, so a failure skips only
  that location.
- Zip entry timestamps are written in UTC (previously host local time).
- The host name and UTC start time are printed after the version banner.
- Changelog moved from the script header to this file.

## 0.13.5 - 2026-10-10

### Fixed
- Delete-on-reboot cleanup never took effect: `MoveFileEx` now receives a true
  null destination.

### Changed
- Licence changed from MIT to 0BSD; SPDX identifier added.

## 0.13.4 - 2026-10-09

First version in this repository.

### Changed
- `getfile` follow-ups for `$MFT` and `$LogFile` are printed only if the read
  actually failed.

## 0.1.0 - 0.13.3 (before the repository, undated)

- **0.13.3** - Changed: user profiles are the folders under `\Users`; service
  profiles under `\Windows` are excluded.
- **0.13.2** - Added: `getfile` follow-ups for locked machine-wide files.
  Changed: zip size shown on the "Collected" line.
- **0.13.1** - Changed: all paths anchored to the system drive.
- **0.13.0** - Changed: paths resolved from the environment (non-`C:`
  installs); UTC timestamp in the zip name; approved-verb function names.
- **0.12.2** - Changed: structural tidy, no behaviour change.
- **0.12.1** - Added: per-artefact progress line.
- **0.12.0** - Added: registry transaction logs (`.LOG1`/`.LOG2`) for every
  hive.
- **0.11.0** - Added: File History catalogs.
- **0.10.0** - Added: SetupAPI device-install logs, Windows Firewall log.
- **0.9.0** - Added: `SECURITY` hive, Scheduled Tasks, Startup folders, WER
  report metadata, `$LogFile`.
- **0.8.2** - Changed: end of run prints only runnable commands.
- **0.8.1** - Changed: summary in a fixed three-group order; files streamed
  into the zip in one pass.
- **0.8.0** - Added: Chrome and Firefox history, counted per browser profile.
- **0.7.0** - Added: `$MFT` and `$UsnJrnl:$J` as summary placeholders, with a
  `getfile` command for `$MFT`.
- **0.6.0** - Added: system and user registry hives; zip size.
- **0.5.1** - Added: per-artefact status summary.
- **0.5.0** - Added: EVTX, Prefetch, SRUM, PowerShell history and transcripts.
- **0.4.0** - Added: delete-on-reboot cleanup. Changed: output folder renamed
  to `C:\LiveResponse`.
- **0.3.0** - Changed: zip compression set to Fastest.
- **0.2.0** - Changed: one fixed, hidden output folder instead of one per run.
- **0.1.0** - Initial collector: Recycle Bin `$I`, LNK, JumpLists, Edge
  history.
