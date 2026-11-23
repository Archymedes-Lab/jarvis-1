
# jarvis-intrusion-payload (first line on purpose: see section 6)
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}
# Files Windows Security refused to let this payload open on an earlier pass, as
# "path|size|lastwrite ticks" (stdin, JSON list). They are listed, not opened again:
# each refused open is logged by Windows as a blocked action.
$refusedBefore = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
try { if ($jarvisReq) { foreach ($k in @(($jarvisReq | ConvertFrom-Json).refused)) { [void]$refusedBefore.Add([string]$k) } } } catch { }

# --- 1. ClickFix: everything ever typed into the Win+R Run dialog ----------
$mru = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
$o.runmru = @()
if (Test-Path $mru) {
  $p = Get-ItemProperty $mru
  $o.runmru = @($p.PSObject.Properties |
    Where-Object { $_.Name -match '^[a-z]$' } |
    ForEach-Object { [pscustomobject]@{ slot=$_.Name; cmd=[string]$_.Value } })
  $o.runmruOrder = [string]$p.MRUList
}

# --- 2. PowerShell console history (what was actually typed) --------------
$hist = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
$o.psHistory = @()
if (Test-Path $hist) {
  $o.psHistoryPath = $hist
  # [string[]] is load-bearing: Get-Content attaches PSPath/PSDrive/PSProvider
  # note properties to every line it returns, and ConvertTo-Json -Depth serialises
  # that entire provider graph once per line. Left as-is this one field produced
  # ~700MB of JSON and took three minutes.
  $o.psHistory = [string[]]@(Get-Content $hist -Tail 300 |
                             Where-Object { $_.Trim() })
}

# --- 3. Defender's own detection history ----------------------------------
$o.threats = @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending |
  Select-Object -First 40 | ForEach-Object {
    $t = $_
    [pscustomobject]@{
      time     = if ($t.InitialDetectionTime) { $t.InitialDetectionTime.ToString('o') } else { '' }
      action   = [string]$t.ActionSuccess
      status   = [string]$t.ThreatStatusID
      resources= [string]($t.Resources -join ' | ')
      id       = [string]$t.ThreatID
    } })
# IsActive and "does the file still exist" are the two facts that decide whether
# a Get-MpThreat entry is a live problem or a historical record. Defender keeps
# naming a threat long after the file behind it is gone, so without these every
# past detection reads as an ongoing compromise forever.
# Get-MpThreat often names no resource at all; the detection records do. Join them by threat id so a
# file Defender flagged and that is still on disk is reported as such, not as "names no file".
$detRes = @{}
foreach ($d in @(Get-MpThreatDetection)) {
  $k = [string]$d.ThreatID
  if (-not $detRes.ContainsKey($k)) { $detRes[$k] = New-Object System.Collections.ArrayList }
  foreach ($r in @($d.Resources)) { if ($r -and -not $detRes[$k].Contains($r)) { [void]$detRes[$k].Add($r) } }
}
$o.threatNames = @(Get-MpThreat | Select-Object -First 40 |
  ForEach-Object {
    $res = @($_.Resources | Where-Object { $_ })
    if (-not $res.Count -and $detRes.ContainsKey([string]$_.ThreatID)) { $res = @($detRes[[string]$_.ThreatID]) }
    $files = @($res | Where-Object { $_ -like 'file:_*' } |
                      ForEach-Object { $_.Substring(6) })
    [pscustomobject]@{
      name      = [string]$_.ThreatName
      id        = [string]$_.ThreatID
      executed  = [bool]$_.DidThreatExecute
      severity  = [string]$_.SeverityID
      resources = [string]($res -join ' | ')
      active    = [bool]$_.IsActive
      # $null when the threat names no file at all (registry/memory detections),
      # which must not be mistaken for "the file is gone".
      onDisk    = if ($files.Count -eq 0) { $null }
                  else { [bool](@($files | Where-Object { Test-Path -LiteralPath $_ }).Count) }
    } })

# --- 4. Browser extensions -------------------------------------------------
$ext = New-Object System.Collections.ArrayList
$chromiumRoots = @(
  @{n='Chrome'; p="$env:LOCALAPPDATA\Google\Chrome\User Data"},
  @{n='Edge';   p="$env:LOCALAPPDATA\Microsoft\Edge\User Data"},
  @{n='Brave';  p="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"},
  @{n='Opera';  p="$env:APPDATA\Opera Software\Opera Stable"}
)
foreach ($b in $chromiumRoots) {
  if (-not (Test-Path $b.p)) { continue }
  Get-ChildItem "$($b.p)\*\Extensions\*\*\manifest.json" -ErrorAction SilentlyContinue |
    ForEach-Object {
      # -Encoding UTF8 matters: PowerShell 5.1 reads as ANSI by default and
      # mangles any non-ASCII character in an extension's name.
      $m = Get-Content $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
      [void]$ext.Add([pscustomobject]@{
        browser = $b.n
        id      = $_.Directory.Parent.Name
        name    = [string]$m.name
        version = [string]$m.version
        perms   = [string](@($m.permissions) + @($m.host_permissions) -join ',')
        updateUrl = [string]$m.update_url
        location  = 'profile'
        installed = $_.LastWriteTime.ToString('o')
      }) }
}
# Firefox keeps its inventory in one JSON file per profile. Its `location` field
# separates add-ons *you* installed ("app-profile") from the ones Mozilla ships
# with the browser ("app-builtin", "app-system-defaults") -- the built-ins have
# no update URL by design, so without this they all look sideloaded.
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles\*\extensions.json" -ErrorAction SilentlyContinue |
  ForEach-Object {
    $j = Get-Content $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    $j.addons | Where-Object { $_.type -eq 'extension' -and $_.active } | ForEach-Object {
      [void]$ext.Add([pscustomobject]@{
        browser='Firefox'; id=[string]$_.id
        name=[string]$_.defaultLocale.name; version=[string]$_.version
        perms=[string](@($_.userPermissions.permissions) + @($_.userPermissions.origins) -join ',')
        updateUrl=[string]$_.updateURL
        location=[string]$_.location
        signed=[string]$_.signedState
        installed=if($_.installDate){([DateTimeOffset]::FromUnixTimeMilliseconds($_.installDate)).ToString('o')}else{''}
      }) } }
$o.extensions = @($ext)

# --- 5. Recently written executables in staging directories ---------------
$cut = (Get-Date).AddDays(-14)
# Deduplicate identical roots, but keep package trees visible: native add-ons and
# poisoned package scripts must not disappear behind a performance optimization.
$stageRoots = @($env:TEMP, "$env:USERPROFILE\Downloads", $env:APPDATA,
                "$env:LOCALAPPDATA\Temp", $env:PUBLIC) |
  Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') } | Select-Object -Unique
$o.recentExe = @(Get-ChildItem -File -ErrorAction SilentlyContinue -Path $stageRoots `
    -Recurse -Depth 2 -Include *.exe,*.dll,*.node,*.scr,*.ps1,*.bat,*.cmd,*.vbs,*.hta,*.js,*.mjs,*.cjs,*.jar |
  Where-Object { $_.LastWriteTime -gt $cut -and
                 $_.FullName -notmatch '\\(Mozilla|Firefox|Google\\Chrome|Microsoft\\Edge)\\' -and
                 $_.Name -notmatch '^(prefs|user|handlers|search|extension-preferences)\.js$' } |
  Sort-Object LastWriteTime -Descending | Select-Object -First 250 |
  ForEach-Object {
    $key = '{0}|{1}|{2}' -f $_.FullName, $_.Length, $_.LastWriteTimeUtc.Ticks
    if ($refusedBefore.Contains($key)) {
      [pscustomobject]@{ path=$_.FullName; size=$_.Length; written=$_.LastWriteTime.ToString('o')
                         sig='BlockedByWindows'; signer=''; sha256=''; key=$key }
      return
    }
    $s = $null; $h = $null; $denied = $false; $fs = $null
    # Open once, explicitly: a refusal by Windows Security arrives as an access error
    # (wrapped by PowerShell), and the hash is taken from the same open handle.
    try { $fs = [IO.File]::Open($_.FullName, 'Open', 'Read', 'ReadWrite') }
    catch { $ex = $_.Exception; while ($ex) { if ($ex -is [UnauthorizedAccessException]) { $denied = $true; break }; $ex = $ex.InnerException } }
    if ($fs) { try { $h = Get-FileHash -Algorithm SHA256 -InputStream $fs } finally { $fs.Dispose() } }
    if (-not $denied) { $s = Get-AuthenticodeSignature -LiteralPath $_.FullName }
    [pscustomobject]@{ path=$_.FullName; size=$_.Length
                       written=$_.LastWriteTime.ToString('o')
                       sig=if($denied){'BlockedByWindows'}else{[string]$s.Status}
                       signer=if($s -and $s.SignerCertificate){[string]$s.SignerCertificate.Subject}else{''}
                       sha256=[string]$h.Hash; key=$key } })

# --- 6. Browser credential stores, and what else references them -------
# Infostealers usually copy the store before decrypting it (the browser holds a
# lock on the live file), and the copy step names the file on a command line:
# esentutl /y "...\Login Data", robocopy, a script given the profile path.
# This sees command lines of running processes only; a program that opens the
# files through the API without naming them on its command line is not seen.
#
# The marker on this script's first line: its own command line names the store
# files too, so a process carrying the marker is this collector, not a thief. It
# sits first so it survives the 400-character command-line truncation below.
$o.credAccess = @()
try {
  $stores = Get-ChildItem -File -ErrorAction SilentlyContinue -Path @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\*\Login Data",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\*\Login Data",
    "$env:APPDATA\Mozilla\Firefox\Profiles\*\logins.json") |
    ForEach-Object { [pscustomobject]@{ path=$_.FullName
                                        written=$_.LastWriteTime.ToString('o') } }
  $o.credAccess = @($stores)
} catch {}
$o.credReaders = @()
$o.credReadersOk = $false
try {
  $storeRx = '(?i)[\\/](Login Data|Cookies|Web Data|Local State|key4\.db|logins\.json|cookies\.sqlite|places\.sqlite)(["''\s]|$)'
  $o.credReaders = @(Get-CimInstance Win32_Process -ErrorAction Stop |
    Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -and
                   $_.CommandLine -match $storeRx -and
                   $_.CommandLine -notmatch 'jarvis-intrusion-payload' } |
    ForEach-Object { [pscustomobject]@{
      pid  = [int]$_.ProcessId
      name = [string]$_.Name
      exe  = [string]$_.ExecutablePath
      cmd  = [string]$_.CommandLine.Substring(0, [Math]::Min(400, $_.CommandLine.Length)) } })
  $o.credReadersOk = $true
} catch {}

# --- 7. BITS transfer jobs (T1197) --------------------------------------
# A queued BITS job survives reboots and logoffs and downloads with the
# System service's network identity, which is why droppers and C2 use it.
# -AllUsers needs elevation. Unelevated it throws Access Denied, and the
# original code caught that and left the list empty -- so an unelevated daemon
# reported no BITS jobs at all rather than reporting that it could not see them,
# which is the exact "a clean report and no report look identical" failure this
# codebase treats as worse than a finding. Fall back to this user's own jobs and
# say which view was obtained.
$o.bits = @()
$o.bitsScope = 'none'
function Get-BitsJobs($all) {
  $jobs = if ($all) { Get-BitsTransfer -AllUsers -ErrorAction Stop }
          else { Get-BitsTransfer -ErrorAction Stop }
  @($jobs | ForEach-Object {
    [pscustomobject]@{
      name  = [string]$_.DisplayName
      state = [string]$_.JobState
      owner = [string]$_.OwnerAccount
      url   = [string](@($_.FileList | ForEach-Object { $_.RemoteName }) -join ' ; ')
      local = [string](@($_.FileList | ForEach-Object { $_.LocalName }) -join ' ; ')
    } })
}
try {
  $o.bits = Get-BitsJobs $true
  $o.bitsScope = 'all'
} catch {
  try {
    $o.bits = Get-BitsJobs $false
    $o.bitsScope = 'user'
  } catch { $o.bitsScope = 'none' }
}

$json = [pscustomobject]$o | ConvertTo-Json -Depth 6 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
