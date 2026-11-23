
$ErrorActionPreference = 'SilentlyContinue'
$logicalCpus = [int](Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors

$procs = Get-CimInstance Win32_Process | ForEach-Object {
    [pscustomobject]@{
        pid  = $_.ProcessId
        ppid = $_.ParentProcessId
        name = $_.Name
        exe  = $_.ExecutablePath
        cmd  = $_.CommandLine
        # PID alone is not an execution identity. Creation time lets the
        # temporal reconciler distinguish PID reuse and match this live
        # instance to Sysmon's ProcessGuid-backed start event.
        started = if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('o') } else { $null }
        rss  = [int64]$_.WorkingSetSize
        cpu  = ([double]$_.KernelModeTime + [double]$_.UserModeTime) / 10000000
    }
}
$processObservedAt = [DateTime]::UtcNow.ToString('o')

$conns = @()
if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $conns = Get-NetTCPConnection | Where-Object { $_.State -ne 'Bound' } | ForEach-Object {
        [pscustomobject]@{
            pid    = $_.OwningProcess
            proto  = 'tcp'
            lip    = $_.LocalAddress
            lport  = $_.LocalPort
            rip    = $_.RemoteAddress
            rport  = $_.RemotePort
            state  = [string]$_.State
        }
    }
}

$payload = [pscustomobject]@{ procs = @($procs); process_observed_at = $processObservedAt; conns = @($conns); logical_cpus = $logicalCpus } | ConvertTo-Json -Depth 4 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
