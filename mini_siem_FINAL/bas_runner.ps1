<#
.SYNOPSIS
    Sentinel BAS runner - drives Invoke-AtomicRedTeam against this machine
    and reports every test run to the SIEM's Detection Validation Engine,
    so coverage gets scored automatically instead of eyeballed.

.DESCRIPTION
    Run this ON the Windows VM that has Invoke-AtomicRedTeam installed -
    NOT on the main SIEM machine. For each technique in $TestPlan below,
    it:
      1. POSTs /api/bas/test-run/start (marks a run as beginning, right
         before the attack actually happens - this timestamp is what the
         SIEM measures detection latency against)
      2. Runs Invoke-AtomicTest for that technique
      3. POSTs /api/bas/test-run/<id>/end (triggers the first scoring
         pass - fast detections show up as "Detected" immediately)
      4. Optionally runs the matching -Cleanup step, so the lab doesn't
         accumulate leftover dumped files, created users, etc. across runs

    Log into the SIEM's /bas page afterward, or click "Rescore Pending"
    a few minutes later, to catch anything that was Delayed rather than
    immediate, and to finalize genuine Missed verdicts once their grace
    window has actually passed.

.NOTES
    HONESTY NOTE: this script was written carefully against documented
    Invoke-AtomicRedTeam behavior, but has not been run end-to-end on a
    real Windows box with the atomics library installed - there's no
    Windows environment available to test it directly. The SIEM-side
    scoring logic it reports into (start/end/score) WAS tested directly
    and thoroughly. If something here doesn't match your actual
    Invoke-AtomicRedTeam version's exact behavior, the fix is almost
    certainly local to the Invoke-AtomicTest call itself, not the
    reporting logic around it.

.PREREQUISITES
    - Invoke-AtomicRedTeam module installed, with the atomics library
      present (see https://github.com/redcanaryco/invoke-atomicredteam
      for setup - typically Install-AtomicRedTeam, or manually cloning
      the atomics folder next to the module).
    - Run as Administrator - most atomic tests need elevated rights,
      same as the log collector/forwarder do.
    - SIEM_URL and SIEM_INGEST_KEY environment variables set, same
      values used by forwarder.py on this or another machine.

.EXAMPLE
    set SIEM_URL=http://192.168.56.1:5000
    set SIEM_INGEST_KEY=<from ingest_key.txt on the SIEM machine>
    powershell -ExecutionPolicy Bypass -File bas_runner.ps1
#>

$SiemUrl = $env:SIEM_URL
$IngestKey = $env:SIEM_INGEST_KEY
$Hostname = $env:COMPUTERNAME

if (-not $SiemUrl -or -not $IngestKey) {
    Write-Host "Set SIEM_URL and SIEM_INGEST_KEY environment variables first. See the .PREREQUISITES block at the top of this file." -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------
# Test plan - curated to match Mini SIEM's actual detection rules, so a
# clean run genuinely exercises real coverage rather than testing
# techniques nothing was built to catch. Add more here as new rules get
# built - each entry needs a real Atomic Red Team technique ID that
# exists in your atomics library.
# ---------------------------------------------------------------------
$TestPlan = @(
    @{ TechniqueId = "T1003.001"; TechniqueName = "OS Credential Dumping: LSASS Memory";        FriendlyName = "Dump LSASS memory" }
    @{ TechniqueId = "T1558.003"; TechniqueName = "Steal or Forge Kerberos Tickets: Kerberoasting"; FriendlyName = "Kerberoasting - request SPN tickets" }
    @{ TechniqueId = "T1059.001"; TechniqueName = "Command and Scripting Interpreter: PowerShell";  FriendlyName = "Encoded PowerShell command" }
    @{ TechniqueId = "T1053.005"; TechniqueName = "Scheduled Task/Job: Scheduled Task";           FriendlyName = "Create a scheduled task" }
    @{ TechniqueId = "T1543.003"; TechniqueName = "Create or Modify System Process: Windows Service"; FriendlyName = "Install a new service" }
    @{ TechniqueId = "T1070.001"; TechniqueName = "Indicator Removal: Clear Windows Event Logs";  FriendlyName = "Clear the Security event log" }
    @{ TechniqueId = "T1547.001"; TechniqueName = "Boot or Logon Autostart Execution: Registry Run Keys"; FriendlyName = "Registry Run key persistence" }
    @{ TechniqueId = "T1490";     TechniqueName = "Inhibit System Recovery";                      FriendlyName = "Delete volume shadow copies" }
    @{ TechniqueId = "T1082";     TechniqueName = "System Information Discovery";                 FriendlyName = "Discovery command burst" }
    @{ TechniqueId = "T1136.001"; TechniqueName = "Create Account: Local Account";                FriendlyName = "Create a new local user" }
)

function Report-TestStart {
    param($TechniqueId, $TechniqueName, $AtomicTestName)
    $body = @{
        technique_id     = $TechniqueId
        technique_name   = $TechniqueName
        atomic_test_name = $AtomicTestName
        atomic_test_guid = ""
        host             = $Hostname
    } | ConvertTo-Json

    try {
        $resp = Invoke-RestMethod -Uri "$SiemUrl/api/bas/test-run/start" -Method Post `
            -Headers @{"X-SIEM-Key" = $IngestKey} -ContentType "application/json" -Body $body
        return $resp.run_id
    } catch {
        Write-Host "  [ERROR] Could not report test start to SIEM: $_" -ForegroundColor Red
        return $null
    }
}

function Report-TestEnd {
    param($RunId)
    if (-not $RunId) { return }
    try {
        $resp = Invoke-RestMethod -Uri "$SiemUrl/api/bas/test-run/$RunId/end" -Method Post `
            -Headers @{"X-SIEM-Key" = $IngestKey}
        $status = $resp.run.status
        $color = switch ($status) {
            "Detected" { "Green" }
            "Delayed"  { "Yellow" }
            default    { "Gray" }
        }
        Write-Host "  -> Scored: $status" -ForegroundColor $color
    } catch {
        Write-Host "  [ERROR] Could not report test end to SIEM: $_" -ForegroundColor Red
    }
}

Write-Host "Sentinel BAS runner starting on $Hostname - $($TestPlan.Count) techniques queued." -ForegroundColor Cyan
Write-Host "Reporting to $SiemUrl`n"

foreach ($test in $TestPlan) {
    Write-Host "=== $($test.TechniqueId) - $($test.FriendlyName) ===" -ForegroundColor White

    $runId = Report-TestStart -TechniqueId $test.TechniqueId -TechniqueName $test.TechniqueName -AtomicTestName $test.FriendlyName
    if (-not $runId) {
        Write-Host "  Skipping - SIEM did not accept the start report, so this run wouldn't be scored anyway.`n" -ForegroundColor Yellow
        continue
    }

    try {
        # -GetPrereqs installs anything the test needs first (files, tools)
        # that isn't already present - safe to run every time, it's a no-op
        # if prerequisites are already satisfied.
        Invoke-AtomicTest $test.TechniqueId -GetPrereqs -ErrorAction SilentlyContinue
        Invoke-AtomicTest $test.TechniqueId
    } catch {
        Write-Host "  [WARNING] Invoke-AtomicTest raised an error - the technique may not exist in your atomics library, or may need manual input: $_" -ForegroundColor Yellow
    }

    Start-Sleep -Seconds 5   # give the log pipeline a moment to actually ingest and evaluate before scoring
    Report-TestEnd -RunId $runId

    # Best-effort cleanup so the lab doesn't accumulate leftover artifacts
    # across runs - some atomic tests don't define a cleanup step, which
    # is fine, this just silently does nothing for those.
    try { Invoke-AtomicTest $test.TechniqueId -Cleanup -ErrorAction SilentlyContinue } catch {}

    Write-Host ""
    Start-Sleep -Seconds 3
}

Write-Host "All tests run. Check $SiemUrl/bas for the coverage report - click 'Rescore Pending' after a few minutes to catch delayed detections." -ForegroundColor Cyan
