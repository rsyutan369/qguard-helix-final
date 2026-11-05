# Test-only Task Scheduler/ACL/HTTP adapters. No real scheduled task is registered,
# changed or stopped. Agent Node processes and HTTP requests are real.
param([string] $FixtureRoot, [string] $BaseUrl, [string] $ScannerId, [string] $CollectorId)
$ErrorActionPreference = 'Stop'
$env:ProgramData = Join-Path $FixtureRoot 'ProgramData'
$global:QguardStartupTasks = @{}
$global:QguardStartupStopped = @()
$global:QguardStartupAssertions = 0
$global:QguardStartupFixtureNode = (Get-Command node.exe).Source
$global:QguardStartupHttpClient = Join-Path $FixtureRoot 'http-client.cjs'

# This workstation blocks PowerShell's own sockets. The adapter performs real
# loopback HTTP using Node (the runtime's transport is verified separately).
function Invoke-FixtureHttp($Request) {
  $reply = ($Request | ConvertTo-Json -Compress -Depth 8) | & $global:QguardStartupFixtureNode $global:QguardStartupHttpClient
  if ($LASTEXITCODE -ne 0) { throw "Fixture HTTP client failed: $reply" }
  return ($reply | ConvertFrom-Json)
}
function Invoke-RestMethod {
  param($Method='Get', $Uri, $TimeoutSec=15, $MaximumRedirection=0, $ContentType, $Headers, $Body)
  return Invoke-FixtureHttp @{ method=$Method; uri=$Uri; timeout=$TimeoutSec; headers=$Headers; contentType=$ContentType; body=$Body }
}
function Invoke-WebRequest {
  param($Uri, $OutFile, $TimeoutSec=15, $MaximumRedirection=0, [switch]$UseBasicParsing, $Headers)
  return Invoke-FixtureHttp @{ method='Get'; uri=$Uri; timeout=$TimeoutSec; headers=$Headers; outFile=$OutFile }
}

function Assert-Check($Condition, $Message) {
  if (-not $Condition) { throw "FAIL: $Message" }
  $global:QguardStartupAssertions++
  Write-Output "PASS $Message"
}
function Get-Acl { param($LiteralPath, $Path)
  $acl = [pscustomobject]@{ Access = @() }
  $acl | Add-Member ScriptMethod SetAccessRuleProtection { param($a,$b) }
  $acl | Add-Member ScriptMethod RemoveAccessRule { param($a) }
  $acl | Add-Member ScriptMethod AddAccessRule { param($a) }
  return $acl
}
function Set-Acl { param($LiteralPath, $Path, $AclObject) }
function Get-FileHash { param($LiteralPath, $Path, $Algorithm='SHA256')
  if ($Algorithm -ne 'SHA256') { throw 'Fixture only supports SHA256' }
  $selected = if ($LiteralPath) { $LiteralPath } else { $Path }
  $sha = [Security.Cryptography.SHA256]::Create()
  $stream = [IO.File]::OpenRead($selected)
  try { return [pscustomobject]@{ Hash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','') } }
  finally { $stream.Dispose(); $sha.Dispose() }
}
function Get-ScheduledTask { param($TaskName, $ErrorAction)
  $task = $global:QguardStartupTasks[$TaskName]
  if (-not $task) { return }
  if ($task.Process) { $task.Process.Refresh(); if ($task.Process.HasExited) { $task.State = 'Ready' } }
  return $task
}
function Stop-ScheduledTask { param($TaskName)
  $task = $global:QguardStartupTasks[$TaskName]
  if (-not $task) { throw "Unknown fixture task $TaskName" }
  if ($task.Process -and -not $task.Process.HasExited) { Stop-Process -Id $task.Process.Id -Force; $task.Process.WaitForExit() }
  $task.State = 'Ready'
  $global:QguardStartupStopped += $TaskName
}
function Unregister-ScheduledTask { param($TaskName, $Confirm, $ErrorAction)
  if ($global:QguardStartupTasks.ContainsKey($TaskName)) {
    if ($global:QguardStartupTasks[$TaskName].State -eq 'Running') { throw 'Must stop before unregister' }
    $global:QguardStartupTasks.Remove($TaskName)
  }
}
function New-ScheduledTaskAction { param($Execute, $Argument, $WorkingDirectory)
  return [pscustomobject]@{ Execute=$Execute; Arguments=$Argument; WorkingDirectory=$WorkingDirectory }
}
function New-ScheduledTaskTrigger { param([switch] $AtStartup) return @{} }
function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel) return @{} }
function New-ScheduledTaskSettingsSet {
  param([switch] $AllowStartIfOnBatteries, [switch] $DontStopIfGoingOnBatteries, [switch] $StartWhenAvailable, $RestartCount, $RestartInterval, $ExecutionTimeLimit)
  return @{}
}
function Register-ScheduledTask {
  param($TaskName, $Action, $Trigger, $Principal, $Settings, $Description, [switch] $Force)
  if ($global:QguardStartupTasks[$TaskName] -and $global:QguardStartupTasks[$TaskName].State -eq 'Running') { throw 'Regression: replaced task without stopping its process' }
  $global:QguardStartupTasks[$TaskName] = [pscustomobject]@{ TaskName=$TaskName; State='Ready'; Action=$Action; Process=$null }
}
function Start-ScheduledTask { param($TaskName)
  $task = $global:QguardStartupTasks[$TaskName]
  if ($task.State -eq 'Running') { return } # The real default IgnoreNew behavior.
  $task.Process = Start-Process -FilePath $task.Action.Execute -ArgumentList $task.Action.Arguments -WorkingDirectory $task.Action.WorkingDirectory -WindowStyle Hidden -PassThru -RedirectStandardError (Join-Path $FixtureRoot "$TaskName-stderr.txt") -RedirectStandardOutput (Join-Path $FixtureRoot "$TaskName-stdout.txt")
  $task.State = 'Running'
}
function Self-Status($AgentId, $Token) {
  return (Invoke-RestMethod -Uri "$BaseUrl/api/v1/agent-installer/self" -TimeoutSec 5 -Headers @{ 'x-qguard-agent-id'=$AgentId; 'x-qguard-agent-token'=$Token }).data
}
function Install-Fixture($Name) {
  & (Join-Path $FixtureRoot "$Name.ps1")
  if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "Fixture installer exited $LASTEXITCODE" }
}

try {
  # Reproduce the original collision with a real running legacy Collector.
  $legacy = Join-Path $env:ProgramData 'QGuardHelix\Agent'
  New-Item -ItemType Directory -Force -Path $legacy | Out-Null
  Copy-Item -LiteralPath (Join-Path $FixtureRoot 'qguard-agent.cjs') -Destination (Join-Path $legacy 'qguard-agent.cjs')
  $legacyConfig = Join-Path $legacy 'agent.env'
  @("QGUARD_API_URL=$BaseUrl", "QGUARD_AGENT_ID=$CollectorId", 'QGUARD_AGENT_TOKEN=collector-fixture-token', 'QGUARD_AGENT_ROLE=collector', 'QGUARD_ENVIRONMENT=development', "QGUARD_STATE_DIR=$(Join-Path $legacy 'state')", "QGUARD_LOG_FILE=$(Join-Path $legacy 'legacy.log')") | Set-Content -LiteralPath $legacyConfig
  $node = (Get-Command node.exe).Source
  $action = New-ScheduledTaskAction -Execute $node -Argument ('"' + (Join-Path $legacy 'qguard-agent.cjs') + '" watch') -WorkingDirectory $legacy
  Register-ScheduledTask -TaskName 'QGuardHelixAgent' -Action $action
  Start-ScheduledTask -TaskName 'QGuardHelixAgent'
  $deadline = [DateTime]::UtcNow.AddSeconds(20)
  while (-not (Self-Status $CollectorId 'collector-fixture-token').connected) {
    if ([DateTime]::UtcNow -gt $deadline) { throw 'Legacy Collector did not heartbeat' }
    Start-Sleep -Milliseconds 250
  }
  # Old installer overwrote the shared file while IgnoreNew left Collector alive.
  (Get-Content -LiteralPath $legacyConfig) -replace "QGUARD_AGENT_ID=$CollectorId", "QGUARD_AGENT_ID=$ScannerId" -replace 'collector-fixture-token', 'scanner-fixture-token' -replace 'QGUARD_AGENT_ROLE=collector', 'QGUARD_AGENT_ROLE=scanner' | Set-Content -LiteralPath $legacyConfig
  Start-ScheduledTask -TaskName 'QGuardHelixAgent'
  Assert-Check (-not (Self-Status $ScannerId 'scanner-fixture-token').connected) 'reproduced: shared task Running, Scanner has no heartbeat'

  $scannerTask = "QGuardHelixAgent-$ScannerId"
  $collectorTask = "QGuardHelixAgent-$CollectorId"
  Install-Fixture 'scanner'
  Assert-Check (-not $global:QguardStartupTasks.ContainsKey('QGuardHelixAgent')) 'legacy shared task retired only when its configuration matches this agent'
  Assert-Check ((Self-Status $ScannerId 'scanner-fixture-token').connected) 'new Scanner process delivers a real signed heartbeat'
  $scannerSlot = Join-Path (Join-Path $env:ProgramData 'QGuardHelix\Agents') $ScannerId
  $scannerKey = Join-Path (Join-Path $scannerSlot 'state') "signing-keys-$ScannerId.json"
  $keyBefore = (Get-FileHash -LiteralPath $scannerKey).Hash

  Install-Fixture 'collector'
  $collectorPid = $global:QguardStartupTasks[$collectorTask].Process.Id
  Assert-Check ($global:QguardStartupTasks[$scannerTask].State -eq 'Running' -and $global:QguardStartupTasks[$collectorTask].State -eq 'Running') 'Collector and Scanner processes run concurrently in separate slots'
  Assert-Check ((Self-Status $CollectorId 'collector-fixture-token').connected) 'Collector reconnects using its existing identity'
  $oldScannerPid = $global:QguardStartupTasks[$scannerTask].Process.Id
  $launchBefore = (Self-Status $ScannerId 'scanner-fixture-token').runtimeLaunchId
  Install-Fixture 'scanner'
  $launchAfter = (Self-Status $ScannerId 'scanner-fixture-token').runtimeLaunchId
  Assert-Check ($global:QguardStartupTasks[$scannerTask].Process.Id -ne $oldScannerPid) 'Scanner reinstall replaces its running process'
  Assert-Check ($launchBefore -ne $launchAfter -and $launchAfter) 'verification requires a fresh launch receipt instead of an old heartbeat'
  Assert-Check ($global:QguardStartupTasks[$collectorTask].Process.Id -eq $collectorPid -and $global:QguardStartupTasks[$collectorTask].State -eq 'Running') 'Scanner reinstall leaves the Collector process running'
  Assert-Check ((Get-FileHash -LiteralPath $scannerKey).Hash -eq $keyBefore) 'Scanner signing keys survive reinstall without resetting server binding'
  Assert-Check (Test-Path -LiteralPath (Join-Path $scannerSlot 'agent.log')) 'unattended runtime writes a persistent startup log'

  & (Join-Path $FixtureRoot 'scanner.ps1') -Uninstall
  Assert-Check (-not $global:QguardStartupTasks.ContainsKey($scannerTask) -and $global:QguardStartupTasks[$collectorTask].State -eq 'Running') 'uninstall removes only the selected agent task'
  Write-Output "$global:QguardStartupAssertions Windows startup integration checks passed"
} catch {
  Get-ChildItem -LiteralPath $FixtureRoot -Recurse -File | Where-Object { $_.Extension -eq '.log' -or $_.Name -like '*-stderr.txt' } | ForEach-Object { Get-Content -LiteralPath $_.FullName -Tail 12 | Write-Host }
  throw
} finally {
  foreach ($task in @($global:QguardStartupTasks.Values)) {
    if ($task.Process) { $task.Process.Refresh(); if (-not $task.Process.HasExited) { Stop-Process -Id $task.Process.Id -Force -ErrorAction SilentlyContinue } }
  }
}
