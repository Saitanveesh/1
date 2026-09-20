param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("install", "start", "status", "stop", "uninstall")]
  [string] $Action,

  [Parameter(Mandatory = $true)]
  [ValidatePattern("^[A-Za-z0-9_.-]{1,128}$")]
  [string] $ServiceName,

  [string] $ExecutablePath,
  [string] $StateDir,
  [string] $TenantId = "local-tenant",
  [string] $SiteId = "local-site",
  [string] $SensorId = "local-sensor",
  [string] $SiteUrl = "http://127.0.0.1:9",
  [ValidateRange(1, 3600)]
  [int] $PollIntervalSeconds = 5,
  [int] $TimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"

function Assert-Windows {
  if ($PSVersionTable.PSEdition -eq "Desktop") {
    return
  }
  if (-not $IsWindows) {
    throw "MONWindows service lifecycle commands require Windows."
  }
}

function Get-ServiceOrNull {
  param([string] $Name)
  Get-Service -Name $Name -ErrorAction SilentlyContinue
}

function Wait-ServiceState {
  param(
    [string] $Name,
    [string] $DesiredState,
    [int] $TimeoutSeconds
  )
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    $service = Get-ServiceOrNull -Name $Name
    if ($null -eq $service -and $DesiredState -eq "Deleted") {
      return
    }
    if ($null -ne $service -and $service.Status.ToString() -eq $DesiredState) {
      return
    }
    Start-Sleep -Milliseconds 500
  } while ((Get-Date) -lt $deadline)
  throw "Service '$Name' did not reach '$DesiredState' within $TimeoutSeconds seconds."
}

function Invoke-Sc {
  param([string[]] $Arguments)
  $output = & sc.exe @Arguments 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "sc.exe $($Arguments -join ' ') failed: $($output -join ' ')"
  }
  return $output
}

function Assert-InstallInputs {
  if ([string]::IsNullOrWhiteSpace($ExecutablePath)) {
    throw "ExecutablePath is required for install."
  }
  if ([string]::IsNullOrWhiteSpace($StateDir)) {
    throw "StateDir is required for install."
  }
  $resolvedExe = Resolve-Path -LiteralPath $ExecutablePath -ErrorAction Stop
  if ([System.IO.Path]::GetFileName($resolvedExe.Path) -ne "MONWindows.exe") {
    throw "ExecutablePath must point to MONWindows.exe."
  }
  New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
  return $resolvedExe.Path
}

function Install-MONWindowsService {
  Assert-Windows
  if ($null -ne (Get-ServiceOrNull -Name $ServiceName)) {
    throw "Service '$ServiceName' already exists."
  }
  $resolvedExe = Assert-InstallInputs
  $resolvedStateDir = (Resolve-Path -LiteralPath $StateDir).Path
  $binPath = "`"$resolvedExe`" service-run --tenant-id $TenantId --site-id $SiteId --sensor-id $SensorId --state-dir `"$resolvedStateDir`" --site-url $SiteUrl --poll-interval-seconds $PollIntervalSeconds --service-name $ServiceName"
  $created = $false
  try {
    Invoke-Sc -Arguments @("create", $ServiceName, "binPath=", $binPath, "start=", "demand", "DisplayName=", $ServiceName) | Out-Null
    $created = $true
    Invoke-Sc -Arguments @("description", $ServiceName, "MON Windows endpoint collector") | Out-Null
    Write-Output "installed $ServiceName"
  }
  catch {
    if ($created -or $null -ne (Get-ServiceOrNull -Name $ServiceName)) {
      & sc.exe delete $ServiceName | Out-Null
      Wait-ServiceState -Name $ServiceName -DesiredState "Deleted" -TimeoutSeconds $TimeoutSeconds
    }
    throw
  }
}

function Start-MONWindowsService {
  Assert-Windows
  if ($null -eq (Get-ServiceOrNull -Name $ServiceName)) {
    throw "Service '$ServiceName' is not installed."
  }
  $service = Get-Service -Name $ServiceName
  if ($service.Status -ne "Running") {
    Start-Service -Name $ServiceName
  }
  Wait-ServiceState -Name $ServiceName -DesiredState "Running" -TimeoutSeconds $TimeoutSeconds
  Write-Output "running $ServiceName"
}

function Stop-MONWindowsService {
  Assert-Windows
  $service = Get-ServiceOrNull -Name $ServiceName
  if ($null -eq $service) {
    Write-Output "absent $ServiceName"
    return
  }
  if ($service.Status -ne "Stopped") {
    Stop-Service -Name $ServiceName -Force
  }
  Wait-ServiceState -Name $ServiceName -DesiredState "Stopped" -TimeoutSeconds $TimeoutSeconds
  Write-Output "stopped $ServiceName"
}

function Uninstall-MONWindowsService {
  Assert-Windows
  Stop-MONWindowsService
  if ($null -ne (Get-ServiceOrNull -Name $ServiceName)) {
    Invoke-Sc -Arguments @("delete", $ServiceName) | Out-Null
  }
  Wait-ServiceState -Name $ServiceName -DesiredState "Deleted" -TimeoutSeconds $TimeoutSeconds
  Write-Output "uninstalled $ServiceName"
}

function Get-MONWindowsServiceStatus {
  Assert-Windows
  $service = Get-ServiceOrNull -Name $ServiceName
  if ($null -eq $service) {
    Write-Output "absent $ServiceName"
    return
  }
  Write-Output "$($service.Status.ToString().ToLowerInvariant()) $ServiceName"
}

switch ($Action) {
  "install" { Install-MONWindowsService }
  "start" { Start-MONWindowsService }
  "status" { Get-MONWindowsServiceStatus }
  "stop" { Stop-MONWindowsService }
  "uninstall" { Uninstall-MONWindowsService }
}
