# Builds the unsigned MON Windows collector MSI from an already-built MONWindows.exe.
# Requires the WiX CLI: dotnet tool install --global wix --version 5.0.2
param(
  [Parameter(Mandatory = $true)] [string] $Exe,
  [Parameter(Mandatory = $true)] [ValidatePattern('^\d+\.\d+\.\d+$')] [string] $Version,
  [Parameter(Mandatory = $true)] [string] $Out
)
$ErrorActionPreference = "Stop"
$exePath = (Resolve-Path -LiteralPath $Exe).Path
if ([System.IO.Path]::GetFileName($exePath) -ne "MONWindows.exe") {
  throw "Exe must be MONWindows.exe"
}
$wxs = Join-Path $PSScriptRoot "..\..\packaging\windows\MONWindows.wxs"
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Out) | Out-Null
wix build -arch x64 -d "SourceExe=$exePath" -d "ProductVersion=$Version" -o $Out $wxs
if ($LASTEXITCODE -ne 0) { throw "wix build failed with exit code $LASTEXITCODE" }
Write-Output "built $Out"
