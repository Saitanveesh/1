# Signing hook. Production signing credentials are NOT available to this repository.
# This stage intentionally refuses to run unless an operator supplies a certificate
# thumbprint; it never generates a certificate and never reports "signed"
# unless Get-AuthenticodeSignature reports Valid.
param(
  [Parameter(Mandatory = $true)] [string] $Path,
  [string] $CertificateThumbprint = $env:MON_SIGNING_CERT_THUMBPRINT,
  [string] $TimestampUrl = $env:MON_SIGNING_TIMESTAMP_URL
)
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($CertificateThumbprint) -or [string]::IsNullOrWhiteSpace($TimestampUrl)) {
  throw "signing not configured: artifact remains UNSIGNED (NOT_PROVEN)"
}
$cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My |
  Where-Object Thumbprint -eq $CertificateThumbprint | Select-Object -First 1
if ($null -eq $cert) { throw "signing certificate not found" }
Set-AuthenticodeSignature -FilePath $Path -Certificate $cert -TimestampServer $TimestampUrl | Out-Null
$status = (Get-AuthenticodeSignature -FilePath $Path).Status.ToString()
if ($status -ne "Valid") { throw "signature verification failed: $status" }
Write-Output "signed $Path ($status)"
