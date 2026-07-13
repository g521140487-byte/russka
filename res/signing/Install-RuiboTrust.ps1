[CmdletBinding()]
param(
    [switch]$Remove,
    [switch]$Quiet,
    [switch]$ValidateOnly
)

$ErrorActionPreference = "Stop"
$manifestPath = Join-Path $PSScriptRoot "certificate-manifest.json"
$rootPath = Join-Path $PSScriptRoot "RuiboRootCA.cer"
$publisherPath = Join-Path $PSScriptRoot "RuiboCodeSigning.cer"

function Normalize-Thumbprint([string]$Value) {
    return ($Value -replace "[^0-9A-Fa-f]", "").ToUpperInvariant()
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not $ValidateOnly -and -not (Test-IsAdministrator)) {
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Remove) { $arguments += " -Remove" }
    if ($Quiet) { $arguments += " -Quiet" }
    $process = Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments -Wait -PassThru
    exit $process.ExitCode
}

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Missing certificate-manifest.json. Use the complete generated public bundle."
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

if ($Remove) {
    $targets = @(
        @{ Store = "Cert:\LocalMachine\Root"; Thumbprint = (Normalize-Thumbprint $manifest.root.thumbprint) },
        @{ Store = "Cert:\LocalMachine\TrustedPublisher"; Thumbprint = (Normalize-Thumbprint $manifest.publisher.thumbprint) }
    )
    if (-not $Quiet) {
        $confirmation = Read-Host "Type REMOVE to remove the pinned Ruibo trust certificates"
        if ($confirmation -ne "REMOVE") { throw "Cancelled." }
    }
    foreach ($target in $targets) {
        $path = Join-Path $target.Store $target.Thumbprint
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
            Write-Host "Removed $path"
        }
    }
    exit 0
}

foreach ($path in @($rootPath, $publisherPath)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing certificate: $path" }
}

$root = New-Object Security.Cryptography.X509Certificates.X509Certificate2($rootPath)
$publisher = New-Object Security.Cryptography.X509Certificates.X509Certificate2($publisherPath)
$expectedRoot = Normalize-Thumbprint $manifest.root.thumbprint
$expectedPublisher = Normalize-Thumbprint $manifest.publisher.thumbprint

if ((Normalize-Thumbprint $root.Thumbprint) -ne $expectedRoot) {
    throw "Root certificate thumbprint does not match the signed deployment manifest."
}
if ((Normalize-Thumbprint $publisher.Thumbprint) -ne $expectedPublisher) {
    throw "Publisher certificate thumbprint does not match the signed deployment manifest."
}
if ($root.Subject -ne $manifest.root.subject -or $publisher.Subject -ne $manifest.publisher.subject) {
    throw "Certificate subjects do not match the deployment manifest."
}

$basicConstraints = $root.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" }
if (-not $basicConstraints -or -not $basicConstraints.CertificateAuthority) {
    throw "RuiboRootCA.cer is not a CA certificate."
}
$codeSigningEku = $publisher.Extensions |
    Where-Object { $_.Oid.Value -eq "2.5.29.37" } |
    ForEach-Object { $_.EnhancedKeyUsages } |
    Where-Object { $_.Value -eq "1.3.6.1.5.5.7.3.3" }
if (-not $codeSigningEku) {
    throw "RuiboCodeSigning.cer does not contain the Code Signing EKU."
}

if ($ValidateOnly) {
    Write-Host "Ruibo certificate bundle validation succeeded."
    Write-Host "Root CA:   $($root.Subject) [$expectedRoot]"
    Write-Host "Publisher: $($publisher.Subject) [$expectedPublisher]"
    exit 0
}

if (-not $Quiet) {
    Write-Host "Root CA:   $($root.Subject) [$expectedRoot]"
    Write-Host "Publisher: $($publisher.Subject) [$expectedPublisher]"
    $confirmation = Read-Host "Type INSTALL to trust this Ruibo certificate chain for the whole computer"
    if ($confirmation -ne "INSTALL") { throw "Cancelled." }
}

Import-Certificate -FilePath $rootPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
Import-Certificate -FilePath $publisherPath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null

if (-not (Test-Path -LiteralPath "Cert:\LocalMachine\Root\$expectedRoot")) {
    throw "Root CA import verification failed."
}
if (-not (Test-Path -LiteralPath "Cert:\LocalMachine\TrustedPublisher\$expectedPublisher")) {
    throw "Trusted Publisher import verification failed."
}

Write-Host "Ruibo Root CA and code-signing publisher trust installed successfully."
