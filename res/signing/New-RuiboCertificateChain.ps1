[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "output"),
    [string]$Organization = "ruibo",
    [ValidateRange(1, 30)]
    [int]$RootValidityYears = 15,
    [ValidateRange(1, 10)]
    [int]$CodeSigningValidityYears = 3,
    [Security.SecureString]$CodeSigningPfxPassword,
    [Security.SecureString]$RootBackupPassword,
    [switch]$ExportRootBackup,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "This script requires Windows and the Windows PKI PowerShell module."
}

$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$publicDirectory = Join-Path $OutputDirectory "public"
$privateDirectory = Join-Path $OutputDirectory "private"
$rootCerPath = Join-Path $publicDirectory "RuiboRootCA.cer"
$publisherCerPath = Join-Path $publicDirectory "RuiboCodeSigning.cer"
$codeSigningPfxPath = Join-Path $privateDirectory "RuiboCodeSigning.pfx"
$rootBackupPath = Join-Path $privateDirectory "RuiboRootCA-backup.pfx"
$manifestPath = Join-Path $publicDirectory "certificate-manifest.json"

$outputs = @($rootCerPath, $publisherCerPath, $codeSigningPfxPath, $manifestPath)
if (-not $Force -and ($outputs | Where-Object { Test-Path -LiteralPath $_ })) {
    throw "Certificate output already exists. Use a new directory or pass -Force."
}

New-Item -ItemType Directory -Path $publicDirectory, $privateDirectory -Force | Out-Null

try {
    $acl = Get-Acl -LiteralPath $privateDirectory
    $acl.SetAccessRuleProtection($true, $false)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        $identity,
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.SetAccessRule($rule)
    Set-Acl -LiteralPath $privateDirectory -AclObject $acl
} catch {
    Write-Warning "Could not restrict the private directory ACL: $($_.Exception.Message)"
}

$codeSigningPassword = $CodeSigningPfxPassword
if (-not $codeSigningPassword) {
    $codeSigningPassword = Read-Host "Password for RuiboCodeSigning.pfx" -AsSecureString
}
if ($ExportRootBackup -and -not $RootBackupPassword) {
    $RootBackupPassword = Read-Host "Separate password for the offline root CA backup" -AsSecureString
}

$rootSubject = "CN=Ruibo Root CA, O=$Organization"
$publisherSubject = "CN=Ruibo Code Signing, O=$Organization"
$rootExportPolicy = if ($ExportRootBackup) { "Exportable" } else { "NonExportable" }

$rootParameters = @{
    Type = "Custom"
    Subject = $rootSubject
    FriendlyName = "Ruibo Root CA"
    CertStoreLocation = "Cert:\CurrentUser\My"
    KeyAlgorithm = "RSA"
    KeyLength = 4096
    HashAlgorithm = "SHA256"
    KeyExportPolicy = $rootExportPolicy
    KeyUsage = @("CertSign", "CRLSign", "DigitalSignature")
    KeyUsageProperty = "Sign"
    Provider = "Microsoft Software Key Storage Provider"
    NotAfter = (Get-Date).AddYears($RootValidityYears)
    TextExtension = @("2.5.29.19={critical}{text}ca=1&pathlength=1")
}
$root = New-SelfSignedCertificate @rootParameters
$requestedPublisherNotAfter = (Get-Date).AddYears($CodeSigningValidityYears)
$publisherNotAfter = if ($requestedPublisherNotAfter -lt $root.NotAfter.AddDays(-1)) {
    $requestedPublisherNotAfter
} else {
    $root.NotAfter.AddDays(-1)
}

$publisherParameters = @{
    Type = "Custom"
    Subject = $publisherSubject
    FriendlyName = "Ruibo Code Signing"
    Signer = $root
    CertStoreLocation = "Cert:\CurrentUser\My"
    KeyAlgorithm = "RSA"
    KeyLength = 3072
    HashAlgorithm = "SHA256"
    KeyExportPolicy = "Exportable"
    KeyUsage = "DigitalSignature"
    KeyUsageProperty = "Sign"
    Provider = "Microsoft Software Key Storage Provider"
    NotAfter = $publisherNotAfter
    TextExtension = @(
        "2.5.29.19={critical}{text}ca=0",
        "2.5.29.37={critical}{text}1.3.6.1.5.5.7.3.3"
    )
}
$publisher = New-SelfSignedCertificate @publisherParameters

Export-Certificate -Cert $root -FilePath $rootCerPath -Type CERT | Out-Null
Export-Certificate -Cert $publisher -FilePath $publisherCerPath -Type CERT | Out-Null
Export-PfxCertificate -Cert $publisher -FilePath $codeSigningPfxPath `
    -Password $codeSigningPassword -ChainOption EndEntityCertOnly | Out-Null

if ($ExportRootBackup) {
    Export-PfxCertificate -Cert $root -FilePath $rootBackupPath `
        -Password $RootBackupPassword -ChainOption EndEntityCertOnly | Out-Null
}

$manifest = [ordered]@{
    schemaVersion = 1
    createdUtc = [DateTime]::UtcNow.ToString("o")
    root = [ordered]@{
        file = "RuiboRootCA.cer"
        subject = $root.Subject
        thumbprint = $root.Thumbprint
        notAfterUtc = $root.NotAfter.ToUniversalTime().ToString("o")
    }
    publisher = [ordered]@{
        file = "RuiboCodeSigning.cer"
        subject = $publisher.Subject
        thumbprint = $publisher.Thumbprint
        issuer = $publisher.Issuer
        notAfterUtc = $publisher.NotAfter.ToUniversalTime().ToString("o")
        eku = "1.3.6.1.5.5.7.3.3"
    }
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

foreach ($name in @("Install-RuiboTrust.ps1", "Install-RuiboTrust.cmd", "Remove-RuiboTrust.cmd")) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $publicDirectory -Force
}

Write-Host "Certificate chain created."
Write-Host "Public deployment bundle: $publicDirectory"
Write-Host "Code-signing PFX:       $codeSigningPfxPath"
if ($ExportRootBackup) {
    Write-Warning "Move $rootBackupPath to encrypted offline storage and remove working copies."
} else {
    Write-Warning "The root private key is non-exportable and remains in Cert:\CurrentUser\My on this machine."
}
Write-Warning "Never copy the private directory or PFX to client computers or source control."
