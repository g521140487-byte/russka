[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactsPath,
    [Parameter(Mandatory = $true)]
    [string]$PfxPath,
    [string]$RootCertificatePath = "",
    [Security.SecureString]$PfxPassword,
    [string]$TimestampUrl = "",
    [switch]$IncludeAllNonDriverBinaries,
    [switch]$Force,
    [switch]$KeepCertificateInStore
)

$ErrorActionPreference = "Stop"

function Find-SignTool {
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }

    $roots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "$env:ProgramFiles\Windows Kits\10\bin"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    $candidates = foreach ($root in $roots) {
        Get-ChildItem -LiteralPath $root -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match "\\x64\\signtool\.exe$" }
    }
    $selected = $candidates | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $selected) {
        throw "signtool.exe was not found. Install the Windows 10/11 SDK Signing Tools feature."
    }
    return $selected.FullName
}

function Test-IsRuiboOwnedFile([IO.FileInfo]$File) {
    return $File.Name -like "ruibo*.exe" -or
        $File.Name -like "ruibo*.msi" -or
        $File.Name -eq "RuntimeBroker_ruibo.exe" -or
        $File.Name -eq "librustdesk.dll" -or
        $File.Name -eq "WindowInjection.dll"
}

$ArtifactsPath = (Resolve-Path -LiteralPath $ArtifactsPath).Path
$PfxPath = (Resolve-Path -LiteralPath $PfxPath).Path
if (-not $RootCertificatePath) {
    $pkiRoot = Split-Path (Split-Path $PfxPath -Parent) -Parent
    $candidateRoot = Join-Path $pkiRoot "public\RuiboRootCA.cer"
    if (Test-Path -LiteralPath $candidateRoot) { $RootCertificatePath = $candidateRoot }
}
if (-not $RootCertificatePath) {
    throw "RuiboRootCA.cer was not found. Pass -RootCertificatePath for chain verification."
}
$RootCertificatePath = (Resolve-Path -LiteralPath $RootCertificatePath).Path
$signTool = Find-SignTool
$password = $PfxPassword
if (-not $password -and $env:RUIBO_SIGNING_PFX_PASSWORD) {
    $password = ConvertTo-SecureString $env:RUIBO_SIGNING_PFX_PASSWORD -AsPlainText -Force
}
if (-not $password) {
    $password = Read-Host "Password for RuiboCodeSigning.pfx" -AsSecureString
}
$existingThumbprints = @(Get-ChildItem Cert:\CurrentUser\My | ForEach-Object { $_.Thumbprint })
$importedCertificate = $null
$rootCertificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2($RootCertificatePath)
$rootTrustPath = "Cert:\CurrentUser\Root\$($rootCertificate.Thumbprint)"
$rootWasAlreadyTrusted = Test-Path -LiteralPath $rootTrustPath
$report = @()

try {
    $imported = @(Import-PfxCertificate -FilePath $PfxPath `
        -CertStoreLocation "Cert:\CurrentUser\My" -Password $password)
    $importedCertificate = $imported | Where-Object { $_.HasPrivateKey } | Select-Object -First 1
    if (-not $rootWasAlreadyTrusted) {
        Import-Certificate -FilePath $RootCertificatePath `
            -CertStoreLocation "Cert:\CurrentUser\Root" | Out-Null
    }
    if (-not $importedCertificate.HasPrivateKey) {
        throw "The imported certificate has no private key."
    }
    $eku = $importedCertificate.Extensions |
        Where-Object { $_.Oid.Value -eq "2.5.29.37" } |
        ForEach-Object { $_.EnhancedKeyUsages } |
        Where-Object { $_.Value -eq "1.3.6.1.5.5.7.3.3" }
    if (-not $eku) { throw "The PFX is not a code-signing certificate." }

    $files = Get-ChildItem -LiteralPath $ArtifactsPath -Recurse -File |
        Where-Object { $_.Extension.ToLowerInvariant() -in @(".exe", ".dll", ".msi") } |
        Where-Object {
            $_.FullName -notmatch "\\(drivers|usbmmidd_v2)\\" -and
            ($IncludeAllNonDriverBinaries -or (Test-IsRuiboOwnedFile $_))
        } |
        Sort-Object FullName -Unique

    if (-not $files) { throw "No Ruibo-owned EXE, DLL, or MSI files were found under $ArtifactsPath" }

    foreach ($file in $files) {
        $before = Get-AuthenticodeSignature -LiteralPath $file.FullName
        if (-not $Force -and $before.Status -eq "Valid" -and
            $before.SignerCertificate.Thumbprint -ne $importedCertificate.Thumbprint) {
            Write-Warning "Skipping third-party signed file: $($file.FullName)"
            continue
        }

        $arguments = @(
            "sign", "/v", "/fd", "SHA256",
            "/sha1", $importedCertificate.Thumbprint,
            "/s", "My",
            "/d", "ruibo Remote Desktop"
        )
        if ($TimestampUrl) {
            $arguments += @("/tr", $TimestampUrl, "/td", "SHA256")
        }
        $arguments += $file.FullName

        & $signTool @arguments
        if ($LASTEXITCODE -ne 0) { throw "SignTool failed for $($file.FullName)" }

        & $signTool verify /pa /v $file.FullName
        if ($LASTEXITCODE -ne 0) { throw "Signature verification failed for $($file.FullName)" }

        $after = Get-AuthenticodeSignature -LiteralPath $file.FullName
        $report += [ordered]@{
            path = $file.FullName
            status = $after.Status.ToString()
            signer = $after.SignerCertificate.Subject
            thumbprint = $after.SignerCertificate.Thumbprint
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        }
    }
} finally {
    if ($importedCertificate -and -not $KeepCertificateInStore -and
        $existingThumbprints -notcontains $importedCertificate.Thumbprint) {
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($importedCertificate.Thumbprint)" -Force
    }
    if (-not $rootWasAlreadyTrusted -and (Test-Path -LiteralPath $rootTrustPath)) {
        Remove-Item -LiteralPath $rootTrustPath -Force
    }
}

$reportPath = Join-Path $ArtifactsPath "RUIBO-SIGNING-REPORT.json"
$report | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $reportPath -Encoding UTF8
Write-Host "Signed $($report.Count) file(s). Report: $reportPath"
Write-Host "The PFX password was not placed on the SignTool command line."
