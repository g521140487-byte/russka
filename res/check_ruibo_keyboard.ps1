param(
    [string]$AppName = "ruibo"
)

$ErrorActionPreference = "Continue"
$service = Get-CimInstance Win32_Service -Filter "Name='$AppName'" -ErrorAction SilentlyContinue
$installPath = Join-Path $env:ProgramFiles $AppName
$exe = Join-Path $installPath "$AppName.exe"
$logRoots = @(
    (Join-Path $env:APPDATA "$AppName\log"),
    (Join-Path $env:ProgramData "$AppName\log"),
    (Join-Path $env:WINDIR "ServiceProfiles\LocalService\AppData\Roaming\$AppName\log")
)

Write-Host "=== ruibo keyboard compatibility check ==="
if ($service) {
    Write-Host "Service: $($service.Name) / $($service.State) / StartMode=$($service.StartMode)"
    Write-Host "Service path: $($service.PathName)"
} else {
    Write-Warning "The ruibo service is not installed. Use the file ending in -install.exe or the MSI package."
}

if (Test-Path -LiteralPath $exe) {
    $signature = Get-AuthenticodeSignature -LiteralPath $exe
    Write-Host "Installed EXE: $exe"
    Write-Host "Signature: $($signature.Status)"
    if ($signature.Status -ne "Valid") {
        Write-Warning "The executable is not trusted-signed. Enterprise endpoint security may block synthetic keyboard input until the binary is signed or allowlisted."
    }
} else {
    Write-Warning "Installed EXE not found at $exe"
}

$logs = foreach ($root in $logRoots) {
    if (Test-Path -LiteralPath $root) {
        Get-ChildItem -LiteralPath $root -Recurse -File -Filter "*.log" -ErrorAction SilentlyContinue
    }
}

$failures = $logs | Select-String -Pattern "SendInput inserted 0 keyboard events|foreground window is elevated|elevated_foreground_window" -ErrorAction SilentlyContinue
if ($failures) {
    Write-Warning "Keyboard injection failures were found:"
    $failures | Select-Object -Last 20 Path, LineNumber, Line | Format-Table -Wrap
} else {
    Write-Host "No keyboard injection failure markers were found in existing logs."
}

Write-Host "Test both a normal Notepad window and an elevated Notepad window. If only the elevated window fails, reinstall and verify that the ruibo service is Running. If both fail while the service is Running, provide these results to the endpoint-security administrator for allowlisting."
