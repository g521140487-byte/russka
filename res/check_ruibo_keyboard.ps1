param(
    [string]$AppName = "ruibo",
    [string]$ReportPath = ""
)

$ErrorActionPreference = "Continue"
$transcribing = $false
if ($ReportPath) {
    Start-Transcript -LiteralPath $ReportPath -Force | Out-Null
    $transcribing = $true
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    Write-Host "=== $AppName keyboard compatibility check ==="
    Write-Host "Time: $(Get-Date -Format o)"
    Write-Host "Administrator: $isAdmin"

    $service = Get-CimInstance Win32_Service -Filter "Name='$AppName'" -ErrorAction SilentlyContinue
    $exe = $null
    if ($service) {
        Write-Host "Service: $($service.Name) / $($service.State) / StartMode=$($service.StartMode) / Account=$($service.StartName)"
        Write-Host "Service PID: $($service.ProcessId)"
        Write-Host "Service path: $($service.PathName)"
        $match = [regex]::Match($service.PathName, '^\s*(?:"([^"]+)"|(\S+))')
        if ($match.Success) {
            $exe = if ($match.Groups[1].Success) { $match.Groups[1].Value } else { $match.Groups[2].Value }
        }
    } else {
        Write-Warning "The $AppName service is not installed. Use the file ending in -install.exe or the MSI package."
    }

    if ($exe -and (Test-Path -LiteralPath $exe)) {
        $signature = Get-AuthenticodeSignature -LiteralPath $exe
        Write-Host "Installed EXE: $exe"
        Write-Host "Signature: $($signature.Status)"
        Write-Host "SHA256: $((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash)"
        if ($signature.Status -ne "Valid") {
            Write-Warning "The executable is not trusted-signed. Endpoint security may block synthetic keyboard input until the Ruibo binaries are signed and approved."
        }

        $installAcl = Get-Acl -LiteralPath (Split-Path $exe -Parent)
        $broadWriteRules = $installAcl.Access | Where-Object {
            $_.AccessControlType -eq "Allow" -and
            $_.IdentityReference -match "Everyone|Authenticated Users|S-1-1-0|S-1-5-11" -and
            $_.FileSystemRights.ToString() -match "Write|Modify|FullControl"
        }
        if ($broadWriteRules) {
            Write-Warning "The SYSTEM service installation directory is writable by a broad user group. Reinstall to Program Files or harden the directory ACL."
            $broadWriteRules | Select-Object IdentityReference, FileSystemRights, IsInherited | Format-Table
        } else {
            Write-Host "Install directory ACL: protected from broad user-group writes"
        }
    } elseif ($service) {
        Write-Warning "The executable from the service path was not found."
    }

    Write-Host "`n--- Processes ---"
    Get-CimInstance Win32_Process -Filter "Name='$AppName.exe'" -ErrorAction SilentlyContinue | ForEach-Object {
        $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue
        [pscustomobject]@{
            PID = $_.ProcessId
            ParentPID = $_.ParentProcessId
            SessionId = $_.SessionId
            Owner = if ($owner -and $owner.ReturnValue -eq 0) { "$($owner.Domain)\$($owner.User)" } else { "unavailable" }
            CommandLine = $_.CommandLine
            ExecutablePath = $_.ExecutablePath
        }
    } | Format-List

    Write-Host "`n--- Registered antivirus products ---"
    Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue |
        Select-Object displayName, productState, pathToSignedProductExe | Format-List

    $roamingRoots = @(
        (Join-Path $env:APPDATA $AppName),
        (Join-Path $env:ProgramData $AppName),
        (Join-Path $env:WINDIR "System32\config\systemprofile\AppData\Roaming\$AppName"),
        (Join-Path $env:WINDIR "ServiceProfiles\LocalService\AppData\Roaming\$AppName")
    )
    $logRoots = $roamingRoots | ForEach-Object { Join-Path $_ "log" }
    $configRoots = $roamingRoots | ForEach-Object { Join-Path $_ "config" }

    Write-Host "`n--- Log locations ---"
    foreach ($root in $logRoots) {
        if (Test-Path -LiteralPath $root -ErrorAction SilentlyContinue) {
            Write-Host "Accessible: $root"
            Get-ChildItem -LiteralPath $root -Recurse -File -Filter "*.log" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 10 FullName, Length, LastWriteTime | Format-Table -AutoSize
        } else {
            Write-Host "Not found or inaccessible: $root"
        }
    }

    Write-Host "`n--- Keyboard configuration ---"
    $configFiles = foreach ($root in $configRoots) {
        if (Test-Path -LiteralPath $root -ErrorAction SilentlyContinue) {
            Get-ChildItem -LiteralPath $root -Recurse -File -Filter "*.toml" -ErrorAction SilentlyContinue
        }
    }
    $configFiles | Select-String -Pattern "keyboard_mode|enable-keyboard|access-mode|block-input" -ErrorAction SilentlyContinue |
        Select-Object Path, LineNumber, Line | Format-Table -Wrap

    Write-Host "`n--- Keyboard injection failures ---"
    $logs = foreach ($root in $logRoots) {
        if (Test-Path -LiteralPath $root -ErrorAction SilentlyContinue) {
            Get-ChildItem -LiteralPath $root -Recurse -File -Filter "*.log" -ErrorAction SilentlyContinue
        }
    }
    $failurePattern = "SendInput inserted 0 (keyboard|mouse) events|Windows keyboard simulation failed|Could not send .*Key|foreground window is elevated|elevated_foreground_window"
    $failures = $logs | Select-String -Pattern $failurePattern -ErrorAction SilentlyContinue
    if ($failures) {
        Write-Warning "Keyboard injection failures were found:"
        $failures | Select-Object -Last 50 Path, LineNumber, Line | Format-Table -Wrap
    } else {
        Write-Host "No keyboard injection failure markers were found in accessible logs."
    }

    Write-Host "`n--- Windows enforcement events (last 24 hours) ---"
    $since = (Get-Date).AddHours(-24)
    $eventLogs = @(
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-CodeIntegrity/Operational",
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-AppLocker/MSI and Script"
    )
    foreach ($eventLog in $eventLogs) {
        Get-WinEvent -FilterHashtable @{ LogName = $eventLog; StartTime = $since } -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match "(?i)$AppName|librustdesk|WindowInjection" } |
            Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-List
    }

    if ($service -and $service.State -eq "Running" -and $service.StartName -eq "LocalSystem") {
        Write-Host "`nService elevation is healthy. If input fails in normal Notepad and the failure markers above appear, use signed binaries plus a centrally approved endpoint-security allowlist."
    }
    Write-Host "Test normal Notepad first, then an elevated Notepad. A driver is not required for ordinary Windows applications."
} finally {
    if ($transcribing) {
        Stop-Transcript | Out-Null
    }
}
