@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-RuiboTrust.ps1" -Quiet
set "RESULT=%ERRORLEVEL%"
if not "%RESULT%"=="0" echo Ruibo certificate installation failed with exit code %RESULT%.
if "%RESULT%"=="0" echo Ruibo certificate installation completed.
pause
exit /b %RESULT%
