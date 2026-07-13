@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-RuiboTrust.ps1" -Remove
set "RESULT=%ERRORLEVEL%"
if not "%RESULT%"=="0" echo Ruibo certificate removal failed with exit code %RESULT%.
if "%RESULT%"=="0" echo Ruibo certificate removal completed.
pause
exit /b %RESULT%
