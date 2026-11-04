@echo off
REM recover_safemode.bat — NT334 Screen Locker Recovery
REM Run in Safe Mode with Administrator CMD to clean all Reveton artifacts.
REM
REM Usage:
REM   1. Trigger Windows Recovery: force-shutdown VM 3 times during boot
REM   2. Troubleshoot > Advanced Options > Startup Settings > Restart > F4 (Safe Mode)
REM   3. Open CMD as Administrator
REM   4. Run: recover_safemode.bat
REM      Or run commands manually if .bat not available (copy from below)
REM
REM Note: reg.exe is blocked by DisableRegistryTools policy.
REM       Use PowerShell commands instead (see recover_safemode.ps1).

echo ============================================
echo   NT334 Screen Locker Recovery Tool
echo   Run in Safe Mode as Administrator
echo ============================================
echo.

REM --- Step 1: Delete Startup persistence ---
echo [*] Step 1 - Removing Startup shortcuts...
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\runctf.lnk" 2>nul
if %errorlevel% equ 0 (echo     [+] Deleted runctf.lnk) else (echo     [-] runctf.lnk not found)
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\ctfmon32.lnk" 2>nul
if %errorlevel% equ 0 (echo     [+] Deleted ctfmon32.lnk) else (echo     [-] ctfmon32.lnk not found)

REM --- Step 2: Delete dropped files in AppData ---
echo.
echo [*] Step 2 - Removing AppData artifacts...
echo     Scanning for .pad files...
for %%f in ("%APPDATA%\*.pad") do (
    echo     [+] Deleting %%~nxf
    del "%%f"
)
echo     Scanning for .js loader files...
for %%f in ("%APPDATA%\*.js") do (
    echo     [+] Deleting %%~nxf
    del "%%f"
)

REM --- Step 3: Delete dropped files in Temp ---
echo.
echo [*] Step 3 - Removing Temp artifacts...
echo     Scanning for suspicious DLLs...
for %%f in ("%LOCALAPPDATA%\Temp\*.dll") do (
    echo     [+] Deleting %%~nxf
    del "%%f"
)
echo     Scanning for guard EXEs...
for %%f in ("%LOCALAPPDATA%\Temp\*_guard.exe") do (
    echo     [+] Deleting %%~nxf
    del "%%f"
)

REM --- Step 4: Fix registry (requires PowerShell) ---
echo.
echo [*] Step 4 - Fixing registry...
echo     NOTE: reg.exe is blocked by DisableRegistryTools.
echo           Using PowerShell to bypass...
powershell -NoProfile -Command "Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Recurse -Force -ErrorAction SilentlyContinue; Write-Host '    [+] Removed HKCU Policies\System'"
powershell -NoProfile -Command "Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Recurse -Force -ErrorAction SilentlyContinue; Write-Host '    [+] Removed HKCU Policies\Explorer'"
powershell -NoProfile -Command "Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Recurse -Force -ErrorAction SilentlyContinue; Write-Host '    [+] Removed HKLM Defender policies'"

REM --- Step 5: Restart ---
echo.
echo ============================================
echo   Recovery complete!
echo   Restart to verify: shutdown /r /t 0
echo ============================================
echo.
set /p RESTART="Restart now? (Y/N): "
if /i "%RESTART%"=="Y" shutdown /r /t 0
