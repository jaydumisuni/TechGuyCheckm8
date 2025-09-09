@echo off
setlocal

REM Path where TechGuy Doctor puts all assets
set "CACHE=C:\TechGuyTools\assets"

set "IREC=%CACHE%\tools\win\irecovery.exe"
set "P1=%CACHE%\a6\payloads\a6_stage1.bin"
set "P2=%CACHE%\a6\payloads\a6_stage2.bin"

if not exist "%IREC%" (
    echo [ERROR] Missing irecovery.exe at %IREC%
    exit /b 2
)
if not exist "%P1%" (
    echo [ERROR] Missing payload stage1: %P1%
    exit /b 2
)
if not exist "%P2%" (
    echo [ERROR] Missing payload stage2: %P2%
    exit /b 2
)

echo Sending stage1...
"%IREC%" -f "%P1%"
if errorlevel 1 exit /b 1

echo Sending stage2...
"%IREC%" -f "%P2%"
if errorlevel 1 exit /b 1

echo Done.
exit /b 0
