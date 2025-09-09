@echo off
setlocal

set "CACHE=C:\TechGuyTools\assets"

set "IREC=%CACHE%\tools\win\irecovery.exe"
set "P1=%CACHE%\a7_a11\payloads\a7_stage1.bin"
set "P2=%CACHE%\a7_a11\payloads\a7_stage2.bin"

if not exist "%IREC%" (
    echo [ERROR] Missing irecovery.exe at %IREC%
    exit /b 2
)
if not exist "%P1%" (
    echo [ERROR] Missing stage1 payload: %P1%
    exit /b 2
)
if not exist "%P2%" (
    echo [ERROR] Missing stage2 payload: %P2%
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
