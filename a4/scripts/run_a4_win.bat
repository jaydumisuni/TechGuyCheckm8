@echo off
setlocal

set "CACHE=C:\TechGuyTools\assets"

set "IREC=%CACHE%\tools\win\irecovery.exe"
set "P1=%CACHE%\a4\payloads\a4_stage1.bin"

if not exist "%IREC%" (
    echo [ERROR] Missing irecovery.exe
    exit /b 2
)
if not exist "%P1%" (
    echo [ERROR] Missing stage1 payload
    exit /b 2
)

echo Sending stage1...
"%IREC%" -f "%P1%"
if errorlevel 1 exit /b 1

echo Done.
exit /b 0
