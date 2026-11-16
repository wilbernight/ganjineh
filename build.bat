@echo off
rem Ganjineh build (needs Go 1.27.3 or newer: https://go.dev/dl/)
cd /d "%~dp0"
if not exist out mkdir out
set CGO_ENABLED=0
go build -mod=vendor -trimpath -ldflags "-s -w" -o out\LanFileServer.exe . || goto err
if exist out\LanUploader.exe del /q out\LanUploader.exe
copy /y README.txt out\ >nul
copy /y Send-Files.url out\ >nul
copy /y Autostart-*.bat out\ >nul
copy /y Uploader.bat out\ >nul
echo.
echo Done: out\LanFileServer.exe  (uploader: LanFileServer.exe -upload, or Uploader.bat)
pause
exit /b 0
:err
echo Build failed.
pause
exit /b 1
