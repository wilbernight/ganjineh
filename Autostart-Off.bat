@echo off
rem Ganjineh: stop starting with Windows and forget the saved password.
rem Close the running server window first.
cd /d "%~dp0"
LanFileServer.exe -autostart off
