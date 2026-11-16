@echo off
rem Ganjineh: start with Windows for this user (no admin).
rem Close the running server window first.
cd /d "%~dp0"
LanFileServer.exe -autostart on
