@echo off
rem Send files/folders to the server. Drag them onto this file, or double-click it.
"%~dp0LanFileServer.exe" -upload %*
