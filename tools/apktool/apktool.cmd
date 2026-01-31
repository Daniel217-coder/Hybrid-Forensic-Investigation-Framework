@echo off
REM Minimal apktool wrapper for Windows (no pause)
setlocal
set DIR=%~dp0
java -jar "%DIR%apktool.jar" %*
