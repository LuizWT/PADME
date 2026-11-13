@echo off
rem Instalador do Padme para Windows: de dois cliques neste arquivo.
rem Remover (mantem config e banco): install.bat -Uninstall
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
set RC=%ERRORLEVEL%
echo.
if not defined PADME_NO_PAUSE pause
exit /b %RC%
