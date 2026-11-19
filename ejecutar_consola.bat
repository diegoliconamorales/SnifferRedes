@echo off
chcp 65001 >nul
rem Version de consola. Ejemplo: ejecutar_consola.bat -f "udp port 53" -c 20 -w dns.pcap
cd /d "%~dp0"
call "%~dp0buscar_python.bat"
if not defined PY (
    pause
    exit /b 1
)
%PY% main.py --consola %*
pause
