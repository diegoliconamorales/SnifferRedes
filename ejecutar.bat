@echo off
chcp 65001 >nul
rem Abre el analizador como Administrador (Npcap lo requiere para capturar).
cd /d "%~dp0"

if not exist "%~dp0main.py" (
    echo No se encontro main.py junto a este archivo.
    echo Si abriste el .bat desde dentro del ZIP, primero extrae la carpeta completa
    echo ^(clic derecho en el ZIP ^> Extraer todo^) y ejecuta el .bat desde ahi.
    echo.
    pause
    exit /b 1
)

net session >nul 2>&1
if %errorlevel% neq 0 (
    rem Se vuelve a abrir este mismo .bat con permisos de Administrador.
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

call "%~dp0buscar_python.bat"
if not defined PY (
    echo.
    pause
    exit /b 1
)

%PY% main.py
if %errorlevel% neq 0 (
    echo.
    echo El analizador se cerro con un error ^(codigo %errorlevel%^). Revisa el mensaje de arriba.
    pause
)
