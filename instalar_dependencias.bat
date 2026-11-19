@echo off
chcp 65001 >nul
echo ============================================================
echo  Analizador de Trafico de Red - Instalacion de dependencias
echo ============================================================
echo.
cd /d "%~dp0"
call "%~dp0buscar_python.bat"
if not defined PY (
    pause
    exit /b 1
)
echo Se usara: %PY%
%PY% --version
echo.
%PY% -m pip install --upgrade pip
%PY% -m pip install -r requirements.txt
echo.
echo Recuerda instalar Npcap desde https://npcap.com (opcion "WinPcap API-compatible Mode").
pause
