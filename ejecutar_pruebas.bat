@echo off
chcp 65001 >nul
cd /d "%~dp0"
call "%~dp0buscar_python.bat"
if not defined PY (
    pause
    exit /b 1
)
%PY% -m unittest discover -s tests -v
pause
