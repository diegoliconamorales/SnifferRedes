@echo off
rem Busca Python 3.8 o superior y guarda el comando en la variable PY.
rem Primero prueba el lanzador "py -3", porque en equipos que tambien tienen
rem Python 2.7 el comando "python" puede abrir la version antigua.
set "PY="
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if not errorlevel 1 set "PY=py -3"
if defined PY exit /b 0
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if not errorlevel 1 set "PY=python"
if defined PY exit /b 0
echo No se encontro Python 3.8 o superior.
echo Version que responde al comando python:
python --version 2>&1
echo.
echo Instala Python 3 desde https://www.python.org/downloads/ marcando
echo "Add python.exe to PATH" y despues ejecuta instalar_dependencias.bat.
exit /b 1
