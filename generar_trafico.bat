@echo off
chcp 65001 >nul
rem Genera trafico controlado para las pruebas del sniffer.
echo [ICMP] ping a 8.8.8.8
ping -n 4 8.8.8.8
echo.
echo [DNS] consultas con nslookup
nslookup www.escom.ipn.mx
nslookup www.ipn.mx
echo.
echo [HTTP] peticion sin cifrar a httpforever.com
curl -s -o nul -w "Codigo HTTP: %%{http_code}\n" http://httpforever.com/
echo.
echo [HTTPS] conexion cifrada a www.escom.ipn.mx
curl -s -o nul -w "Codigo HTTP: %%{http_code}\n" https://www.escom.ipn.mx/
echo.
pause
