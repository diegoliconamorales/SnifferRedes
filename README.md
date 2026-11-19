# Analizador de Tráfico de Red (Sniffer)

Proyecto 3 de **Redes de Computadoras** (ESCOM-IPN, grupo 5CM3).
Aplicación de escritorio en Python que captura y analiza paquetes en tiempo real
con **Scapy** y una interfaz gráfica en **Tkinter**. Parte del programa base
`sniffer.py` (copia original en `base/`) y le agrega:

1. **Filtros BPF** predefinidos o escritos a mano, validados antes de capturar.
2. **Capa de aplicación:** dominios consultados por DNS, peticiones y respuestas HTTP,
   e identificación de conexiones HTTPS (TLS) con el nombre del servidor (SNI), sin
   descifrar el contenido. También reconoce DHCP, QUIC, mDNS, LLMNR, SSDP y NTP.
3. **Almacenamiento en PCAP** (o PCAPNG), para abrir las capturas en Wireshark.
4. **Interfaz gráfica** con las cuatro secciones de la guía: configuración, listado
   de paquetes, información detallada por capas y carga útil en hexadecimal y ASCII.

---

## 1. Instalación (Windows)

1. **Python 3.8 o superior** desde <https://www.python.org/downloads/>. En el
   instalador marcar *"Add python.exe to PATH"*. Tkinter ya viene incluido.
2. **Npcap** desde <https://npcap.com/#download>. Dejar marcada la opción
   *"Install Npcap in WinPcap API-compatible Mode"*. Si ya tienen Wireshark,
   Npcap ya está instalado.
3. **Scapy:** doble clic en `instalar_dependencias.bat`, o en una terminal:
   ```
   pip install -r requirements.txt
   ```
4. **Wireshark** (para validar los PCAP) desde <https://www.wireshark.org/download.html>.

Los archivos `.bat` buscan primero el lanzador `py -3` y después `python`, y solo
aceptan Python 3.8 o superior. Esto evita que se use Python 2.7 en equipos que lo
tienen instalado (en ese caso `python main.py` termina con un mensaje que pide
Python 3). Desde una terminal, en esos equipos, usar `py -3 main.py` y
`py -3 -m pip install -r requirements.txt`.

En Linux basta con `pip install scapy` (y `sudo apt install python3-tk` si falta Tkinter).

## 2. Ejecución

| Sistema | Interfaz gráfica | Consola |
|---|---|---|
| Windows | doble clic en `ejecutar.bat` (pide permisos de Administrador) | `ejecutar_consola.bat` |
| Linux | `./ejecutar.sh` (usa `sudo`) | `sudo python3 main.py --consola` |
| Cualquiera | `python main.py` | `python main.py --consola` |

La captura necesita privilegios: en Windows depende de cómo se instaló Npcap (si se
marcó *"Restrict Npcap driver's access to Administrators only"* es obligatorio abrir
como Administrador); en Linux siempre se necesita `sudo`.

Versión de consola (mismo análisis, formato del `sniffer.py` original):
```
python main.py --interfaces                         lista las interfaces
python main.py --consola -f "udp port 53" -c 20     20 paquetes DNS
python main.py --consola -i "Wi-Fi" -f icmp -w ping.pcap
```

## 3. Uso rápido

1. **Interfaz de red:** elegir la tarjeta (normalmente *Wi-Fi* o *Ethernet*; la que
   tiene la ruta por defecto aparece primero, marcada como *[predeterminada]*).
2. **Filtro BPF:** elegir uno de la lista o escribir la expresión. A la derecha se
   indica si la sintaxis es válida. Vacío = todo el tráfico.
3. **Iniciar captura.** Los paquetes aparecen en la tabla conforme llegan; el indicador
   cambia a *Capturando* y el contador aumenta.
4. **Detener.** Al seleccionar un paquete se muestran sus capas en *Información
   detallada* y sus bytes en *Carga útil*. Al seleccionar una capa se resaltan sus
   bytes; la carga útil siempre aparece en amarillo.
5. **Guardar PCAP** guarda todos los paquetes de la sesión (`.pcap` o `.pcapng`).
   **Abrir PCAP** carga una captura guardada con el mismo análisis.

El **filtro de visualización** (arriba de la tabla) oculta filas de paquetes ya
capturados; a diferencia del filtro BPF, no cambia lo que se captura ni lo que se guarda.

Para generar tráfico de prueba: `generar_trafico.bat` (ping, nslookup, petición
HTTP a httpforever.com y conexión HTTPS a www.escom.ipn.mx).

Si `ejecutar.bat` no abre la ventana: extraer primero el ZIP completo (no ejecutarlo
desde dentro del ZIP), confirmar que Python y las dependencias estén instalados y
revisar el mensaje que el `.bat` deja en pantalla.

## 4. Filtros BPF de la guía

| Filtro | Expresión | Función |
|---|---|---|
| HTTP | `tcp port 80` | Tráfico TCP del puerto 80 |
| HTTPS | `tcp port 443` | Tráfico TCP del puerto 443 |
| DNS | `udp port 53` | Consultas y respuestas DNS |
| ICMP | `icmp` | Mensajes ICMP |
| TCP | `tcp` | Paquetes TCP |
| UDP | `udp` | Paquetes UDP |
| IP específica | `host <IP de la interfaz>` | Tráfico de o hacia una IP |
| Red específica | `net <red>/24` | Tráfico de una red (ajustar el prefijo a la red real) |
| Puerto específico | `port 443` | TCP o UDP en ese puerto |

## 5. Estructura del código

```
SnifferRedes/
├── main.py                  Punto de entrada: revisa Scapy/Npcap y abre la interfaz
├── analizador/
│   ├── analisis.py          Capas 2-4 (Ethernet, IPv4/IPv6, ARP, TCP, UDP, ICMP)
│   ├── aplicacion.py        Capa 7 (DNS, HTTP, TLS/HTTPS, DHCP, QUIC...)
│   ├── filtros.py           Filtros BPF predefinidos y validación de sintaxis
│   ├── captura.py           AsyncSniffer, cola hacia la GUI y PCAP temporal
│   ├── volcado.py           Volcado hexadecimal y ASCII
│   └── modelos.py           Estructuras de datos compartidas
├── interfaz/
│   ├── gui.py               Ventana Tkinter (4 secciones)
│   └── consola.py           Versión de consola
├── tests/                   Pruebas unitarias (python -m unittest discover -s tests -v)
├── base/sniffer.py          Programa base entregado por el profesor
└── *.bat / ejecutar.sh      Scripts de instalación, ejecución y tráfico de prueba
```

### Cómo funciona la captura sin congelar la ventana

```
[Hilo de captura: AsyncSniffer]                [Hilo principal: Tkinter]
 Npcap entrega el paquete (ya filtrado por BPF)
   ├─ se escribe en un PCAP temporal (disco)
   ├─ se analiza (resumen para la tabla)
   └─ cola.put(registro) ─────────────────────►  root.after(100 ms) saca hasta
                                                 400 registros y los agrega a la tabla
```

Para no consumir memoria en capturas largas: `store=False` (Scapy no guarda la lista
de paquetes), cada paquete se escribe de inmediato en disco, en memoria solo se
conservan los bytes de los últimos 10 000 paquetes (no el objeto de Scapy) y la tabla
descarta las filas más antiguas, que siguen guardadas en el PCAP.

## 6. Pruebas unitarias

```
python -m unittest discover -s tests -v
```
o doble clic en `ejecutar_pruebas.bat`. Las pruebas construyen paquetes con Scapy
(no necesitan red ni permisos) y verifican el análisis de cada capa, DNS, HTTP, TLS
(incluido un Client Hello dividido en dos segmentos), DHCP, la validación de filtros,
el volcado hexadecimal y el guardado en PCAP/PCAPNG.

## 7. Integrantes

| Integrante | Módulos del código |
|---|---|
| Cruz Torres Frida Paola | `analisis.py`, `volcado.py` |
| Licona Morales Diego | `captura.py`, `main.py` |
| López Castro Melissa | `filtros.py`, `tests/` |
| Núñez Moreno Ángel Gabriel | `aplicacion.py`, `consola.py`, scripts `.bat`, README |
| Palestina Jaime Gael Rodrigo | `gui.py`, `modelos.py` |

Profesor: Juan Jesús Alcaraz Torres · Redes de Computadoras · ESCOM-IPN.
