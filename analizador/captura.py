"""
captura.py
----------
Motor de captura (Módulo 1) y almacenamiento en PCAP.

Funcionamiento:

    [Hilo de captura - AsyncSniffer]               [Hilo principal - Tkinter]
     recibe un paquete del controlador
     (ya filtrado por BPF)
        │
        ├─ lo escribe en un PCAP temporal (disco)
        ├─ lo analiza (construir_registro)
        └─ cola.put(registro) ───────────────────►  root.after() saca los
                                                    registros de la cola y
                                                    los agrega a la tabla

Para no acumular paquetes en memoria:
    * sniff/AsyncSniffer se usa con store=False: Scapy no guarda la lista.
    * Cada paquete se escribe de inmediato en un archivo PCAP temporal; al
      pulsar "Guardar PCAP" solo se copia ese archivo.
    * En memoria se conserva únicamente los bytes de los últimos paquetes
      (la interfaz limita cuántos muestra), nunca el objeto de Scapy.
"""

from __future__ import annotations

import os
import queue
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import List, Optional

from scapy.config import conf
from scapy.sendrecv import AsyncSniffer
from scapy.utils import PcapReader, PcapWriter

from analizador.analisis import construir_registro
from analizador.aplicacion import AnalizadorAplicacion
from analizador.modelos import RegistroPaquete

try:  # PCAPNG: disponible en Scapy 2.5 o superior
    from scapy.utils import PcapNgWriter
except ImportError:  # pragma: no cover
    PcapNgWriter = None

# Estados del motor
DETENIDO, CAPTURANDO, DETENIENDO, LEYENDO = "detenido", "capturando", "deteniendo", "leyendo"


class ErrorCaptura(Exception):
    """Error que se le muestra al usuario con una explicación."""


# ---------------------------------------------------------------------------
# Interfaces de red
# ---------------------------------------------------------------------------
@dataclass
class InterfazRed:
    nombre: str
    descripcion: str
    ip: str
    mac: str
    objeto: object            # NetworkInterface de Scapy (se pasa a AsyncSniffer)
    predeterminada: bool

    def etiqueta(self) -> str:
        partes = [self.nombre]
        if self.descripcion and self.descripcion != self.nombre:
            partes.append(self.descripcion)
        partes.append(self.ip or "sin IPv4")
        texto = " — ".join(partes)
        return texto + ("  [predeterminada]" if self.predeterminada else "")


def listar_interfaces() -> List[InterfazRed]:
    """
    Interfaces que Scapy puede usar. En Windows los nombres vienen de Npcap
    (Wi-Fi, Ethernet...); en Linux son eth0, wlan0, lo...
    La interfaz de la ruta por defecto aparece primero.
    """
    try:
        conf.ifaces.reload()
    except Exception:
        pass
    predeterminada = conf.iface
    interfaces = []
    for iface in conf.ifaces.values():
        try:
            if not iface.is_valid():
                continue
        except Exception:
            continue
        interfaces.append(InterfazRed(
            nombre=iface.name or str(iface), descripcion=iface.description or "",
            ip=iface.ip or "", mac=iface.mac or "", objeto=iface,
            predeterminada=(iface == predeterminada)))
    interfaces.sort(key=lambda i: (not i.predeterminada, not i.ip, i.nombre.lower()))
    return interfaces


# ---------------------------------------------------------------------------
# Motor de captura
# ---------------------------------------------------------------------------
class MotorCaptura:
    """
    Controla una sesión de captura. La interfaz gráfica solo llama a
    iniciar(), detener(), abrir_pcap() y guardar_pcap(), y lee la cola.

    Mensajes que se ponen en la cola:
        ("iniciado", None)           la interfaz ya está abierta y escuchando
        ("paquete", RegistroPaquete)
        ("fin", None | "mensaje de error")
    """

    def __init__(self) -> None:
        self.cola: "queue.Queue[tuple]" = queue.Queue()
        self.estado = DETENIDO
        self.total = 0
        self.inicio_captura: Optional[float] = None
        self.ruta_temporal: Optional[str] = None
        self._sniffer: Optional[AsyncSniffer] = None
        self._escritor: Optional[PcapWriter] = None
        self._analizador = AnalizadorAplicacion()
        self._t0: Optional[float] = None
        self._candado = threading.Lock()
        self._errores_escritura = 0

    # -- sesión ------------------------------------------------------------
    def _nueva_sesion(self) -> None:
        self.descartar()
        descriptor, self.ruta_temporal = tempfile.mkstemp(prefix="sniffer_", suffix=".pcap")
        os.close(descriptor)
        self.total = 0
        self._t0 = None
        self._errores_escritura = 0
        self._analizador.reiniciar()
        self.cola = queue.Queue()

    def descartar(self) -> None:
        """Borra el archivo temporal de la sesión anterior."""
        self._cerrar_escritor()
        if self.ruta_temporal and os.path.exists(self.ruta_temporal):
            try:
                os.remove(self.ruta_temporal)
            except OSError:
                pass
        self.ruta_temporal = None
        self.total = 0

    # -- captura en vivo ---------------------------------------------------
    def iniciar(self, interfaz: Optional[InterfazRed], filtro: str = "",
                promiscuo: bool = True) -> None:
        if self.estado != DETENIDO:
            raise ErrorCaptura("Ya hay una captura en curso.")
        self._nueva_sesion()
        argumentos = dict(prn=self._procesar, store=False, promisc=promiscuo,
                          started_callback=lambda: self.cola.put(("iniciado", None)))
        if interfaz is not None:
            argumentos["iface"] = interfaz.objeto
        if filtro.strip():
            argumentos["filter"] = filtro.strip()
        self._sniffer = AsyncSniffer(**argumentos)
        self.estado = CAPTURANDO
        self.inicio_captura = time.time()
        self._sniffer.start()

    def _procesar(self, paquete) -> None:
        """Se ejecuta en el hilo de captura por cada paquete (parámetro prn)."""
        try:
            with self._candado:
                self.total += 1
                numero = self.total
                if self._t0 is None:
                    self._t0 = float(paquete.time)
                if self._escritor is None:
                    self._escritor = PcapWriter(self.ruta_temporal, sync=True)
                try:
                    self._escritor.write(paquete)
                except Exception:
                    self._errores_escritura += 1
            registro = construir_registro(paquete, numero, self._t0, self._analizador)
            self.cola.put(("paquete", registro))
        except Exception as error:  # un paquete raro nunca debe detener la captura
            self.cola.put(("aviso", f"No se pudo analizar un paquete: {error}"))

    def detener(self) -> None:
        """
        Detiene la captura sin congelar la ventana: la espera a que termine el
        hilo de Scapy se hace en otro hilo, y al final se avisa por la cola.
        """
        if self.estado != CAPTURANDO or self._sniffer is None:
            return
        self.estado = DETENIENDO
        threading.Thread(target=self._detener_en_segundo_plano, daemon=True,
                         name="DetenerCaptura").start()

    def _detener_en_segundo_plano(self) -> None:
        error = None
        sniffer = self._sniffer
        try:
            if sniffer.running:
                sniffer.stop(join=True)
            else:
                sniffer.join(timeout=2)
        except Exception as ex:
            error = self.explicar_error(ex)
        self._finalizar(error)

    def revisar(self) -> None:
        """
        La interfaz lo llama periódicamente. Si el hilo de captura terminó por
        sí solo (permisos, interfaz desconectada, filtro inválido), se avisa.
        """
        if self.estado != CAPTURANDO or self._sniffer is None:
            return
        hilo = self._sniffer.thread
        if hilo is not None and not hilo.is_alive():
            error = self._sniffer.exception
            self._finalizar(self.explicar_error(error) if error else
                            "La captura terminó inesperadamente.")

    def _finalizar(self, error: Optional[str]) -> None:
        with self._candado:
            self._cerrar_escritor()
        self._sniffer = None
        self.estado = DETENIDO
        self.cola.put(("fin", error))

    def _cerrar_escritor(self) -> None:
        if self._escritor is not None:
            try:
                self._escritor.close()
            except Exception:
                pass
            self._escritor = None

    # -- lectura de un PCAP existente ---------------------------------------
    def abrir_pcap(self, ruta: str) -> None:
        """Carga un archivo PCAP/PCAPNG con el mismo análisis que la captura en vivo."""
        if self.estado != DETENIDO:
            raise ErrorCaptura("Detén la captura antes de abrir un archivo.")
        self._nueva_sesion()
        shutil.copyfile(ruta, self.ruta_temporal)
        self.estado = LEYENDO
        self.inicio_captura = time.time()
        threading.Thread(target=self._leer_pcap, args=(ruta,), daemon=True,
                         name="LeerPCAP").start()

    def _leer_pcap(self, ruta: str) -> None:
        error = None
        try:
            with PcapReader(ruta) as lector:      # lee un paquete a la vez (no carga todo)
                for paquete in lector:
                    if self.estado != LEYENDO:
                        break
                    self.total += 1
                    if self._t0 is None:
                        self._t0 = float(paquete.time)
                    registro = construir_registro(paquete, self.total, self._t0, self._analizador)
                    self.cola.put(("paquete", registro))
                    while self.cola.qsize() > 2000 and self.estado == LEYENDO:
                        time.sleep(0.05)          # espera a que la interfaz avance
        except Exception as ex:
            error = f"No se pudo leer el archivo: {ex}"
        self.estado = DETENIDO
        self.cola.put(("fin", error))

    # -- almacenamiento ----------------------------------------------------
    def guardar_pcap(self, destino: str) -> int:
        """
        Guarda todos los paquetes de la sesión. Con extensión .pcapng se
        convierte al formato PCAP Next Generation; con .pcap se copia el
        archivo temporal tal cual. Regresa el número de paquetes guardados.
        """
        if self.estado in (CAPTURANDO, DETENIENDO):
            raise ErrorCaptura("Detén la captura antes de guardar.")
        if not self.ruta_temporal or self.total == 0 or not os.path.exists(self.ruta_temporal):
            raise ErrorCaptura("No hay paquetes para guardar.")
        if destino.lower().endswith(".pcapng"):
            if PcapNgWriter is None:
                raise ErrorCaptura("Esta versión de Scapy no permite escribir PCAPNG.")
            guardados = 0
            with PcapReader(self.ruta_temporal) as lector:
                escritor = PcapNgWriter(destino)
                try:
                    for paquete in lector:
                        escritor.write(paquete)
                        guardados += 1
                finally:
                    escritor.close()
            return guardados
        shutil.copyfile(self.ruta_temporal, destino)
        return self.total

    # -- mensajes de error -------------------------------------------------
    @staticmethod
    def explicar_error(error: BaseException) -> str:
        texto = str(error) or type(error).__name__
        bajo = texto.lower()
        if isinstance(error, PermissionError) or "permission" in bajo or "not permitted" in bajo \
                or "access is denied" in bajo or "acceso denegado" in bajo:
            return ("No hay permisos para capturar paquetes.\n\n"
                    "Windows: ejecuta el programa como Administrador (o reinstala Npcap sin "
                    "la opción 'Restrict Npcap driver's access to Administrators only').\n"
                    "Linux: ejecuta con sudo.\n\nDetalle: " + texto)
        if "filter" in bajo or "syntax" in bajo:
            return "El filtro BPF no es válido.\n\nDetalle: " + texto
        if "npcap" in bajo or "winpcap" in bajo or "libpcap" in bajo:
            return ("No se encontró Npcap. Instálalo desde https://npcap.com y vuelve a "
                    "abrir el programa.\n\nDetalle: " + texto)
        return ("La captura se detuvo por un error.\n\nSi usas Wi-Fi, prueba desmarcar «Modo "
                "promiscuo» o elegir otra interfaz.\n\nDetalle: " + texto)
