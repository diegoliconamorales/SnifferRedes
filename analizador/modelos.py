"""
modelos.py
----------
Estructuras de datos que comparten todos los módulos del analizador.

    Campo               -> un campo de un encabezado (nombre y valor)
    Seccion             -> una capa del paquete (Ethernet, IPv4, TCP...)
    ResultadoAplicacion -> lo que se identificó en la capa de aplicación
    Resumen             -> una fila de la tabla de paquetes
    RegistroPaquete     -> lo que se guarda en memoria por cada paquete
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Campo:
    """Campo de un encabezado. 'hijos' permite anidar (p. ej. respuestas DNS)."""
    nombre: str
    valor: str = ""
    hijos: List["Campo"] = field(default_factory=list)
    expandido: bool = True       # si sus hijos se muestran abiertos en el panel


@dataclass
class Seccion:
    """
    Una capa del paquete, tal como se muestra en el panel de detalle.
    inicio y longitud indican qué bytes de la trama ocupa la capa, para
    poder resaltarlos en el panel hexadecimal al seleccionarla.
    """
    titulo: str                  # nombre corto de la capa: "Ethernet II", "IPv4"...
    campos: List[Campo]
    inicio: int = 0
    longitud: int = 0
    resumen: str = ""            # datos principales: "Origen: ..., Destino: ..."


@dataclass
class ResultadoAplicacion:
    """Información extraída de la capa de aplicación (DNS, HTTP, TLS...)."""
    protocolo: str               # nombre corto: "DNS", "HTTP", "TLS (HTTPS)"...
    info: str                    # texto para la columna Información
    titulo: str = ""             # nombre de la capa en el panel de detalle
    campos: List[Campo] = field(default_factory=list)


@dataclass
class Resumen:
    """Columnas de la tabla de paquetes (Módulo 1 de la guía)."""
    mac_origen: str = "—"
    mac_destino: str = "—"
    ip_origen: str = "—"
    ip_destino: str = "—"
    protocolo: str = "Otro"
    puerto_origen: str = ""
    puerto_destino: str = ""
    longitud: int = 0
    aplicacion: str = ""
    info: str = ""
    etiqueta: str = "otro"       # define el color de la fila en la tabla


class RegistroPaquete:
    """
    Lo único que se conserva en memoria por cada paquete capturado.

    No se guarda el objeto de Scapy (que ocupa mucha memoria), sino los bytes
    originales de la trama. Cuando el usuario selecciona el paquete en la
    tabla, el paquete se reconstruye a partir de esos bytes con clase_enlace.
    __slots__ evita el diccionario interno de cada objeto y reduce memoria.
    """

    __slots__ = ("numero", "tiempo", "tiempo_relativo", "datos", "clase_enlace",
                 "resumen", "aplicacion")

    def __init__(self, numero: int, tiempo: float, tiempo_relativo: float, datos: bytes,
                 clase_enlace: type, resumen: Resumen,
                 aplicacion: Optional[ResultadoAplicacion]) -> None:
        self.numero = numero
        self.tiempo = tiempo
        self.tiempo_relativo = tiempo_relativo
        self.datos = datos
        self.clase_enlace = clase_enlace
        self.resumen = resumen
        self.aplicacion = aplicacion

    def fila(self) -> tuple:
        """Valores de la fila en el mismo orden que las columnas de la tabla."""
        r = self.resumen
        return (self.numero, f"{self.tiempo_relativo:.6f}", r.mac_origen, r.mac_destino,
                r.ip_origen, r.ip_destino, r.protocolo, r.puerto_origen, r.puerto_destino,
                r.longitud, r.aplicacion, r.info)
