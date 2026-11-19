"""
filtros.py
----------
Filtros BPF (Berkeley Packet Filter) del Módulo 2.

Un filtro BPF es una expresión de texto ("tcp port 443") que libpcap/Npcap
traduce a un pequeño programa de instrucciones. Ese programa se carga en el
controlador de captura y se ejecuta por cada paquete ANTES de entregarlo a
Python: los paquetes que no cumplen la condición se descartan en el
controlador y nunca llegan al programa.

Aquí están los filtros mínimos que pide la guía y la validación de sintaxis
que se hace antes de iniciar la captura.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import List, Optional, Tuple

DLT_EN10MB = 1  # tipo de enlace Ethernet (Npcap también lo usa para Wi-Fi)


@dataclass(frozen=True)
class FiltroPredefinido:
    nombre: str
    expresion: str
    funcion: str


def filtros_predefinidos(ip_local: Optional[str] = None) -> List[FiltroPredefinido]:
    """
    Filtros de la tabla del Módulo 2. Para "IP específica" y "Red específica"
    se usa la IP de la interfaz seleccionada (si se conoce) en lugar del
    ejemplo 192.168.1.10.
    """
    ip = ip_local or "192.168.1.10"
    try:
        red = ipaddress.ip_interface(f"{ip}/24").network
    except ValueError:
        ip, red = "192.168.1.10", ipaddress.ip_network("192.168.1.0/24")
    return [
        FiltroPredefinido("Sin filtro (todo el tráfico)", "", "Captura todos los paquetes"),
        FiltroPredefinido("HTTP", "tcp port 80", "Tráfico TCP asociado al puerto 80"),
        FiltroPredefinido("HTTPS", "tcp port 443", "Tráfico TCP asociado al puerto 443"),
        FiltroPredefinido("DNS", "udp port 53", "Consultas y respuestas DNS sobre UDP"),
        FiltroPredefinido("ICMP", "icmp", "Mensajes ICMP (ping, errores)"),
        FiltroPredefinido("TCP", "tcp", "Solo paquetes TCP"),
        FiltroPredefinido("UDP", "udp", "Solo paquetes UDP"),
        FiltroPredefinido("IP específica", f"host {ip}", "Tráfico de o hacia una IP"),
        FiltroPredefinido("Red específica", f"net {red}", "Tráfico de una red"),
        FiltroPredefinido("Puerto específico", "port 443", "Tráfico TCP o UDP de un puerto"),
    ]


def validar_filtro(expresion: str) -> Tuple[Optional[bool], str]:
    """
    Pide a libpcap (Npcap en Windows) que compile la expresión, sin abrir
    ninguna interfaz. Regresa:
        (True,  mensaje)  -> la sintaxis es correcta
        (False, mensaje)  -> la sintaxis es incorrecta (mensaje de libpcap)
        (None,  mensaje)  -> no se pudo verificar (libpcap no disponible)
    """
    expresion = expresion.strip()
    if not expresion:
        return True, "Sin filtro: se capturará todo el tráfico"
    try:
        from scapy.arch.common import compile_filter
        from scapy.error import Scapy_Exception
    except ImportError:
        return None, "No se pudo verificar el filtro"
    try:
        programa = compile_filter(expresion, linktype=DLT_EN10MB)
    except ImportError:
        return None, "No se pudo verificar: libpcap/Npcap no está disponible"
    except Scapy_Exception as error:
        return False, _mensaje_libpcap(str(error))
    except Exception as error:  # cualquier otro fallo de la biblioteca
        return None, f"No se pudo verificar el filtro ({error})"
    # el número de instrucciones se lee ANTES de liberar el programa:
    # pcap_freecode() pone bf_len en 0
    instrucciones = getattr(programa, "bf_len", 0)
    try:  # liberar el programa compilado (no existe en versiones antiguas)
        from scapy.arch.common import free_filter
        free_filter(programa)
    except Exception:
        pass
    return True, f"Filtro válido ({instrucciones} instrucciones BPF)"


def _mensaje_libpcap(texto: str) -> str:
    """Deja solo la explicación de libpcap (lo que va entre paréntesis)."""
    if "(" in texto and texto.endswith(")"):
        texto = texto[texto.rfind("(") + 1:-1]
    return f"Sintaxis BPF inválida: {texto}"
