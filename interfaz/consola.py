"""
consola.py
----------
Versión de consola del analizador. Conserva el formato de salida del programa
base sniffer.py, pero ya usa los módulos nuevos: filtro BPF, capa de
aplicación y guardado en PCAP.

    python main.py --consola                       captura en la interfaz por defecto
    python main.py --consola -f "udp port 53"      con filtro BPF
    python main.py --consola -i "Wi-Fi" -c 20 -w prueba.pcap
    python main.py --interfaces                    lista las interfaces disponibles
"""

from __future__ import annotations

import argparse
from typing import List, Optional

from scapy.sendrecv import sniff
from scapy.utils import PcapWriter

from analizador import analisis, captura, filtros
from analizador.aplicacion import AnalizadorAplicacion

ANCHO = 65


def imprimir_seccion(titulo: str, campos, sangria: str = "  ") -> None:
    print(f"\n[{titulo}]")
    for campo in campos:
        print(f"{sangria}{campo.nombre:<34}: {campo.valor}")
        if campo.hijos:
            for hijo in campo.hijos:
                print(f"{sangria}    - {hijo.nombre}: {hijo.valor}")


class SnifferConsola:
    def __init__(self, archivo: Optional[str] = None) -> None:
        self.numero = 0
        self.t0: Optional[float] = None
        self.aplicacion = AnalizadorAplicacion()
        self.escritor = PcapWriter(archivo, sync=True) if archivo else None

    def analizar_paquete(self, paquete) -> None:
        """Equivalente a analizar_paquete() de sniffer.py, ahora con capa de aplicación."""
        self.numero += 1
        if self.t0 is None:
            self.t0 = float(paquete.time)
        if self.escritor:
            self.escritor.write(paquete)
        registro = analisis.construir_registro(paquete, self.numero, self.t0, self.aplicacion)
        r = registro.resumen
        print("=" * ANCHO)
        print(f"Paquete {self.numero}  |  t = {registro.tiempo_relativo:.6f} s  |  {r.longitud} bytes"
              f"  |  {r.protocolo}{' / ' + r.aplicacion if r.aplicacion else ''}")
        for seccion in analisis.detallar(paquete, registro.aplicacion)[1:]:
            if seccion.titulo.startswith(("Carga útil", "Relleno")):
                continue
            imprimir_seccion(seccion.titulo.upper(), seccion.campos)
        print("=" * ANCHO + "\n")

    def cerrar(self) -> None:
        if self.escritor:
            self.escritor.close()


def listar_interfaces() -> None:
    print("Interfaces disponibles:\n")
    for i, iface in enumerate(captura.listar_interfaces(), 1):
        print(f"  {i}. {iface.etiqueta()}")


def ejecutar(argumentos: List[str]) -> int:
    parser = argparse.ArgumentParser(prog="main.py --consola",
                                     description="Analizador de tráfico de red en consola")
    parser.add_argument("-i", "--interfaz", help="nombre de la interfaz (por defecto: la principal)")
    parser.add_argument("-f", "--filtro", default="", help='filtro BPF, por ejemplo "tcp port 80"')
    parser.add_argument("-c", "--cantidad", type=int, default=0, help="paquetes a capturar (0 = sin límite)")
    parser.add_argument("-w", "--guardar", help="archivo PCAP donde se guardan los paquetes")
    opciones = parser.parse_args(argumentos)

    if opciones.filtro:
        valido, mensaje = filtros.validar_filtro(opciones.filtro)
        if valido is False:
            print(mensaje)
            return 1
    sniffer = SnifferConsola(opciones.guardar)
    print("Iniciando captura de paquetes... Presiona Ctrl+C para detener.")
    if opciones.filtro:
        print(f"Filtro BPF: {opciones.filtro}")
    print()
    try:
        # store=0 evita que los paquetes se acumulen en la memoria RAM.
        sniff(iface=opciones.interfaz, filter=opciones.filtro or None, prn=sniffer.analizar_paquete,
              store=0, count=opciones.cantidad)
    except PermissionError:
        print("Error: Necesitas ejecutar este script como Administrador o con sudo.")
        return 1
    except KeyboardInterrupt:
        print("\nCaptura detenida por el usuario.")
    finally:
        sniffer.cerrar()
    print(f"\nPaquetes capturados: {sniffer.numero}")
    if opciones.guardar:
        print(f"Guardados en: {opciones.guardar}")
    return 0
