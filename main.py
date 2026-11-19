# -*- coding: utf-8 -*-
"""
main.py
-------
Punto de entrada del Analizador de Tráfico de Red (Sniffer).

    python main.py                         abre la interfaz gráfica
    python main.py --consola [opciones]    versión de consola (ver interfaz/consola.py)
    python main.py --interfaces            lista las interfaces de red

Requisitos: Python 3.8+, Scapy (pip install scapy) y, en Windows, Npcap.

Este archivo se mantiene compatible con versiones antiguas de Python (sin anotaciones
ni f-strings) para poder mostrar un mensaje claro si se ejecuta con una versión que
no es compatible, por ejemplo Python 2.7.
"""

import os
import sys

VERSION_MINIMA = (3, 8)

if sys.version_info < VERSION_MINIMA:
    # Mensaje sin acentos para que se lea bien en cualquier consola.
    sys.stderr.write(
        "Este programa necesita Python %d.%d o superior y se ejecuto con Python %d.%d.\n"
        "Instala Python 3 desde https://www.python.org/downloads/ o ejecutalo con:\n"
        "    py -3 main.py\n" % (VERSION_MINIMA + tuple(sys.version_info[:2])))
    sys.exit(1)


def _es_administrador():
    try:
        if sys.platform.startswith("win"):
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def _avisar(titulo, mensaje, grafico):
    print("{}: {}".format(titulo, mensaje))
    if grafico:
        try:
            import tkinter as tk
            from tkinter import messagebox
            raiz = tk.Tk()
            raiz.withdraw()
            messagebox.showerror(titulo, mensaje)
            raiz.destroy()
        except Exception:
            pass


def revisar_requisitos(grafico):
    """Comprueba que Scapy y Npcap estén instalados antes de abrir el programa."""
    try:
        import scapy  # noqa: F401
        from scapy.config import conf
        import scapy.all  # noqa: F401  (carga las capas y detecta Npcap)
    except ImportError:
        _avisar("Falta Scapy", "Instala Scapy con:\n\n    pip install scapy", grafico)
        return False
    if sys.platform.startswith("win") and not conf.use_pcap:
        _avisar("Falta Npcap",
                "No se encontró Npcap, que Windows necesita para capturar paquetes.\n\n"
                "Descárgalo de https://npcap.com, instálalo y vuelve a abrir el programa.", grafico)
        return False
    if not _es_administrador():
        print("Aviso: el programa no se está ejecutando como Administrador/root. "
              "Si la captura falla por permisos, vuelve a abrirlo con privilegios.")
    return True


def main(argumentos):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    modo_consola = bool(argumentos) and argumentos[0] in ("--consola", "--interfaces")
    if not revisar_requisitos(grafico=not modo_consola):
        return 1
    if argumentos and argumentos[0] == "--interfaces":
        from interfaz.consola import listar_interfaces
        listar_interfaces()
        return 0
    if modo_consola:
        from interfaz.consola import ejecutar
        return ejecutar(argumentos[1:])
    from interfaz.gui import iniciar
    iniciar()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
