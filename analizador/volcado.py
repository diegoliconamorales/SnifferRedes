"""
volcado.py
----------
Volcado hexadecimal y ASCII de los bytes de un paquete (panel Payload).

Formato de cada línea (16 bytes por línea, igual que Wireshark):

    0000  45 00 00 3c 1c 46 40 00  40 06 b1 e6 c0 a8 01 0a   E..<.F@. @.......
    ^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^
    posición       bytes en hexadecimal                       mismos bytes en ASCII

Los bytes que no son caracteres imprimibles se muestran como punto.
"""

from __future__ import annotations

from typing import Iterator, List, Tuple

BYTES_POR_LINEA = 16
INICIO_HEX = 6                        # "0000  "
ANCHO_HEX = BYTES_POR_LINEA * 3 + 1   # 16 bytes "xx " + un espacio extra a la mitad
INICIO_ASCII = INICIO_HEX + ANCHO_HEX + 2


def caracter(byte: int) -> str:
    return chr(byte) if 32 <= byte < 127 else "."


def volcado_hex(datos: bytes, desplazamiento: int = 0) -> List[str]:
    """
    Regresa las líneas del volcado. 'desplazamiento' es la posición del
    primer byte dentro de la trama (para mostrar solo la carga útil con su
    posición real).
    """
    lineas = []
    for i in range(0, len(datos), BYTES_POR_LINEA):
        bloque = datos[i:i + BYTES_POR_LINEA]
        hex_partes = [f"{b:02x}" for b in bloque]
        izquierda = " ".join(hex_partes[:8])
        derecha = " ".join(hex_partes[8:])
        parte_hex = f"{izquierda:<23}  {derecha:<23}"
        texto = "".join(caracter(b) for b in bloque)
        parte_ascii = f"{texto[:8]} {texto[8:]}" if len(texto) > 8 else texto
        lineas.append(f"{desplazamiento + i:04x}  {parte_hex}   {parte_ascii}")
    return lineas


def columnas_byte(indice: int) -> Tuple[int, int]:
    """Columna donde aparece el byte 'indice' de su línea en la parte hex y en la ASCII."""
    j = indice % BYTES_POR_LINEA
    col_hex = INICIO_HEX + j * 3 + (1 if j >= 8 else 0)
    col_ascii = INICIO_ASCII + j + (1 if j >= 8 else 0)
    return col_hex, col_ascii


def tramos(inicio: int, longitud: int) -> Iterator[Tuple[int, int, int, int, int]]:
    """
    Divide un rango de bytes en tramos de una sola línea para poder resaltarlo.
    Regresa (línea, col_hex_inicio, col_hex_fin, col_ascii_inicio, col_ascii_fin).
    Las líneas se numeran desde 0; las columnas finales son exclusivas.
    """
    fin = inicio + longitud
    actual = inicio
    while actual < fin:
        linea = actual // BYTES_POR_LINEA
        ultimo = min(fin, (linea + 1) * BYTES_POR_LINEA) - 1
        hex_ini, ascii_ini = columnas_byte(actual)
        hex_fin, ascii_fin = columnas_byte(ultimo)
        yield linea, hex_ini, hex_fin + 2, ascii_ini, ascii_fin + 1
        actual = ultimo + 1
