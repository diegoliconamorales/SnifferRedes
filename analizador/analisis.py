"""
analisis.py
-----------
Análisis de un paquete capa por capa.

Este módulo parte de la función analizar_paquete() del programa base
sniffer.py. Ahí cada campo se imprimía con print(); aquí cada capa tiene su
propia función que REGRESA los campos (lista de Campo). Así el mismo análisis
lo usan la interfaz gráfica, la versión de consola y las pruebas unitarias.

    Capa 2  analizar_ethernet()   MAC origen, MAC destino, EtherType
    Capa 3  analizar_ipv4()       IP origen/destino, TTL, longitud, protocolo...
            analizar_ipv6(), analizar_arp()  (aparecen en cualquier red real)
    Capa 4  analizar_tcp(), analizar_udp(), analizar_icmp(), analizar_icmpv6()
    Capa 7  ver aplicacion.py (DNS, HTTP, TLS/HTTPS, DHCP...)

Funciones principales:
    construir_registro()  se ejecuta por cada paquete capturado (hilo de captura)
    detallar()            arma el panel de detalle del paquete seleccionado
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Tuple

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, STP, Dot1Q, Dot3, Ether, Loopback
from scapy.packet import Packet, Padding, Raw

from analizador.aplicacion import AnalizadorAplicacion
from analizador.modelos import Campo, RegistroPaquete, ResultadoAplicacion, Resumen, Seccion

# ---------------------------------------------------------------------------
# Tablas de referencia
# ---------------------------------------------------------------------------
ETHERTYPES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "VLAN 802.1Q",
              0x88A8: "VLAN 802.1ad", 0x88CC: "LLDP", 0x888E: "EAPOL (802.1X)",
              0x8863: "PPPoE Discovery", 0x8864: "PPPoE Session", 0x893A: "IEEE 1905.1"}

PROTOCOLOS_IP = {0: "Hop-by-Hop IPv6", 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
                 41: "IPv6 encapsulado", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6",
                 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP"}

ICMP_TIPOS = {0: "Respuesta de eco (Echo reply)", 3: "Destino inalcanzable",
              4: "Source quench", 5: "Redirección", 8: "Solicitud de eco (Echo request)",
              9: "Anuncio de router", 10: "Solicitud de router", 11: "Tiempo excedido",
              12: "Problema de parámetro", 13: "Solicitud de marca de tiempo",
              14: "Respuesta de marca de tiempo"}
ICMP_CODIGOS = {
    3: {0: "Red inalcanzable", 1: "Host inalcanzable", 2: "Protocolo inalcanzable",
        3: "Puerto inalcanzable", 4: "Se requiere fragmentar y DF está activo",
        6: "Red de destino desconocida", 7: "Host de destino desconocido",
        9: "Red prohibida administrativamente", 10: "Host prohibido administrativamente",
        13: "Comunicación prohibida administrativamente"},
    5: {0: "Redirección para la red", 1: "Redirección para el host"},
    11: {0: "TTL agotado en tránsito", 1: "Tiempo de reensamblado agotado"},
}
ICMPV6_TIPOS = {1: "Destino inalcanzable", 2: "Paquete demasiado grande", 3: "Tiempo excedido",
                4: "Problema de parámetro", 128: "Solicitud de eco (Echo request)",
                129: "Respuesta de eco (Echo reply)", 130: "Consulta MLD", 131: "Informe MLD",
                133: "Solicitud de router (RS)", 134: "Anuncio de router (RA)",
                135: "Solicitud de vecino (NS)", 136: "Anuncio de vecino (NA)",
                137: "Redirección", 143: "Informe MLDv2"}

BANDERAS_TCP = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
                (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]

NOMBRES_CAPA = {"Ether": "Ethernet", "Dot3": "IEEE 802.3", "Dot1Q": "VLAN", "ARP": "ARP",
                "IP": "IPv4", "IPv6": "IPv6", "TCP": "TCP", "UDP": "UDP", "ICMP": "ICMP",
                "Loopback": "Loopback"}


# ---------------------------------------------------------------------------
# Localización de capas y rangos de bytes
# ---------------------------------------------------------------------------
def capa_red(paquete: Packet):
    """Regresa la primera capa IPv4 o IPv6 del paquete (o None)."""
    capa = paquete
    while capa:
        if isinstance(capa, (IP, IPv6)):
            return capa
        capa = capa.payload
    return None


def capa_transporte(red):
    """
    Regresa la capa que va justo después de IP (TCP, UDP, ICMP, ICMPv6...).
    En IPv6 se saltan los encabezados de extensión (Hop-by-Hop, etc.).
    """
    if red is None:
        return None
    capa = red.payload
    while capa and type(capa).__name__.startswith("IPv6ExtHdr"):
        capa = capa.payload
    if not capa or isinstance(capa, (Raw, Padding)):
        return _transporte_de_segmento_unido(red, capa)
    return capa


def es_segmento_unido(red) -> bool:
    """
    IPv6 con longitud de carga útil 0 que lleva TCP o UDP. Ocurre cuando la tarjeta
    de red une varios segmentos en uno solo antes de entregarlo al sistema (Receive
    Segment Coalescing): la trama supera los 1500 bytes y el campo de longitud queda en 0.
    """
    return isinstance(red, IPv6) and int(red.plen) == 0 and int(red.nh) in (6, 17)


def _transporte_de_segmento_unido(red, capa):
    """
    Con longitud 0, Scapy toma todo lo que sigue al encabezado IPv6 como relleno.
    En ese caso se vuelve a interpretar ese contenido como TCP o UDP.
    """
    if not es_segmento_unido(red) or not isinstance(capa, Padding):
        return None
    datos = bytes(capa)
    clase, minimo = (TCP, 20) if int(red.nh) == 6 else (UDP, 8)
    return clase(datos) if len(datos) >= minimo else None


def _es_reconstruida(transporte) -> bool:
    """La capa de transporte se reconstruyó aparte (segmento unido por la tarjeta)."""
    return transporte is not None and transporte.underlayer is None


def es_icmpv6(capa) -> bool:
    return capa is not None and type(capa).__name__.startswith("ICMPv6")


def rango_encabezado(total: int, capa) -> Tuple[int, int]:
    """
    Posición (inicio, longitud) del encabezado de una capa dentro de la trama.
    bytes(capa) contiene la capa y todo lo que lleva encima, por eso
    total - len(capa) es el byte donde empieza.
    """
    inicio = total - len(capa)
    siguiente = capa.payload
    fin = total - len(siguiente) if siguiente else total
    return inicio, fin - inicio


def rango_carga(paquete: Packet, transporte, total: int) -> Tuple[int, int]:
    """
    Posición (inicio, longitud) de la carga útil: los datos que van después
    del encabezado de transporte, sin el relleno (padding) de Ethernet.
    """
    if transporte is None:
        return total, 0
    inicio_t, largo_t = rango_encabezado(total, transporte)
    inicio = inicio_t + largo_t
    fin = total
    if paquete.haslayer(Padding) and not _es_reconstruida(transporte):
        fin = total - len(paquete[Padding])
    return inicio, max(0, fin - inicio)


def banderas_tcp(valor: int) -> str:
    """Convierte el número de banderas TCP a texto: 0x012 -> 'SYN, ACK'."""
    return ", ".join(nombre for bit, nombre in BANDERAS_TCP if valor & bit) or "ninguna"


def _opciones_tcp(opciones) -> str:
    partes = []
    for opcion in opciones:
        nombre, valor = opcion if isinstance(opcion, tuple) else (opcion, None)
        if nombre == "MSS":
            partes.append(f"MSS={valor}")
        elif nombre == "WScale":
            partes.append(f"Escala de ventana={valor} (x{2 ** int(valor)})")
        elif nombre == "SAckOK":
            partes.append("SACK permitido")
        elif nombre == "Timestamp" and isinstance(valor, tuple):
            partes.append(f"TSval={valor[0]} TSecr={valor[1]}")
        elif nombre == "SAck":
            partes.append(f"SACK {valor}")
        else:
            partes.append(str(nombre))
    return ", ".join(partes)


def _tipo_mac(mac: str) -> str:
    if mac.lower() == "ff:ff:ff:ff:ff:ff":
        return " (difusión / broadcast)"
    try:
        if int(mac.split(":")[0], 16) & 1:
            return " (multidifusión / multicast)"
    except ValueError:
        pass
    return ""


# ---------------------------------------------------------------------------
# CAPA 2 - ENLACE
# ---------------------------------------------------------------------------
def analizar_ethernet(eth) -> List[Campo]:
    """Campos de la trama Ethernet II (igual que en sniffer.py, sin print)."""
    tipo = int(eth.type)
    return [
        Campo("MAC destino", f"{eth.dst}{_tipo_mac(eth.dst)}"),
        Campo("MAC origen", eth.src),
        Campo("Tipo (EtherType)", f"0x{tipo:04x} ({ETHERTYPES.get(tipo, 'desconocido')})"),
    ]


def analizar_arp(arp) -> List[Campo]:
    operacion = {1: "Solicitud (request)", 2: "Respuesta (reply)"}.get(int(arp.op), str(arp.op))
    return [
        Campo("Tipo de hardware", f"{arp.hwtype} (Ethernet)" if arp.hwtype == 1 else str(arp.hwtype)),
        Campo("Tipo de protocolo", f"0x{int(arp.ptype):04x}"),
        Campo("Longitud de dirección física / lógica", f"{arp.hwlen} / {arp.plen} bytes"),
        Campo("Operación", f"{operacion} ({arp.op})"),
        Campo("MAC del emisor", arp.hwsrc),
        Campo("IP del emisor", arp.psrc),
        Campo("MAC de destino", arp.hwdst),
        Campo("IP de destino", arp.pdst),
    ]


# ---------------------------------------------------------------------------
# CAPA 3 - RED
# ---------------------------------------------------------------------------
def analizar_ipv4(ip) -> List[Campo]:
    """Campos del encabezado IPv4."""
    ihl = int(ip.ihl)
    tos = int(ip.tos)
    banderas = int(ip.flags)
    texto_banderas = [n for bit, n in ((2, "DF (no fragmentar)"), (1, "MF (más fragmentos)"))
                      if banderas & bit]
    proto = int(ip.proto)
    campos = [
        Campo("Versión", str(ip.version)),
        Campo("Longitud del encabezado (IHL)", f"{ihl * 4} bytes ({ihl})"),
        Campo("Servicios diferenciados (ToS)", f"0x{tos:02x} (DSCP {tos >> 2}, ECN {tos & 3})"),
        Campo("Longitud total", f"{ip.len} bytes"),
        Campo("Identificación", f"0x{int(ip.id):04x} ({ip.id})"),
        Campo("Banderas", f"0x{banderas:x}: " + (", ".join(texto_banderas) or "ninguna")),
        Campo("Desplazamiento de fragmento", f"{int(ip.frag) * 8} bytes"),
        Campo("Tiempo de vida (TTL)", str(ip.ttl)),
        Campo("Protocolo", f"{PROTOCOLOS_IP.get(proto, 'desconocido')} ({proto})"),
        Campo("Suma de verificación (checksum)", f"0x{int(ip.chksum):04x}"),
        Campo("IP origen", ip.src),
        Campo("IP destino", ip.dst),
    ]
    if ihl > 5:
        campos.append(Campo("Opciones", f"{(ihl - 5) * 4} bytes"))
    return campos


def analizar_ipv6(ip6) -> List[Campo]:
    nh = int(ip6.nh)
    return [
        Campo("Versión", str(ip6.version)),
        Campo("Clase de tráfico", f"0x{int(ip6.tc):02x}"),
        Campo("Etiqueta de flujo", f"0x{int(ip6.fl):05x}"),
        Campo("Longitud de la carga útil", f"{ip6.plen} bytes"),
        Campo("Siguiente encabezado", f"{PROTOCOLOS_IP.get(nh, 'desconocido')} ({nh})"),
        Campo("Límite de saltos", str(ip6.hlim)),
        Campo("IP origen", ip6.src),
        Campo("IP destino", ip6.dst),
    ] + ([Campo("Nota", "Longitud 0: la tarjeta de red unió varios segmentos en esta trama "
                        "(Receive Segment Coalescing); se usa la longitud capturada")]
         if es_segmento_unido(ip6) else [])


# ---------------------------------------------------------------------------
# CAPA 4 - TRANSPORTE / CONTROL
# ---------------------------------------------------------------------------
def analizar_tcp(tcp, largo_datos: int) -> List[Campo]:
    banderas = int(tcp.flags)
    campos = [
        Campo("Puerto origen", str(tcp.sport)),
        Campo("Puerto destino", str(tcp.dport)),
        Campo("Número de secuencia (Seq)", str(tcp.seq)),
        Campo("Número de acuse (Ack)", str(tcp.ack)),
        Campo("Longitud del encabezado", f"{int(tcp.dataofs) * 4} bytes ({tcp.dataofs})"),
        Campo("Banderas (Flags)", f"0x{banderas:03x} [{banderas_tcp(banderas)}]",
              [Campo(nombre, "1 (activa)" if banderas & bit else "0")
               for bit, nombre in BANDERAS_TCP], expandido=False),
        Campo("Ventana", str(tcp.window)),
        Campo("Suma de verificación (checksum)", f"0x{int(tcp.chksum):04x}"),
        Campo("Puntero urgente", str(tcp.urgptr)),
    ]
    if tcp.options:
        campos.append(Campo("Opciones", _opciones_tcp(tcp.options)))
    campos.append(Campo("Datos del segmento (carga útil)", f"{largo_datos} bytes"))
    return campos


def analizar_udp(udp) -> List[Campo]:
    return [
        Campo("Puerto origen", str(udp.sport)),
        Campo("Puerto destino", str(udp.dport)),
        Campo("Longitud UDP", f"{udp.len} bytes (8 de encabezado + {int(udp.len) - 8} de datos)"),
        Campo("Suma de verificación (checksum)", f"0x{int(udp.chksum):04x}"),
    ]


def analizar_icmp(icmp) -> List[Campo]:
    tipo, codigo = int(icmp.type), int(icmp.code)
    campos = [
        Campo("Tipo", f"{tipo} - {ICMP_TIPOS.get(tipo, 'otro')}"),
        Campo("Código", f"{codigo} - {ICMP_CODIGOS[tipo][codigo]}"
              if codigo in ICMP_CODIGOS.get(tipo, {}) else str(codigo)),
        Campo("Suma de verificación (checksum)", f"0x{int(icmp.chksum):04x}"),
    ]
    if tipo in (0, 8, 13, 14):
        campos += [Campo("Identificador", f"0x{int(icmp.id):04x} ({icmp.id})"),
                   Campo("Número de secuencia", str(icmp.seq))]
    original = capa_red(icmp.payload) if icmp.payload else None
    if tipo in (3, 5, 11, 12) and original is not None:
        campos.append(Campo("Datagrama original que causó el error",
                            f"{original.src} → {original.dst}, protocolo "
                            f"{PROTOCOLOS_IP.get(int(original.proto), original.proto)}"))
    return campos


def analizar_icmpv6(capa) -> List[Campo]:
    tipo, codigo = int(capa.type), int(capa.code)
    campos = [Campo("Tipo", f"{tipo} - {ICMPV6_TIPOS.get(tipo, 'otro')}"),
              Campo("Código", str(codigo)),
              Campo("Suma de verificación (checksum)", f"0x{int(capa.cksum):04x}")]
    for campo, nombre in (("tgt", "Dirección objetivo"), ("id", "Identificador"),
                          ("seq", "Número de secuencia")):
        try:
            campos.append(Campo(nombre, str(getattr(capa, campo))))
        except AttributeError:
            pass
    return campos


def _info_icmp(icmp, ttl) -> str:
    tipo, codigo = int(icmp.type), int(icmp.code)
    nombre = ICMP_TIPOS.get(tipo, f"Tipo {tipo}")
    if tipo in (0, 8):
        return f"{nombre} id=0x{int(icmp.id):04x}, seq={icmp.seq}, ttl={ttl}"
    descripcion = ICMP_CODIGOS.get(tipo, {}).get(codigo)
    return f"{nombre}" + (f" — {descripcion}" if descripcion else f" (código {codigo})")


# ---------------------------------------------------------------------------
# Resumen (una fila de la tabla)
# ---------------------------------------------------------------------------
def resumir(paquete: Packet, total: int, red, transporte, largo_carga: int,
            aplicacion: Optional[ResultadoAplicacion]) -> Resumen:
    r = Resumen(longitud=total)

    if isinstance(paquete, (Ether, Dot3)):
        r.mac_origen, r.mac_destino = paquete.src, paquete.dst

    if red is None:
        if paquete.haslayer(ARP):
            arp = paquete[ARP]
            r.protocolo, r.etiqueta = "ARP", "arp"
            r.ip_origen, r.ip_destino = arp.psrc, arp.pdst
            if int(arp.op) == 1:
                r.info = (f"ARP gratuito: anuncia {arp.psrc}" if arp.psrc == arp.pdst
                          else f"¿Quién tiene {arp.pdst}? Responder a {arp.psrc}")
            else:
                r.info = f"{arp.psrc} está en {arp.hwsrc}"
        elif isinstance(paquete, Ether):
            tipo = int(paquete.type)
            r.protocolo = ETHERTYPES.get(tipo, "Otro")
            r.info = f"EtherType 0x{tipo:04x} ({ETHERTYPES.get(tipo, 'desconocido')})"
        else:
            if paquete.haslayer(STP):
                stp = paquete[STP]
                r.protocolo = "STP"
                r.info = f"Spanning Tree (BPDU): puente raíz {stp.rootmac}, costo {stp.pathcost}"
            else:
                r.protocolo = "LLC" if isinstance(paquete, Dot3) else "Otro"
                r.info = paquete.summary()
        return r

    r.ip_origen, r.ip_destino = red.src, red.dst
    es_v4 = isinstance(red, IP)
    ttl = red.ttl if es_v4 else red.hlim

    if isinstance(transporte, TCP):
        banderas = int(transporte.flags)
        r.protocolo, r.etiqueta = "TCP", "tcp"
        r.puerto_origen, r.puerto_destino = str(transporte.sport), str(transporte.dport)
        r.info = (f"{transporte.sport} → {transporte.dport} [{banderas_tcp(banderas)}] "
                  f"Seq={transporte.seq}" + (f" Ack={transporte.ack}" if banderas & 0x10 else "")
                  + f" Win={transporte.window} Len={largo_carga}")
        if banderas & 0x04:
            r.etiqueta = "rst"
        elif banderas & 0x03:
            r.etiqueta = "syn"
    elif isinstance(transporte, UDP):
        r.protocolo, r.etiqueta = "UDP", "udp"
        r.puerto_origen, r.puerto_destino = str(transporte.sport), str(transporte.dport)
        r.info = f"{transporte.sport} → {transporte.dport} Len={largo_carga}"
    elif isinstance(transporte, ICMP):
        r.protocolo, r.etiqueta = "ICMP", "icmp"
        r.info = _info_icmp(transporte, ttl)
    elif es_icmpv6(transporte):
        r.protocolo, r.etiqueta = "ICMPv6", "icmp"
        tipo = int(transporte.type)
        r.info = ICMPV6_TIPOS.get(tipo, f"Tipo {tipo}")
    else:
        numero = int(red.proto) if es_v4 else int(red.nh)
        r.protocolo = PROTOCOLOS_IP.get(numero, "Otro")
        if es_v4 and int(red.frag) > 0:
            r.info = (f"Fragmento IPv4 (desplazamiento {int(red.frag) * 8} bytes, "
                      f"ID 0x{int(red.id):04x})")
        else:
            r.info = f"Protocolo IP {numero} ({PROTOCOLOS_IP.get(numero, 'desconocido')})"

    if aplicacion is not None:
        r.aplicacion = aplicacion.protocolo
        r.info = aplicacion.info
        etiquetas = {"HTTP": "http", "DNS": "dns", "mDNS": "dns", "LLMNR": "dns",
                     "TLS (HTTPS)": "tls", "QUIC": "tls", "DHCP": "dhcp"}
        r.etiqueta = etiquetas.get(aplicacion.protocolo, r.etiqueta)
    return r


# ---------------------------------------------------------------------------
# Registro por paquete (se ejecuta en el hilo de captura)
# ---------------------------------------------------------------------------
def construir_registro(paquete: Packet, numero: int, t0: float,
                       analizador: Optional[AnalizadorAplicacion] = None) -> RegistroPaquete:
    """
    Analiza un paquete recién capturado y regresa lo que se guarda en memoria:
    los bytes de la trama y el resumen para la tabla. El objeto de Scapy se
    descarta después de esto.
    """
    datos = bytes(paquete)
    total = len(datos)
    tiempo = float(paquete.time)
    red = capa_red(paquete)
    transporte = capa_transporte(red)
    inicio, largo = rango_carga(paquete, transporte, total)
    carga = datos[inicio:inicio + largo]
    aplicacion = None
    if analizador is not None and red is not None:
        aplicacion = analizador.analizar(paquete, transporte, carga, red.src, red.dst)
    resumen = resumir(paquete, total, red, transporte, largo, aplicacion)
    return RegistroPaquete(numero, tiempo, tiempo - t0, datos, type(paquete), resumen, aplicacion)


def reconstruir(registro: RegistroPaquete) -> Packet:
    """Vuelve a crear el paquete de Scapy a partir de los bytes guardados."""
    paquete = registro.clase_enlace(registro.datos)
    paquete.time = registro.tiempo
    return paquete


# ---------------------------------------------------------------------------
# Detalle completo (panel "Información detallada")
# ---------------------------------------------------------------------------
def detallar(paquete: Packet, aplicacion: Optional[ResultadoAplicacion] = None,
             numero: Optional[int] = None, tiempo_relativo: Optional[float] = None
             ) -> List[Seccion]:
    """Regresa una Seccion por cada capa del paquete, con el rango de bytes que ocupa."""
    total = len(paquete)
    secciones: List[Seccion] = []
    capas: List[str] = []

    # --- Capa 2 ---
    if isinstance(paquete, Ether):
        ini, lon = rango_encabezado(total, paquete)
        secciones.append(Seccion("Ethernet II", analizar_ethernet(paquete), ini, lon,
                                 f"Origen: {paquete.src}, Destino: {paquete.dst}"))
        capas.append("Ethernet")
    elif isinstance(paquete, Dot3):
        ini, lon = rango_encabezado(total, paquete)
        secciones.append(Seccion("IEEE 802.3", [Campo("MAC destino", paquete.dst),
                                                Campo("MAC origen", paquete.src),
                                                Campo("Longitud", str(paquete.len))], ini, lon,
                                 f"Origen: {paquete.src}, Destino: {paquete.dst}"))
        capas.append("IEEE 802.3")
    elif isinstance(paquete, Loopback):
        ini, lon = rango_encabezado(total, paquete)
        secciones.append(Seccion("Loopback", [Campo("Familia de protocolo", str(paquete.type))],
                                 ini, lon, "Tráfico local del propio equipo"))
        capas.append("Loopback")
    if paquete.haslayer(Dot1Q):
        vlan = paquete[Dot1Q]
        ini, lon = rango_encabezado(total, vlan)
        secciones.append(Seccion("VLAN 802.1Q",
                                 [Campo("Prioridad", str(vlan.prio)), Campo("ID de VLAN", str(vlan.vlan)),
                                  Campo("Tipo", f"0x{int(vlan.type):04x}")], ini, lon,
                                 f"ID: {vlan.vlan}"))
        capas.append("VLAN")

    # --- Capa 3 ---
    red = capa_red(paquete)
    if red is None and paquete.haslayer(ARP):
        arp = paquete[ARP]
        ini, lon = rango_encabezado(total, arp)
        tipo = "solicitud" if int(arp.op) == 1 else "respuesta"
        secciones.append(Seccion("ARP (Resolución de Direcciones)", analizar_arp(arp), ini, lon,
                                 f"{tipo.capitalize()}: {arp.psrc} → {arp.pdst}"))
        capas.append("ARP")
    elif isinstance(red, IP):
        ini, lon = rango_encabezado(total, red)
        secciones.append(Seccion("IPv4 (Protocolo de Internet v4)", analizar_ipv4(red), ini, lon,
                                 f"Origen: {red.src}, Destino: {red.dst}"))
        capas.append("IPv4")
    elif isinstance(red, IPv6):
        ini, lon = rango_encabezado(total, red)
        secciones.append(Seccion("IPv6 (Protocolo de Internet v6)", analizar_ipv6(red), ini, lon,
                                 f"Origen: {red.src}, Destino: {red.dst}"))
        capas.append("IPv6")

    # --- Capa 4 ---
    transporte = capa_transporte(red)
    inicio_carga, largo_carga = rango_carga(paquete, transporte, total)
    if transporte is not None:
        ini, lon = rango_encabezado(total, transporte)
        if isinstance(transporte, TCP):
            resumen = (f"Puerto origen: {transporte.sport}, Puerto destino: {transporte.dport}, "
                       f"Seq: {transporte.seq}, Len: {largo_carga}")
            secciones.append(Seccion("TCP (Control de Transmisión)",
                                     analizar_tcp(transporte, largo_carga), ini, lon, resumen))
            capas.append("TCP")
        elif isinstance(transporte, UDP):
            resumen = f"Puerto origen: {transporte.sport}, Puerto destino: {transporte.dport}"
            secciones.append(Seccion("UDP (Datagramas de Usuario)", analizar_udp(transporte),
                                     ini, lon, resumen))
            capas.append("UDP")
        elif isinstance(transporte, ICMP):
            secciones.append(Seccion("ICMP (Mensajes de Control)", analizar_icmp(transporte),
                                     ini, lon, ICMP_TIPOS.get(int(transporte.type), "")))
            capas.append("ICMP")
        elif es_icmpv6(transporte):
            secciones.append(Seccion("ICMPv6 (Mensajes de Control v6)", analizar_icmpv6(transporte),
                                     ini, lon, ICMPV6_TIPOS.get(int(transporte.type), "")))
            capas.append("ICMPv6")

    # --- Capa 7 ---
    if aplicacion is not None:
        secciones.append(Seccion(aplicacion.titulo or aplicacion.protocolo, aplicacion.campos,
                                 inicio_carga, largo_carga, aplicacion.info))
        capas.append(aplicacion.protocolo)
    if largo_carga > 0:
        datos = bytes(paquete)[inicio_carga:inicio_carga + largo_carga]
        vista = "".join(chr(b) if 32 <= b < 127 else "." for b in datos[:60])
        secciones.append(Seccion("Carga útil (datos)", [
            Campo("Posición en la trama", f"byte {inicio_carga} (0x{inicio_carga:04x})"),
            Campo("Longitud", f"{largo_carga} bytes"),
            Campo("Vista previa ASCII", vista + ("…" if largo_carga > 60 else "")),
        ], inicio_carga, largo_carga, f"{largo_carga} bytes"))
    if paquete.haslayer(Padding) and not _es_reconstruida(transporte):
        relleno = len(paquete[Padding])
        if relleno:
            secciones.append(Seccion("Relleno Ethernet (padding)",
                                     [Campo("Motivo", "Ethernet exige tramas de al menos 60 bytes")],
                                     total - relleno, relleno, f"{relleno} bytes"))

    # --- Trama (va al inicio, como en Wireshark) ---
    campos_trama = []
    if paquete.time:
        hora = datetime.fromtimestamp(float(paquete.time))
        campos_trama.append(Campo("Hora de captura", hora.strftime("%d/%m/%Y %H:%M:%S.%f")))
    if tiempo_relativo is not None:
        campos_trama.append(Campo("Tiempo desde el primer paquete", f"{tiempo_relativo:.6f} s"))
    campos_trama += [Campo("Longitud de la trama", f"{total} bytes ({total * 8} bits)"),
                     Campo("Protocolos en la trama", " → ".join(capas) or "desconocido")]
    titulo_trama = f"Trama {numero}" if numero is not None else "Trama"
    secciones.insert(0, Seccion(titulo_trama, campos_trama, 0, total,
                                f"{total} bytes capturados ({total * 8} bits)"))
    return secciones
