"""
aplicacion.py
-------------
Identificación y extracción controlada de información de la capa de aplicación.

"Controlada" significa que no se vuelca todo el contenido del paquete: de cada
protocolo solo se extraen los campos que sirven para el análisis.

    DNS   -> dominios consultados, tipo de registro y direcciones de respuesta.
    HTTP  -> método, URI, Host y encabezados principales. Los valores de Cookie
             y Authorization no se muestran (solo se indica que existen).
    HTTPS -> se identifica la conexión TLS y se leen los datos que viajan en
             claro durante el saludo (nombre del servidor o SNI, versión TLS,
             suite de cifrado). El contenido NO se descifra.
    Otros -> DHCP, QUIC, SSDP, NTP y servicios conocidos por número de puerto.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Dict, List, Optional, Tuple

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP, UDP

try:  # diccionario de tipos de registro DNS (A, AAAA, CNAME...)
    from scapy.layers.dns import dnstypes
except ImportError:  # pragma: no cover - versiones muy antiguas de Scapy
    dnstypes = {}

from analizador.modelos import Campo, ResultadoAplicacion

# ---------------------------------------------------------------------------
# Tablas de referencia
# ---------------------------------------------------------------------------
PUERTOS_CONOCIDOS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
    137: "NBNS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    162: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    520: "RIP", 587: "SMTP", 853: "DNS sobre TLS", 993: "IMAPS", 995: "POP3S",
    1900: "SSDP", 3389: "RDP", 5353: "mDNS", 5355: "LLMNR", 8080: "HTTP",
}

DNS_RCODES = {0: "Sin error", 1: "Error de formato", 2: "Falla del servidor",
              3: "El dominio no existe (NXDOMAIN)", 4: "No implementado", 5: "Rechazada"}
DNS_OPCODES = {0: "Consulta estándar", 1: "Consulta inversa", 2: "Estado del servidor",
               4: "Notificación", 5: "Actualización"}

METODOS_HTTP = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ",
                b"PATCH ", b"CONNECT ", b"TRACE ")
ENCABEZADOS_PRIVADOS = {"cookie", "set-cookie", "authorization", "proxy-authorization"}

TLS_REGISTROS = {20: "Change Cipher Spec", 21: "Alert", 22: "Handshake",
                 23: "Application Data", 24: "Heartbeat"}
TLS_HANDSHAKE = {0: "Hello Request", 1: "Client Hello", 2: "Server Hello",
                 4: "New Session Ticket", 8: "Encrypted Extensions", 11: "Certificate",
                 12: "Server Key Exchange", 13: "Certificate Request",
                 14: "Server Hello Done", 15: "Certificate Verify",
                 16: "Client Key Exchange", 20: "Finished"}
TLS_VERSIONES = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
                 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
TLS_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
}
PUERTOS_TLS = {443, 8443, 853, 993, 995, 465}

DHCP_TIPOS = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK",
              6: "NAK", 7: "Release", 8: "Inform"}
NTP_MODOS = {1: "simétrico activo", 2: "simétrico pasivo", 3: "cliente", 4: "servidor",
             5: "difusión (broadcast)"}
QUIC_TIPOS = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}

TITULO_TLS = "TLS (Seguridad de la Capa de Transporte)"
MAX_SEGMENTOS_REENSAMBLE = 4
MAX_FLUJOS_PENDIENTES = 256


# ---------------------------------------------------------------------------
# Funciones auxiliares
# ---------------------------------------------------------------------------
def _texto(valor) -> str:
    """Convierte bytes, listas o números de Scapy a texto legible."""
    if isinstance(valor, bytes):
        return valor.decode("utf-8", "replace").rstrip(".")
    if isinstance(valor, (list, tuple)):
        return ", ".join(_texto(v) for v in valor)
    return str(valor).rstrip(".") if isinstance(valor, str) else str(valor)


def _entero(datos: bytes, inicio: int, tam: int) -> int:
    """Lee un entero big-endian (orden de red). Lanza IndexError si no alcanza."""
    if inicio + tam > len(datos):
        raise IndexError("datos insuficientes")
    return int.from_bytes(datos[inicio:inicio + tam], "big")


def _registros_dns(campo) -> list:
    """
    Regresa las preguntas o respuestas DNS como lista.
    Scapy 2.6 o superior las entrega como lista; Scapy 2.5 como una cadena de
    paquetes enlazados (cada registro es la carga del anterior).
    """
    if campo is None:
        return []
    if isinstance(campo, list):
        return campo
    registros, actual = [], campo
    while actual is not None and hasattr(actual, "fields") and actual.fields:
        registros.append(actual)
        actual = actual.payload if actual.payload else None
    return registros


def _tipo_dns(numero: int) -> str:
    return dnstypes.get(numero, str(numero))


def _dato_registro(rr) -> str:
    """Obtiene el dato de una respuesta DNS sin importar su tipo (A, CNAME, MX...)."""
    for atributo in ("rdata", "exchange", "target", "target_name", "mname"):
        try:
            return _texto(getattr(rr, atributo))
        except AttributeError:
            continue
    return rr.summary()


def _es_grease(valor: int) -> bool:
    """Valores GREASE (0x0a0a, 0x1a1a...) que los navegadores agregan a propósito."""
    return (valor & 0x0F0F) == 0x0A0A


def es_encabezado_tls(datos: bytes, i: int = 0) -> bool:
    """Revisa si en la posición i comienza un registro TLS válido (5 bytes)."""
    if len(datos) - i < 5:
        return False
    longitud = int.from_bytes(datos[i + 3:i + 5], "big")
    return datos[i] in TLS_REGISTROS and datos[i + 1] == 3 and datos[i + 2] <= 4 \
        and 0 < longitud <= 18432


def parsear_client_hello(hs: bytes) -> Dict[str, object]:
    """
    Lee los campos en claro de un mensaje Client Hello. 'hs' empieza en el
    encabezado del handshake (tipo 1). Tolera datos incompletos: devuelve lo
    que se alcanzó a leer y marca 'truncado'.
    """
    r: Dict[str, object] = {"truncado": False}
    try:
        p = 4                                    # tipo (1) + longitud (3)
        r["version"] = _entero(hs, p, 2)
        p += 2 + 32                              # versión + random
        p += 1 + _entero(hs, p, 1)               # session id
        largo_suites = _entero(hs, p, 2)
        r["num_suites"] = largo_suites // 2
        p += 2 + largo_suites
        p += 1 + _entero(hs, p, 1)               # métodos de compresión
        fin = min(len(hs), p + 2 + _entero(hs, p, 2))
        p += 2
        while p + 4 <= fin:
            tipo, largo = _entero(hs, p, 2), _entero(hs, p + 2, 2)
            p += 4
            dato = hs[p:p + largo]
            if len(dato) < largo:
                r["truncado"] = True
                break
            if tipo == 0 and len(dato) >= 5:     # server_name (SNI)
                largo_nombre = _entero(dato, 3, 2)
                r["sni"] = dato[5:5 + largo_nombre].decode("ascii", "replace")
            elif tipo == 16 and len(dato) >= 2:  # ALPN: protocolos de aplicación
                protocolos, q = [], 2
                while q < len(dato):
                    n = dato[q]
                    protocolos.append(dato[q + 1:q + 1 + n].decode("ascii", "replace"))
                    q += 1 + n
                r["alpn"] = protocolos
            elif tipo == 43 and dato:            # supported_versions
                versiones = [_entero(dato, 1 + k, 2) for k in range(0, dato[0] - 1, 2)]
                r["versiones"] = [TLS_VERSIONES.get(v, hex(v)) for v in versiones
                                  if not _es_grease(v)]
            p += largo
    except IndexError:
        r["truncado"] = True
    return r


def parsear_server_hello(hs: bytes) -> Dict[str, object]:
    """Lee versión y suite de cifrado elegidas por el servidor (Server Hello)."""
    r: Dict[str, object] = {}
    try:
        p = 4
        version = _entero(hs, p, 2)
        p += 2 + 32
        p += 1 + _entero(hs, p, 1)
        r["suite"] = _entero(hs, p, 2)
        p += 2 + 1
        fin = min(len(hs), p + 2 + _entero(hs, p, 2))
        p += 2
        while p + 4 <= fin:
            tipo, largo = _entero(hs, p, 2), _entero(hs, p + 2, 2)
            if tipo == 43 and largo == 2:        # TLS 1.3 indica aquí la versión real
                version = _entero(hs, p + 4, 2)
            p += 4 + largo
        r["version"] = version
    except IndexError:
        pass
    return r


# ---------------------------------------------------------------------------
# Analizador de la capa de aplicación
# ---------------------------------------------------------------------------
class _ClientHelloPendiente:
    """Client Hello que no cupo en un solo segmento TCP (se espera el resto)."""
    __slots__ = ("buffer", "total", "siguiente_seq", "segmentos")

    def __init__(self, buffer: bytes, total: int, siguiente_seq: int) -> None:
        self.buffer = buffer
        self.total = total
        self.siguiente_seq = siguiente_seq
        self.segmentos = 1


class AnalizadorAplicacion:
    """
    Identifica el protocolo de aplicación de cada paquete.

    Guarda un estado mínimo entre paquetes: los navegadores actuales envían
    un Client Hello tan grande que se divide en dos segmentos TCP, y el nombre
    del servidor (SNI) puede quedar en el segundo. Para leerlo se unen los
    segmentos de esa conexión (como hace Wireshark). Se limita el número de
    conexiones pendientes para no acumular memoria.
    """

    def __init__(self) -> None:
        self._pendientes: "OrderedDict[tuple, _ClientHelloPendiente]" = OrderedDict()

    def reiniciar(self) -> None:
        self._pendientes.clear()

    # -- punto de entrada --------------------------------------------------
    def analizar(self, paquete, transporte, carga: bytes,
                 ip_origen: str = "", ip_destino: str = "") -> Optional[ResultadoAplicacion]:
        if transporte is None:
            return None
        es_tcp = isinstance(transporte, TCP)
        es_udp = isinstance(transporte, UDP)
        if not (es_tcp or es_udp):
            return None
        sport, dport = int(transporte.sport), int(transporte.dport)
        puertos = (sport, dport)

        dns = self._buscar_dns(paquete)
        if dns is not None:
            return self._dns(dns, puertos)
        if paquete.haslayer(BOOTP):
            return self._dhcp(paquete)
        if not carga:
            return None

        if es_tcp:
            http = self._http(carga)
            if http:
                return http
            flujo = (ip_origen, sport, ip_destino, dport)
            tls = self._tls(carga, flujo, int(transporte.seq), puertos)
            if tls:
                return tls
        else:
            if 443 in puertos:
                return self._quic(carga)
            if 1900 in puertos:
                return self._http(carga, protocolo="SSDP")
            if 123 in puertos:
                return self._ntp(carga)
        return self._por_puerto(puertos, carga)

    # -- DNS ---------------------------------------------------------------
    @staticmethod
    def _buscar_dns(paquete):
        """Scapy ya decodifica DNS, mDNS y LLMNR; se busca la primera capa de ese tipo."""
        capa = paquete
        while capa:
            if isinstance(capa, DNS):
                return capa
            capa = capa.payload
        return None

    def _dns(self, dns, puertos: Tuple[int, int]) -> ResultadoAplicacion:
        nombre = "mDNS" if 5353 in puertos else "LLMNR" if 5355 in puertos else "DNS"
        es_respuesta = int(dns.qr) == 1
        preguntas = _registros_dns(dns.qd)
        respuestas = _registros_dns(dns.an)

        consultas = [f"{_tipo_dns(int(q.qtype))} {_texto(q.qname)}" for q in preguntas]
        info = f"{'Respuesta' if es_respuesta else 'Consulta'} estándar 0x{int(dns.id):04x} "
        info += ", ".join(consultas) if consultas else "(sin preguntas)"
        rcode = int(dns.rcode)
        if es_respuesta and rcode:
            info += f" — {DNS_RCODES.get(rcode, rcode)}"
        elif respuestas:
            datos = [f"{_tipo_dns(int(rr.type))} {_dato_registro(rr)}" for rr in respuestas[:3]]
            info += " → " + ", ".join(datos) + (" …" if len(respuestas) > 3 else "")

        campos = [
            Campo("ID de transacción", f"0x{int(dns.id):04x}"),
            Campo("Tipo de mensaje", "Respuesta (QR = 1)" if es_respuesta else "Consulta (QR = 0)"),
            Campo("Código de operación", DNS_OPCODES.get(int(dns.opcode), str(dns.opcode))),
            Campo("Banderas", f"RD={int(dns.rd)}  RA={int(dns.ra)}  AA={int(dns.aa)}  TC={int(dns.tc)}"),
        ]
        if es_respuesta:
            campos.append(Campo("Código de respuesta", f"{DNS_RCODES.get(rcode, rcode)} ({rcode})"))
        campos.append(Campo("Preguntas / Respuestas / Autoridad / Adicionales",
                            f"{dns.qdcount} / {dns.ancount} / {dns.nscount} / {dns.arcount}"))
        campos.append(Campo("Dominios consultados", str(len(preguntas)), [
            Campo(_texto(q.qname), f"Tipo {_tipo_dns(int(q.qtype))}, clase IN") for q in preguntas]))
        if respuestas:
            campos.append(Campo("Respuestas", str(len(respuestas)), [
                Campo(_texto(rr.rrname),
                      f"{_tipo_dns(int(rr.type))} {_dato_registro(rr)}  (TTL {rr.ttl} s)")
                for rr in respuestas]))
        titulo = {"DNS": "DNS (Sistema de Nombres de Dominio)",
                  "mDNS": "mDNS (DNS de multidifusión)",
                  "LLMNR": "LLMNR (resolución de nombres local)"}[nombre]
        return ResultadoAplicacion(nombre, info, titulo, campos)

    # -- HTTP --------------------------------------------------------------
    def _http(self, carga: bytes, protocolo: str = "HTTP") -> Optional[ResultadoAplicacion]:
        es_peticion = carga.startswith(METODOS_HTTP) or carga.startswith(b"M-SEARCH ") \
            or carga.startswith(b"NOTIFY ")
        es_respuesta = carga.startswith(b"HTTP/1.")
        if not (es_peticion or es_respuesta) or b"\r\n" not in carga[:2048]:
            return None
        encabezado, separador, cuerpo = carga.partition(b"\r\n\r\n")
        lineas = encabezado.decode("iso-8859-1").split("\r\n")
        primera = lineas[0]
        encabezados: Dict[str, Tuple[str, str]] = {}
        for linea in lineas[1:]:
            nombre, dos_puntos, valor = linea.partition(":")
            if dos_puntos:
                encabezados.setdefault(nombre.strip().lower(), (nombre.strip(), valor.strip()))

        campos: List[Campo] = []
        partes = primera.split(" ", 2)
        if es_peticion and len(partes) == 3:
            metodo, uri, version = partes
            host = encabezados.get("host", ("", ""))[1]
            campos += [Campo("Tipo", "Petición"), Campo("Método", metodo),
                       Campo("URI solicitada", uri), Campo("Versión", version)]
            if host:
                campos.append(Campo("Host", host))
                if protocolo == "HTTP":
                    campos.append(Campo("URL completa", f"http://{host}{uri}"))
            uri_corta = uri if len(uri) <= 70 else uri[:67] + "..."
            info = f"{metodo} {uri_corta} {version}" + (f"  (Host: {host})" if host else "")
        elif es_respuesta and len(partes) >= 2:
            campos += [Campo("Tipo", "Respuesta"), Campo("Versión", partes[0]),
                       Campo("Código de estado", " ".join(partes[1:]))]
            info = primera
        else:
            return None

        otros = []
        for clave, (nombre, valor) in encabezados.items():
            if clave == "host":
                continue
            if clave in ENCABEZADOS_PRIVADOS:
                valor = "(presente; valor no mostrado por privacidad)"
            otros.append(Campo(nombre, valor if len(valor) <= 120 else valor[:117] + "..."))
        if otros:
            campos.append(Campo("Encabezados", str(len(otros)), otros))
        if separador:
            campos.append(Campo("Cuerpo del mensaje",
                                f"{len(cuerpo)} bytes en este segmento (no se muestra)"))
        else:
            campos.append(Campo("Encabezado", "Continúa en el siguiente segmento"))
        titulo = ("HTTP (Transferencia de Hipertexto)" if protocolo == "HTTP"
                  else "SSDP (descubrimiento de servicios)")
        return ResultadoAplicacion(protocolo, info, titulo, campos)

    # -- TLS / HTTPS -------------------------------------------------------
    def _tls(self, carga: bytes, flujo: tuple, seq: int,
             puertos: Tuple[int, int]) -> Optional[ResultadoAplicacion]:
        pendiente = self._pendientes.get(flujo)
        if pendiente is not None and seq == pendiente.siguiente_seq:
            return self._continuar_client_hello(flujo, pendiente, carga)

        if not es_encabezado_tls(carga):
            if PUERTOS_TLS.intersection(puertos):
                return ResultadoAplicacion(
                    "TLS (HTTPS)", f"Continuación de datos cifrados ({len(carga)} bytes)",
                    TITULO_TLS,
                    [Campo("Contenido", "Fragmento de un registro TLS anterior; está cifrado"),
                     Campo("Bytes en el segmento", str(len(carga)))])
            return None

        nombres, campos_registros, extra = [], [], []
        despues_de_ccs = False   # tras Change Cipher Spec el handshake ya va cifrado
        i = 0
        while es_encabezado_tls(carga, i):
            tipo, version = carga[i], _entero(carga, i + 1, 2)
            largo = _entero(carga, i + 3, 2)
            cuerpo = carga[i + 5:i + 5 + largo]
            nombre = TLS_REGISTROS[tipo]
            detalle = f"{TLS_VERSIONES.get(version, hex(version))}, {largo} bytes"
            if tipo == 20:
                despues_de_ccs = True
            if tipo == 22 and cuerpo:
                hs_tipo = cuerpo[0]
                if despues_de_ccs or hs_tipo not in TLS_HANDSHAKE:
                    nombre, hs_tipo = "Mensaje de handshake cifrado", -1
                else:
                    nombre = TLS_HANDSHAKE[hs_tipo]
                if hs_tipo == 1:
                    if len(cuerpo) < largo:      # el Client Hello sigue en otro segmento
                        self._guardar_pendiente(flujo, carga[i:], largo + 5, seq + len(carga))
                    extra = self._campos_client_hello(parsear_client_hello(cuerpo))
                elif hs_tipo == 2:
                    extra = self._campos_server_hello(parsear_server_hello(cuerpo))
            elif tipo == 23:
                detalle += " (cifrado)"
            nombres.append(nombre)
            campos_registros.append(Campo(nombre, detalle))
            if len(cuerpo) < largo:
                break
            i += 5 + largo

        info = ", ".join(dict.fromkeys(nombres))
        sni = next((c.valor for c in extra if c.nombre.startswith("Nombre del servidor")), "")
        if sni:
            info += f" (SNI: {sni})"
        if nombres and nombres[0] == "Client Hello" and flujo in self._pendientes:
            info += " — continúa en el siguiente segmento"
        campos = [Campo("Registros TLS en el segmento", str(len(campos_registros)), campos_registros)]
        campos += extra
        campos.append(Campo("Nota", "Solo se leen datos que viajan en claro; "
                                    "el contenido de Application Data está cifrado"))
        return ResultadoAplicacion("TLS (HTTPS)", info, TITULO_TLS, campos)

    def _guardar_pendiente(self, flujo: tuple, buffer: bytes, total: int, sig_seq: int) -> None:
        self._pendientes[flujo] = _ClientHelloPendiente(buffer, total, sig_seq)
        while len(self._pendientes) > MAX_FLUJOS_PENDIENTES:
            self._pendientes.popitem(last=False)

    def _continuar_client_hello(self, flujo: tuple, pendiente: _ClientHelloPendiente,
                                carga: bytes) -> ResultadoAplicacion:
        pendiente.buffer += carga
        pendiente.siguiente_seq += len(carga)
        pendiente.segmentos += 1
        completo = len(pendiente.buffer) >= pendiente.total
        if completo or pendiente.segmentos >= MAX_SEGMENTOS_REENSAMBLE:
            del self._pendientes[flujo]
        datos = parsear_client_hello(pendiente.buffer[5:pendiente.total])
        campos = [Campo("Reensamble", f"Client Hello unido a partir de {pendiente.segmentos} "
                                      f"segmentos TCP ({min(len(pendiente.buffer), pendiente.total)}"
                                      f" de {pendiente.total} bytes)")]
        campos += self._campos_client_hello(datos)
        info = "Client Hello (reensamblado)"
        if datos.get("sni"):
            info += f" (SNI: {datos['sni']})"
        if not completo and flujo in self._pendientes:
            info += " — continúa"
        return ResultadoAplicacion("TLS (HTTPS)", info, TITULO_TLS, campos)

    @staticmethod
    def _campos_client_hello(datos: Dict[str, object]) -> List[Campo]:
        campos = []
        if "version" in datos:
            v = int(datos["version"])
            campos.append(Campo("Versión en el Client Hello", TLS_VERSIONES.get(v, hex(v))))
        if datos.get("versiones"):
            campos.append(Campo("Versiones TLS ofrecidas", ", ".join(datos["versiones"])))
        if "num_suites" in datos:
            campos.append(Campo("Suites de cifrado ofrecidas", str(datos["num_suites"])))
        if datos.get("sni"):
            campos.append(Campo("Nombre del servidor (SNI)", str(datos["sni"])))
        if datos.get("alpn"):
            campos.append(Campo("Protocolos de aplicación (ALPN)", ", ".join(datos["alpn"])))
        if datos.get("truncado"):
            campos.append(Campo("Aviso", "El mensaje continúa en otro segmento; "
                                         "se muestran los campos leídos hasta aquí"))
        return campos

    @staticmethod
    def _campos_server_hello(datos: Dict[str, object]) -> List[Campo]:
        campos = []
        if "version" in datos:
            v = int(datos["version"])
            campos.append(Campo("Versión TLS acordada", TLS_VERSIONES.get(v, hex(v))))
        if "suite" in datos:
            s = int(datos["suite"])
            campos.append(Campo("Suite de cifrado elegida",
                                f"{TLS_SUITES.get(s, 'Suite')} (0x{s:04x})"))
        return campos

    # -- DHCP --------------------------------------------------------------
    @staticmethod
    def _dhcp(paquete) -> ResultadoAplicacion:
        bootp = paquete[BOOTP]
        opciones = {}
        if paquete.haslayer(DHCP):
            for opcion in paquete[DHCP].options:
                if isinstance(opcion, tuple) and len(opcion) >= 2:
                    opciones[opcion[0]] = opcion[1] if len(opcion) == 2 else opcion[1:]
        tipo = opciones.get("message-type")
        nombre_tipo = DHCP_TIPOS.get(int(tipo), str(tipo)) if tipo is not None else "BOOTP"
        mac_cliente = ":".join(f"{b:02x}" for b in bytes(bootp.chaddr)[:6])
        campos = [
            Campo("Tipo de mensaje", f"DHCP {nombre_tipo}"),
            Campo("ID de transacción", f"0x{int(bootp.xid):08x}"),
            Campo("IP del cliente (ciaddr)", str(bootp.ciaddr)),
            Campo("IP ofrecida/asignada (yiaddr)", str(bootp.yiaddr)),
            Campo("IP del agente relay (giaddr)", str(bootp.giaddr)),
            Campo("MAC del cliente", mac_cliente),
        ]
        nombres_opciones = {"server_id": "Servidor DHCP", "requested_addr": "IP solicitada",
                            "subnet_mask": "Máscara de subred", "router": "Puerta de enlace",
                            "name_server": "Servidores DNS", "lease_time": "Tiempo de concesión (s)",
                            "hostname": "Nombre del equipo", "domain": "Dominio"}
        for clave, texto in nombres_opciones.items():
            if clave in opciones:
                campos.append(Campo(texto, _texto(opciones[clave])))
        info = f"DHCP {nombre_tipo} — ID de transacción 0x{int(bootp.xid):08x}"
        return ResultadoAplicacion("DHCP", info, "DHCP (Configuración Dinámica de Host)", campos)

    # -- QUIC, NTP y otros -------------------------------------------------
    @staticmethod
    def _quic(carga: bytes) -> ResultadoAplicacion:
        primer = carga[0]
        if primer & 0x80 and len(carga) >= 5:
            version = int.from_bytes(carga[1:5], "big")
            tipo = QUIC_TIPOS.get((primer & 0x30) >> 4, "Largo")
            info = f"QUIC {tipo} (HTTPS sobre UDP, cifrado)"
            campos = [Campo("Formato de encabezado", "Largo (establecimiento de conexión)"),
                      Campo("Tipo de paquete", tipo), Campo("Versión", f"0x{version:08x}")]
        else:
            info = "QUIC datos protegidos (HTTPS sobre UDP, cifrado)"
            campos = [Campo("Formato de encabezado", "Corto (datos de la conexión ya establecida)")]
        campos.append(Campo("Contenido", f"{len(carga)} bytes cifrados"))
        return ResultadoAplicacion("QUIC", info, "QUIC (HTTPS sobre UDP)", campos)

    @staticmethod
    def _ntp(carga: bytes) -> ResultadoAplicacion:
        version, modo = (carga[0] >> 3) & 0x07, carga[0] & 0x07
        info = f"NTP versión {version}, {NTP_MODOS.get(modo, modo)}"
        return ResultadoAplicacion("NTP", info, "NTP (Protocolo de Tiempo de Red)",
                                   [Campo("Versión", str(version)),
                                    Campo("Modo", f"{NTP_MODOS.get(modo, '')} ({modo})")])

    @staticmethod
    def _por_puerto(puertos: Tuple[int, int], carga: bytes) -> Optional[ResultadoAplicacion]:
        """Servicio identificado solo por el número de puerto conocido."""
        for puerto in sorted(puertos):
            nombre = PUERTOS_CONOCIDOS.get(puerto)
            if nombre:
                return ResultadoAplicacion(
                    nombre, f"Datos de {nombre} ({len(carga)} bytes)", f"Datos de {nombre}",
                    [Campo("Servicio (por número de puerto)", f"{nombre} ({puerto})"),
                     Campo("Datos de aplicación", f"{len(carga)} bytes")])
        return None
