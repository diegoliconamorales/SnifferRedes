"""
Pruebas unitarias del analizador. No necesitan capturar tráfico ni permisos:
los paquetes se construyen con Scapy y se analizan igual que los capturados.

    python -m unittest discover -s tests -v
"""

import os
import struct
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scapy.all  # noqa: F401,E402  (registra todas las capas)
from scapy.layers.dhcp import BOOTP, DHCP  # noqa: E402
from scapy.layers.dns import DNS, DNSQR, DNSRR  # noqa: E402
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402
from scapy.utils import rdpcap, wrpcap  # noqa: E402

from analizador import analisis, filtros, volcado  # noqa: E402
from analizador.aplicacion import AnalizadorAplicacion, parsear_client_hello  # noqa: E402
from analizador.captura import MotorCaptura  # noqa: E402

MAC_A, MAC_B = "aa:bb:cc:00:00:01", "00:11:22:33:44:55"


def capturado(paquete):
    """Simula un paquete recién capturado: se reconstruye desde sus bytes."""
    nuevo = paquete.__class__(bytes(paquete))
    nuevo.time = 1763500000.0
    return nuevo


def registro(paquete, analizador=None):
    return analisis.construir_registro(capturado(paquete), 1, 1763500000.0,
                                       analizador or AnalizadorAplicacion())


def client_hello(sni: str, relleno: int = 0) -> bytes:
    """Construye un registro TLS con un Client Hello mínimo y la extensión SNI."""
    nombre = sni.encode()
    ext_sni = struct.pack("!HHHBH", 0, len(nombre) + 5, len(nombre) + 3, 0, len(nombre)) + nombre
    ext_versiones = struct.pack("!HHB", 43, 5, 4) + struct.pack("!HH", 0x0A0A, 0x0304)
    ext_alpn = struct.pack("!HHH", 16, 14, 12) + b"\x02h2\x08http/1.1"
    ext_relleno = struct.pack("!HH", 21, relleno) + b"\x00" * relleno
    # el SNI va al final para que, con relleno, quede en el segundo segmento
    extensiones = ext_versiones + ext_alpn + ext_relleno + ext_sni
    cuerpo = struct.pack("!H", 0x0303) + b"\x11" * 32 + b"\x00" + struct.pack("!H", 4) + \
        b"\x13\x01\x13\x02" + b"\x01\x00" + struct.pack("!H", len(extensiones)) + extensiones
    handshake = b"\x01" + len(cuerpo).to_bytes(3, "big") + cuerpo
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


class PruebasCapas(unittest.TestCase):
    def test_tcp_resumen(self):
        p = Ether(src=MAC_A, dst=MAC_B) / IP(src="192.168.1.70", dst="1.1.1.1") / \
            TCP(sport=50001, dport=443, flags="S", seq=100)
        r = registro(p).resumen
        self.assertEqual((r.protocolo, r.puerto_origen, r.puerto_destino), ("TCP", "50001", "443"))
        self.assertEqual((r.mac_origen, r.mac_destino), (MAC_A, MAC_B))
        self.assertIn("[SYN]", r.info)
        self.assertEqual(r.longitud, 54)

    def test_udp_y_longitud(self):
        p = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1234, dport=9999) / Raw(b"x" * 10)
        r = registro(p).resumen
        self.assertEqual(r.protocolo, "UDP")
        self.assertIn("Len=10", r.info)

    def test_icmp_eco(self):
        p = Ether() / IP(src="192.168.1.70", dst="8.8.8.8") / ICMP(type=8, id=1, seq=7)
        r = registro(p).resumen
        self.assertEqual(r.protocolo, "ICMP")
        self.assertIn("Solicitud de eco", r.info)
        self.assertIn("seq=7", r.info)

    def test_arp(self):
        p = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="192.168.1.70", pdst="192.168.1.254")
        r = registro(p).resumen
        self.assertEqual(r.protocolo, "ARP")
        self.assertIn("¿Quién tiene 192.168.1.254?", r.info)

    def test_detalle_rangos_de_bytes(self):
        p = Ether() / IP() / TCP() / Raw(b"hola")
        paquete = capturado(p)
        secciones = analisis.detallar(paquete)
        rangos = {s.titulo.split(" (")[0]: (s.inicio, s.longitud) for s in secciones}
        self.assertEqual(rangos["Ethernet II"], (0, 14))
        self.assertEqual(rangos["IPv4"], (14, 20))
        self.assertEqual(rangos["TCP"], (34, 20))
        self.assertEqual(rangos["Carga útil"], (54, 4))
        transporte = analisis.capa_transporte(analisis.capa_red(paquete))
        self.assertEqual(analisis.rango_carga(paquete, transporte, len(paquete)), (54, 4))

    def test_segmento_unido_ipv6_longitud_cero(self):
        """Trama >1500 bytes con longitud IPv6 en 0 (segmentos unidos por la tarjeta)."""
        from scapy.layers.inet6 import IPv6
        datos = bytearray(bytes(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") /
                                TCP(sport=5000, dport=50000, flags="A") / Raw(b"x" * 4000)))
        datos[18:20] = b"\x00\x00"           # campo "longitud de la carga útil" = 0
        r = registro(Ether(bytes(datos))).resumen
        self.assertEqual((r.protocolo, r.puerto_origen, r.puerto_destino), ("TCP", "5000", "50000"))
        self.assertIn("Len=4000", r.info)

    def test_relleno_ethernet_no_es_carga(self):
        p = Ether() / IP() / TCP(flags="A")
        datos = bytes(p) + b"\x00" * 6       # trama mínima de 60 bytes
        paquete = Ether(datos)
        transporte = analisis.capa_transporte(analisis.capa_red(paquete))
        self.assertEqual(analisis.rango_carga(paquete, transporte, len(datos))[1], 0)


class PruebasAplicacion(unittest.TestCase):
    def test_dns_consulta_y_respuesta(self):
        base = Ether() / IP(src="192.168.1.70", dst="8.8.8.8")
        consulta = base / UDP(sport=50000, dport=53) / DNS(id=0xF89B, rd=1, qd=DNSQR(qname="www.escom.ipn.mx"))
        r = registro(consulta)
        self.assertEqual(r.resumen.aplicacion, "DNS")
        self.assertIn("www.escom.ipn.mx", r.resumen.info)
        self.assertIn("0xf89b", r.resumen.info)
        respuesta = base / UDP(sport=53, dport=50000) / DNS(
            id=0xF89B, qr=1, qd=DNSQR(qname="www.escom.ipn.mx"),
            an=DNSRR(rrname="www.escom.ipn.mx", type="A", rdata="148.204.103.161"))
        r = registro(respuesta)
        self.assertIn("148.204.103.161", r.resumen.info)

    def test_http_peticion_oculta_cookie(self):
        carga = b"GET /prueba HTTP/1.1\r\nHost: neverssl.com\r\nCookie: sesion=123\r\n\r\n"
        p = Ether() / IP() / TCP(sport=50000, dport=80, flags="PA") / Raw(carga)
        r = registro(p)
        self.assertEqual(r.resumen.aplicacion, "HTTP")
        self.assertIn("GET /prueba", r.resumen.info)
        campos = {c.nombre: c.valor for c in r.aplicacion.campos}
        self.assertEqual(campos["URL completa"], "http://neverssl.com/prueba")
        encabezados = next(c for c in r.aplicacion.campos if c.nombre == "Encabezados")
        self.assertNotIn("123", encabezados.hijos[0].valor)

    def test_http_en_puerto_no_estandar(self):
        p = Ether() / IP() / TCP(sport=50000, dport=8000, flags="PA") / Raw(b"POST /api HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertEqual(registro(p).resumen.aplicacion, "HTTP")

    def test_tls_sni_en_un_segmento(self):
        p = Ether() / IP() / TCP(sport=50000, dport=443, flags="PA") / Raw(client_hello("www.escom.ipn.mx"))
        r = registro(p)
        self.assertEqual(r.resumen.aplicacion, "TLS (HTTPS)")
        self.assertIn("Client Hello", r.resumen.info)
        self.assertIn("SNI: www.escom.ipn.mx", r.resumen.info)

    def test_tls_client_hello_en_dos_segmentos(self):
        hello = client_hello("www.ipn.mx", relleno=1500)
        corte = 1200
        analizador = AnalizadorAplicacion()
        ip = IP(src="192.168.1.70", dst="148.204.103.2")
        uno = Ether() / ip / TCP(sport=50000, dport=443, seq=1000, flags="A") / Raw(hello[:corte])
        dos = Ether() / ip / TCP(sport=50000, dport=443, seq=1000 + corte, flags="PA") / Raw(hello[corte:])
        r1 = registro(uno, analizador)
        self.assertIn("continúa", r1.resumen.info)
        r2 = registro(dos, analizador)
        self.assertIn("SNI: www.ipn.mx", r2.resumen.info)

    def test_parser_client_hello_ignora_grease(self):
        datos = parsear_client_hello(client_hello("a.b")[5:])
        self.assertEqual(datos["versiones"], ["TLS 1.3"])
        self.assertEqual(datos["alpn"], ["h2", "http/1.1"])

    def test_dhcp(self):
        p = Ether() / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / \
            BOOTP(xid=0x1234ABCD) / DHCP(options=[("message-type", "request"), "end"])
        r = registro(p)
        self.assertEqual(r.resumen.aplicacion, "DHCP")
        self.assertIn("Request", r.resumen.info)


class PruebasFiltrosYVolcado(unittest.TestCase):
    def test_predefinidos_usan_ip_local(self):
        lista = filtros.filtros_predefinidos("10.100.83.139")
        expresiones = [f.expresion for f in lista]
        for esperado in ("tcp port 80", "tcp port 443", "udp port 53", "icmp", "tcp", "udp",
                         "host 10.100.83.139", "net 10.100.83.0/24", "port 443"):
            self.assertIn(esperado, expresiones)

    def test_validacion_filtro(self):
        valido, _ = filtros.validar_filtro("")
        self.assertTrue(valido)
        valido, mensaje = filtros.validar_filtro("tcp prot 80")
        if valido is None:
            self.skipTest("libpcap no está disponible en este equipo: " + mensaje)
        self.assertFalse(valido)
        self.assertTrue(filtros.validar_filtro("tcp port 80 or udp port 53")[0])

    def test_volcado_hex_y_columnas(self):
        lineas = volcado.volcado_hex(bytes(range(65, 65 + 20)))
        self.assertEqual(len(lineas), 2)
        self.assertTrue(lineas[0].startswith("0000  41 42 43"))
        self.assertTrue(lineas[0].endswith("ABCDEFGH IJKLMNOP"))
        h, a = volcado.columnas_byte(9)
        self.assertEqual(lineas[0][h:h + 2], "4a")
        self.assertEqual(lineas[0][a], "J")


class PruebasAlmacenamiento(unittest.TestCase):
    def test_guardar_pcap_y_pcapng(self):
        paquetes = [Ether() / IP(dst="10.0.0.%d" % i) / ICMP() for i in range(1, 6)]
        carpeta = tempfile.mkdtemp()
        origen = os.path.join(carpeta, "origen.pcap")
        wrpcap(origen, paquetes)
        motor = MotorCaptura()
        motor.abrir_pcap(origen)
        while motor.estado != "detenido":
            time.sleep(0.01)
        self.assertEqual(motor.total, 5)
        for extension in (".pcap", ".pcapng"):
            destino = os.path.join(carpeta, "salida" + extension)
            self.assertEqual(motor.guardar_pcap(destino), 5)
            leidos = rdpcap(destino)
            self.assertEqual(len(leidos), 5)
            self.assertEqual(bytes(leidos[2]), bytes(paquetes[2]))
        motor.descartar()


if __name__ == "__main__":
    unittest.main()
