from scapy.all import Ether, IP, TCP, UDP, ICMP, sniff


def analizar_paquete(paquete):
    # Filtramos para procesar solo paquetes que contengan capa Ethernet e IP
    if paquete.haslayer(Ether) and paquete.haslayer(IP):
        print("=" * 65)

        # --- CAPA 2: TRAMA ETHERNET ---
        eth = paquete[Ether]
        print("[CAPA 2 - TRAMA ETHERNET]")
        print(f"  MAC Origen      : {eth.src}")
        print(f"  MAC Destino     : {eth.dst}")
        print(f"  Tipo (EtherType): {hex(eth.type)}")

        # --- CAPA 3: ENCABEZADO IP ---
        ip = paquete[IP]
        print("\n[CAPA 3 - ENCABEZADO IPv4]")
        print(f"  IP Origen       : {ip.src}")
        print(f"  IP Destino      : {ip.dst}")
        print(f"  TTL             : {ip.ttl}")
        print(f"  Longitud Total  : {ip.len} bytes")
        print(f"  Protocolo ID    : {ip.proto}")

        # --- CAPA 4: TRANSPORTE ---
        print("\n[CAPA 4 - TRANSPORTE / CONTROL]")
        if paquete.haslayer(TCP):
            tcp = paquete[TCP]
            print("  Protocolo       : TCP")
            print(f"  Puerto Origen   : {tcp.sport}")
            print(f"  Puerto Destino  : {tcp.dport}")
            print(f"  Secuencia (Seq) : {tcp.seq}")
            print(f"  Acuse (Ack)     : {tcp.ack}")
            print(f"  Banderas (Flags): {tcp.flags}")

        elif paquete.haslayer(UDP):
            udp = paquete[UDP]
            print("  Protocolo       : UDP")
            print(f"  Puerto Origen   : {udp.sport}")
            print(f"  Puerto Destino  : {udp.dport}")
            print(f"  Longitud UDP    : {udp.len} bytes")

        elif paquete.haslayer(ICMP):
            icmp = paquete[ICMP]
            print("  Protocolo       : ICMP")
            print(f"  Tipo            : {icmp.type}")
            print(f"  Código          : {icmp.code}")

        else:
            print(f"  Protocolo       : Otro (ID: {ip.proto})")

        print("=" * 65 + "\n")


def iniciar_captura():
    print("Iniciando captura de paquetes... Presiona Ctrl+C para detener.\n")
    try:
        # sniff() escucha en la interfaz de red por defecto.
        # store=0 evita que los paquetes se acumulen en la memoria RAM.
        sniff(prn=analizar_paquete, store=0)
    except PermissionError:
        print(
            "Error: Necesitas ejecutar este script como Administrador o con sudo."
        )
    except KeyboardInterrupt:
        print("\nCaptura detenida por el usuario.")


if __name__ == "__main__":
    iniciar_captura()