"""
gui.py
------
Interfaz gráfica (Tkinter) del analizador de tráfico de red (Módulo 5).

La ventana se organiza en las cuatro secciones que propone la guía:
    1. Configuración de captura  -> interfaz, filtro BPF, Iniciar / Detener, Guardar PCAP
    2. Listado de paquetes       -> una fila por paquete capturado
    3. Información detallada     -> campos por capa del paquete seleccionado
    4. Carga útil                -> volcado hexadecimal y ASCII

La captura corre en un hilo aparte (AsyncSniffer, ver analizador/captura.py).
Esta ventana nunca se queda esperando a la red: cada INTERVALO_MS milisegundos
root.after() revisa la cola y agrega a la tabla los paquetes nuevos.
"""

from __future__ import annotations

import os
import queue
import sys
import time
from collections import OrderedDict
from typing import Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

from analizador import analisis, captura, filtros, volcado
from analizador.modelos import RegistroPaquete

# ---------------------------------------------------------------------------
# Apariencia y parámetros
# ---------------------------------------------------------------------------
COLOR_PRINCIPAL = "#6C1D45"     # guinda IPN
COLOR_FONDO = "#F4F1F3"
COLOR_TEXTO_SUAVE = "#5A5A5A"
COLOR_VERDE = "#2E7D32"
COLOR_ROJO = "#B23A3A"

INTERVALO_MS = 100              # cada cuánto se revisa la cola de paquetes
LOTE_MAXIMO = 400               # paquetes que se agregan a la tabla por ciclo
MAX_PAQUETES_EN_MEMORIA = 10000 # los más antiguos salen de la tabla (siguen en el PCAP)

COLUMNAS = [  # (id, encabezado, ancho, alineación)
    ("no", "No.", 62, "e"), ("tiempo", "Tiempo", 92, "e"),
    ("mac_o", "MAC origen", 124, "w"), ("mac_d", "MAC destino", 124, "w"),
    ("ip_o", "IP origen", 235, "w"), ("ip_d", "IP destino", 235, "w"),   # caben direcciones IPv6
    ("proto", "Protocolo", 80, "center"), ("p_o", "Puerto origen", 112, "center"),
    ("p_d", "Puerto destino", 118, "center"), ("long", "Longitud", 74, "e"),
    ("app", "Aplicación", 96, "center"), ("info", "Información", 460, "w"),
]

COLORES_FILA = {  # colores parecidos a los de Wireshark
    "tcp": ("#E7E6FF", "#12272E"), "syn": ("#DADADA", "#12272E"),
    "rst": ("#FFD9D9", "#7A0000"), "udp": ("#DAEEFF", "#12272E"),
    "dns": ("#CDEBFF", "#12272E"), "http": ("#E4FFC7", "#12272E"),
    "tls": ("#EFE5FF", "#12272E"), "icmp": ("#FCE0FF", "#12272E"),
    "arp": ("#FAF0D7", "#12272E"), "dhcp": ("#DFF7F2", "#12272E"),
    "otro": ("#FFFFFF", "#12272E"),
}

TEXTO_PERSONALIZADO = "Personalizado (escrito a mano)"

TEXTO_GUIA_BPF = """\
¿Qué es un filtro BPF?
BPF (Berkeley Packet Filter) es un lenguaje para describir qué paquetes se quieren
capturar. La expresión se compila en un pequeño programa que el controlador de captura
(Npcap en Windows, el kernel en Linux) ejecuta por cada paquete. Solo los paquetes que
cumplen la condición llegan a Python; los demás se descartan antes.

Filtro de captura (BPF) vs. filtro de visualización
  • El filtro BPF se aplica DURANTE la captura: lo que no cumple nunca se guarda.
  • El filtro de visualización (barra de la tabla) se aplica DESPUÉS: solo oculta
    filas de paquetes que ya se capturaron y que siguen en el PCAP.

Primitivas más usadas
  host 192.168.1.10        tráfico de o hacia esa IP
  src host 192.168.1.10    solo paquetes cuyo ORIGEN es esa IP
  dst host 192.168.1.10    solo paquetes cuyo DESTINO es esa IP
  net 192.168.1.0/24       tráfico de una red completa
  port 443                 puerto 443 en TCP o UDP (origen o destino)
  tcp port 80              solo TCP con puerto 80
  udp port 53              solo UDP con puerto 53 (DNS)
  portrange 1-1024         rango de puertos
  icmp / tcp / udp / arp   por protocolo
  ether host aa:bb:cc:dd:ee:ff   por dirección MAC

Operadores
  and (&&), or (||), not (!) y paréntesis. Ejemplos:
  tcp port 80 or tcp port 443
  host 192.168.1.10 and not port 53
  icmp and src host 10.0.0.1
"""


def _elegir_fuente(raiz: tk.Misc, opciones: List[str], respaldo: str) -> str:
    disponibles = {f.lower() for f in tkfont.families(raiz)}
    for familia in opciones:
        if familia.lower() in disponibles:
            return familia
    return respaldo


class AplicacionSniffer:
    """Ventana principal del analizador."""

    def __init__(self, raiz: tk.Tk) -> None:
        self.raiz = raiz
        self.motor = captura.MotorCaptura()
        self.interfaces: List[captura.InterfazRed] = []
        self.predefinidos: List[filtros.FiltroPredefinido] = []
        self.registros: "OrderedDict[int, RegistroPaquete]" = OrderedDict()
        self.registro_actual: Optional[RegistroPaquete] = None
        self.rango_carga: Tuple[int, int] = (0, 0)
        self.rango_seleccion: Optional[Tuple[int, int]] = None
        self.rangos_detalle: Dict[str, Tuple[int, int]] = {}
        self.contadores: Dict[str, int] = {}
        self.sin_guardar = False
        self.filtro_vista: List[str] = []
        self.filtro_activo = ""
        self._id_validacion: Optional[str] = None
        self._tasa_ref = (time.time(), 0)
        self._tasa = 0.0
        self._cerrando = False
        self.origen = "vivo"            # "vivo" (captura) o "archivo" (PCAP abierto)
        self._texto_captura = ""

        self._configurar_estilos()
        self._construir_menu()
        self._construir_encabezado()
        self._construir_configuracion()
        # la barra de estado se coloca antes que los paneles: con pack(), el widget que
        # se empaca primero conserva su espacio y los paneles toman lo que sobra
        self._construir_barra_estado()
        self._construir_paneles()
        self._atajos()
        self.actualizar_interfaces(recargar=False)
        self._validar_filtro()
        self._poner_estado(captura.DETENIDO)
        self.raiz.protocol("WM_DELETE_WINDOW", self.al_cerrar)
        self.raiz.after(INTERVALO_MS, self._ciclo)

    # ------------------------------------------------------------------
    # Construcción de la ventana
    # ------------------------------------------------------------------
    def _configurar_estilos(self) -> None:
        r = self.raiz
        self.fuente = _elegir_fuente(r, ["Segoe UI", "Noto Sans", "DejaVu Sans"], "TkDefaultFont")
        self.fuente_mono = _elegir_fuente(r, ["Consolas", "Cascadia Mono", "DejaVu Sans Mono",
                                              "Liberation Mono", "Courier New"], "TkFixedFont")
        estilo = ttk.Style(r)
        if "clam" in estilo.theme_names():
            estilo.theme_use("clam")
        r.configure(background=COLOR_FONDO)
        base = (self.fuente, 10)
        negrita = (self.fuente, 10, "bold")
        estilo.configure(".", font=base, background=COLOR_FONDO)
        estilo.configure("TFrame", background=COLOR_FONDO)
        estilo.configure("TLabel", background=COLOR_FONDO)
        estilo.configure("TCheckbutton", background=COLOR_FONDO)
        estilo.configure("TRadiobutton", background=COLOR_FONDO)
        estilo.configure("TLabelframe", background=COLOR_FONDO)
        estilo.configure("TLabelframe.Label", background=COLOR_FONDO, foreground=COLOR_PRINCIPAL,
                         font=negrita)
        estilo.configure("Sub.TLabel", foreground=COLOR_TEXTO_SUAVE)
        estilo.configure("Contador.TLabel", font=(self.fuente, 15, "bold"), foreground=COLOR_PRINCIPAL)
        estilo.configure("Estado.TLabel", font=(self.fuente, 11, "bold"))
        estilo.configure("TButton", padding=(10, 5))
        for nombre, color, activo in (("Iniciar", COLOR_VERDE, "#388E3C"),
                                      ("Detener", COLOR_ROJO, "#C94A4A"),
                                      ("Accion", COLOR_PRINCIPAL, "#8E2A5D")):
            estilo.configure(f"{nombre}.TButton", font=negrita, foreground="white",
                             background=color, padding=(14, 6))
            estilo.map(f"{nombre}.TButton",
                       background=[("disabled", "#C9C3C6"), ("active", activo)],
                       foreground=[("disabled", "#F2F2F2")])
        alto = tkfont.Font(root=r, font=(self.fuente_mono, 10)).metrics("linespace") + 6
        estilo.configure("Treeview", rowheight=alto, font=base)
        estilo.configure("Treeview.Heading", font=negrita, background="#E4D3DC", foreground="#3A0F25")
        estilo.configure("Paquetes.Treeview", font=(self.fuente, 9))

    def _construir_menu(self) -> None:
        barra = tk.Menu(self.raiz)
        archivo = tk.Menu(barra, tearoff=False)
        archivo.add_command(label="Abrir PCAP...", accelerator="Ctrl+O", command=self.abrir_pcap)
        archivo.add_command(label="Guardar PCAP...", accelerator="Ctrl+S", command=self.guardar_pcap)
        archivo.add_separator()
        archivo.add_command(label="Salir", command=self.al_cerrar)
        barra.add_cascade(label="Archivo", menu=archivo)
        menu_captura = tk.Menu(barra, tearoff=False)
        menu_captura.add_command(label="Iniciar / Detener", accelerator="Ctrl+E",
                                 command=self.alternar_captura)
        menu_captura.add_command(label="Limpiar tabla", command=self.limpiar)
        menu_captura.add_command(label="Actualizar interfaces", command=self.actualizar_interfaces)
        barra.add_cascade(label="Captura", menu=menu_captura)
        ayuda = tk.Menu(barra, tearoff=False)
        ayuda.add_command(label="Guía de filtros BPF", command=self.mostrar_guia_bpf)
        ayuda.add_command(label="Acerca de", command=self.mostrar_acerca_de)
        barra.add_cascade(label="Ayuda", menu=ayuda)
        self.raiz.config(menu=barra)

    def _construir_encabezado(self) -> None:
        marco = tk.Frame(self.raiz, background=COLOR_PRINCIPAL)
        marco.pack(fill="x")
        tk.Label(marco, text="Analizador de Tráfico de Red (Sniffer)", bg=COLOR_PRINCIPAL, fg="white",
                 font=(self.fuente, 15, "bold")).pack(side="left", padx=(14, 10), pady=8)
        tk.Label(marco, text="Captura y análisis de paquetes con Python, Scapy y Tkinter",
                 bg=COLOR_PRINCIPAL, fg="#E9D6E0", font=(self.fuente, 10)).pack(side="left", pady=8)
        tk.Label(marco, text="Redes de Computadoras · ESCOM - IPN", bg=COLOR_PRINCIPAL, fg="#E9D6E0",
                 font=(self.fuente, 10)).pack(side="right", padx=14)

    def _construir_configuracion(self) -> None:
        marco = ttk.LabelFrame(self.raiz, text="1. Configuración de captura", padding=(10, 6))
        marco.pack(fill="x", padx=10, pady=(8, 4))
        marco.columnconfigure(1, weight=1)

        # Fila 0: interfaz
        ttk.Label(marco, text="Interfaz de red:").grid(row=0, column=0, sticky="w", pady=3)
        self.combo_interfaz = ttk.Combobox(marco, state="readonly", width=70)
        self.combo_interfaz.grid(row=0, column=1, columnspan=2, sticky="ew", padx=6)
        self.combo_interfaz.bind("<<ComboboxSelected>>", lambda e: self._al_cambiar_interfaz())
        self.btn_actualizar = ttk.Button(marco, text="Actualizar", command=self.actualizar_interfaces)
        self.btn_actualizar.grid(row=0, column=3, sticky="w")
        self.var_promiscuo = tk.BooleanVar(value=True)
        self.chk_promiscuo = ttk.Checkbutton(marco, text="Modo promiscuo", variable=self.var_promiscuo)
        self.chk_promiscuo.grid(row=0, column=4, sticky="w", padx=(12, 0))

        # Fila 1: filtro BPF
        ttk.Label(marco, text="Filtro BPF:").grid(row=1, column=0, sticky="w", pady=3)
        fila_filtro = ttk.Frame(marco)
        fila_filtro.grid(row=1, column=1, columnspan=4, sticky="ew", padx=6)
        fila_filtro.columnconfigure(1, weight=1)
        self.combo_filtro = ttk.Combobox(fila_filtro, state="readonly", width=30)
        self.combo_filtro.grid(row=0, column=0, sticky="w")
        self.combo_filtro.bind("<<ComboboxSelected>>", lambda e: self._al_elegir_filtro())
        self.var_filtro = tk.StringVar()
        self.ent_filtro = ttk.Entry(fila_filtro, textvariable=self.var_filtro,
                                    font=(self.fuente_mono, 11))
        self.ent_filtro.grid(row=0, column=1, sticky="ew", padx=6)
        self.ent_filtro.bind("<KeyRelease>", lambda e: self._programar_validacion())
        self.ent_filtro.bind("<Return>", lambda e: self.iniciar())
        self.lbl_validacion = ttk.Label(fila_filtro, text="", width=46)
        self.lbl_validacion.grid(row=0, column=2, sticky="w")

        # Fila 2: botones, estado y contador
        botones = ttk.Frame(marco)
        botones.grid(row=2, column=0, columnspan=5, sticky="ew", pady=(6, 0))
        self.btn_iniciar = ttk.Button(botones, text="▶  Iniciar captura", style="Iniciar.TButton",
                                      command=self.iniciar)
        self.btn_detener = ttk.Button(botones, text="■  Detener", style="Detener.TButton",
                                      command=self.detener)
        self.btn_guardar = ttk.Button(botones, text="Guardar PCAP", style="Accion.TButton",
                                      command=self.guardar_pcap)
        self.btn_abrir = ttk.Button(botones, text="Abrir PCAP", command=self.abrir_pcap)
        self.btn_limpiar = ttk.Button(botones, text="Limpiar", command=self.limpiar)
        for i, boton in enumerate((self.btn_iniciar, self.btn_detener, self.btn_guardar,
                                   self.btn_abrir, self.btn_limpiar)):
            boton.pack(side="left", padx=(0 if i == 0 else 6, 0))

        indicador = ttk.Frame(botones)
        indicador.pack(side="right")
        self.lienzo_estado = tk.Canvas(indicador, width=18, height=18, highlightthickness=0,
                                       background=COLOR_FONDO)
        self.lienzo_estado.pack(side="left")
        self.circulo = self.lienzo_estado.create_oval(2, 2, 16, 16, fill="#9E9E9E", outline="")
        self.lbl_estado = ttk.Label(indicador, text="Detenido", style="Estado.TLabel", width=24)
        self.lbl_estado.pack(side="left", padx=(6, 18))
        ttk.Label(indicador, text="Paquetes:", style="Sub.TLabel").pack(side="left")
        self.lbl_contador = ttk.Label(indicador, text="0", style="Contador.TLabel", width=8)
        self.lbl_contador.pack(side="left", padx=(4, 0))

    def _construir_paneles(self) -> None:
        vertical = ttk.PanedWindow(self.raiz, orient="vertical")
        vertical.pack(fill="both", expand=True, padx=10, pady=4)

        # --- 2. Listado de paquetes ---
        marco_lista = ttk.LabelFrame(vertical, text="2. Listado de paquetes", padding=(6, 4))
        vertical.add(marco_lista, weight=5)
        barra = ttk.Frame(marco_lista)
        barra.pack(fill="x", pady=(0, 4))
        ttk.Label(barra, text="Filtro de visualización (después de capturar):").pack(side="left")
        self.var_vista = tk.StringVar()
        entrada_vista = ttk.Entry(barra, textvariable=self.var_vista, width=34)
        entrada_vista.pack(side="left", padx=6)
        entrada_vista.bind("<Return>", lambda e: self.aplicar_filtro_vista())
        ttk.Button(barra, text="Aplicar", command=self.aplicar_filtro_vista).pack(side="left")
        ttk.Button(barra, text="Quitar", command=self.quitar_filtro_vista).pack(side="left", padx=4)
        self.lbl_vista = ttk.Label(barra, text="", style="Sub.TLabel")
        self.lbl_vista.pack(side="left", padx=8)
        self.var_autoscroll = tk.BooleanVar(value=True)
        ttk.Checkbutton(barra, text="Desplazamiento automático",
                        variable=self.var_autoscroll).pack(side="right")

        tabla_marco = ttk.Frame(marco_lista)
        tabla_marco.pack(fill="both", expand=True)
        self.tabla = ttk.Treeview(tabla_marco, columns=[c[0] for c in COLUMNAS], show="headings",
                                  style="Paquetes.Treeview", selectmode="browse")
        for clave, titulo, ancho, alineacion in COLUMNAS:
            self.tabla.heading(clave, text=titulo, anchor=alineacion)
            self.tabla.column(clave, width=ancho, minwidth=40, anchor=alineacion,
                              stretch=(clave == "info"))
        for etiqueta, (fondo, texto) in COLORES_FILA.items():
            self.tabla.tag_configure(etiqueta, background=fondo, foreground=texto)
        self._con_barras(tabla_marco, self.tabla)
        self.tabla.bind("<<TreeviewSelect>>", lambda e: self._al_seleccionar_paquete())
        self.tabla.bind("<Control-c>", lambda e: self._copiar_fila())

        # --- 3 y 4: detalle y carga útil ---
        horizontal = ttk.PanedWindow(vertical, orient="horizontal")
        vertical.add(horizontal, weight=4)

        marco_detalle = ttk.LabelFrame(horizontal, text="3. Información detallada", padding=(6, 4))
        horizontal.add(marco_detalle, weight=1)
        detalle_marco = ttk.Frame(marco_detalle)
        detalle_marco.pack(fill="both", expand=True)
        self.detalle = ttk.Treeview(detalle_marco, columns=("valor",), show="tree headings",
                                    selectmode="browse")
        self.detalle.heading("#0", text="Campo", anchor="w")
        self.detalle.heading("valor", text="Valor", anchor="w")
        self.detalle.column("#0", width=330, minwidth=160, stretch=False)
        self.detalle.column("valor", width=360, minwidth=160, stretch=True)
        self.detalle.tag_configure("seccion", background="#EFE3EA", foreground="#3A0F25",
                                   font=(self.fuente, 10, "bold"))
        self._con_barras(detalle_marco, self.detalle)
        self.detalle.bind("<<TreeviewSelect>>", lambda e: self._al_seleccionar_detalle())
        self.detalle.bind("<Control-c>", lambda e: self._copiar_detalle())

        marco_hex = ttk.LabelFrame(horizontal, text="4. Carga útil (hexadecimal y ASCII)",
                                   padding=(6, 4))
        horizontal.add(marco_hex, weight=1)
        opciones = ttk.Frame(marco_hex)
        opciones.pack(fill="x")
        self.var_modo_hex = tk.StringVar(value="trama")
        ttk.Radiobutton(opciones, text="Trama completa", value="trama", variable=self.var_modo_hex,
                        command=self._mostrar_hex).pack(side="left")
        ttk.Radiobutton(opciones, text="Solo carga útil", value="carga", variable=self.var_modo_hex,
                        command=self._mostrar_hex).pack(side="left", padx=10)
        tk.Label(opciones, text="  carga útil  ", bg="#FFF1B8", font=(self.fuente, 9)).pack(side="right")
        tk.Label(opciones, text="  sección seleccionada  ", bg="#F3C6DD",
                 font=(self.fuente, 9)).pack(side="right", padx=4)
        self.lbl_hex = ttk.Label(marco_hex, text="Selecciona un paquete de la tabla.",
                                 style="Sub.TLabel")
        self.lbl_hex.pack(fill="x", pady=(2, 4))
        texto_marco = ttk.Frame(marco_hex)
        texto_marco.pack(fill="both", expand=True)
        self.texto_hex = tk.Text(texto_marco, font=(self.fuente_mono, 10), wrap="none",
                                 background="white", relief="flat", padx=6, pady=4, width=76,
                                 state="disabled", cursor="arrow")
        self.texto_hex.tag_configure("carga", background="#FFF1B8")
        self.texto_hex.tag_configure("seleccion", background="#F3C6DD")
        self.texto_hex.tag_raise("seleccion")
        self._con_barras(texto_marco, self.texto_hex)

    def _construir_barra_estado(self) -> None:
        barra = ttk.Frame(self.raiz, padding=(10, 3))
        barra.pack(fill="x", side="bottom")
        self.lbl_mensaje = ttk.Label(barra, text="", style="Sub.TLabel")
        self.lbl_mensaje.pack(side="left")
        self.lbl_tiempo = ttk.Label(barra, text="", style="Sub.TLabel")
        self.lbl_tiempo.pack(side="right")
        self.lbl_tasa = ttk.Label(barra, text="", style="Sub.TLabel")
        self.lbl_tasa.pack(side="right", padx=14)
        self.lbl_protocolos = ttk.Label(barra, text="", style="Sub.TLabel")
        self.lbl_protocolos.pack(side="right", padx=14)

    @staticmethod
    def _con_barras(marco: ttk.Frame, widget) -> None:
        barra_v = ttk.Scrollbar(marco, orient="vertical", command=widget.yview)
        barra_h = ttk.Scrollbar(marco, orient="horizontal", command=widget.xview)
        widget.configure(yscrollcommand=barra_v.set, xscrollcommand=barra_h.set)
        widget.grid(row=0, column=0, sticky="nsew")
        barra_v.grid(row=0, column=1, sticky="ns")
        barra_h.grid(row=1, column=0, sticky="ew")
        marco.rowconfigure(0, weight=1)
        marco.columnconfigure(0, weight=1)

    def _atajos(self) -> None:
        self.raiz.bind_all("<Control-e>", lambda e: self.alternar_captura())
        self.raiz.bind_all("<Control-s>", lambda e: self.guardar_pcap())
        self.raiz.bind_all("<Control-o>", lambda e: self.abrir_pcap())

    # ------------------------------------------------------------------
    # Interfaces y filtros
    # ------------------------------------------------------------------
    def actualizar_interfaces(self, recargar: bool = True) -> None:
        anterior = self.interfaz_seleccionada()
        try:
            self.interfaces = captura.listar_interfaces() if recargar or not self.interfaces \
                else self.interfaces
        except Exception as error:
            self.interfaces = []
            messagebox.showerror("Interfaces", f"No se pudieron obtener las interfaces:\n{error}")
        self.combo_interfaz["values"] = [i.etiqueta() for i in self.interfaces]
        if not self.interfaces:
            self.combo_interfaz.set("")
            self._mensaje("No se encontraron interfaces. En Windows revisa que Npcap esté instalado.")
        else:
            indice = 0
            if anterior is not None:
                for k, iface in enumerate(self.interfaces):
                    if iface.nombre == anterior.nombre:
                        indice = k
            self.combo_interfaz.current(indice)
        self._al_cambiar_interfaz()

    def interfaz_seleccionada(self) -> Optional[captura.InterfazRed]:
        try:
            indice = self.combo_interfaz.current()
        except (tk.TclError, AttributeError):
            return None
        return self.interfaces[indice] if 0 <= indice < len(self.interfaces) else None

    def _al_cambiar_interfaz(self) -> None:
        iface = self.interfaz_seleccionada()
        actual = self.combo_filtro.current() if self.predefinidos else 0
        self.predefinidos = filtros.filtros_predefinidos(iface.ip if iface else None)
        self.combo_filtro["values"] = [f"{f.nombre}" + (f"  ({f.expresion})" if f.expresion else "")
                                       for f in self.predefinidos] + [TEXTO_PERSONALIZADO]
        self.combo_filtro.current(max(0, actual))
        if actual in (7, 8):   # IP o red específica: se actualiza con la IP de la interfaz
            self._al_elegir_filtro()
        self._mensaje("Listo. Elige la interfaz y el filtro, y pulsa Iniciar captura."
                      if iface else self.lbl_mensaje.cget("text"))

    def _al_elegir_filtro(self) -> None:
        indice = self.combo_filtro.current()
        if 0 <= indice < len(self.predefinidos):
            self.var_filtro.set(self.predefinidos[indice].expresion)
        else:                   # "Personalizado": se escribe la expresión a mano
            self.ent_filtro.focus_set()
        self._validar_filtro()

    def _sincronizar_lista_filtros(self) -> None:
        """Si la expresión escrita no es la de un filtro predefinido, la lista dice Personalizado."""
        texto = " ".join(self.var_filtro.get().split())
        for indice, filtro in enumerate(self.predefinidos):
            if filtro.expresion == texto:
                self.combo_filtro.current(indice)
                return
        self.combo_filtro.current(len(self.predefinidos))

    def _programar_validacion(self) -> None:
        self._sincronizar_lista_filtros()
        if self._id_validacion:
            self.raiz.after_cancel(self._id_validacion)
        self._id_validacion = self.raiz.after(350, self._validar_filtro)

    def _validar_filtro(self) -> Optional[bool]:
        self._id_validacion = None
        valido, mensaje = filtros.validar_filtro(self.var_filtro.get())
        color = {True: COLOR_VERDE, False: COLOR_ROJO, None: COLOR_TEXTO_SUAVE}[valido]
        simbolo = {True: "✔", False: "✖", None: "•"}[valido]
        self.lbl_validacion.configure(text=f"{simbolo} {mensaje}", foreground=color)
        return valido

    # ------------------------------------------------------------------
    # Acciones principales
    # ------------------------------------------------------------------
    def alternar_captura(self) -> None:
        if self.motor.estado == captura.CAPTURANDO:
            self.detener()
        else:
            self.iniciar()

    def iniciar(self) -> None:
        if self.motor.estado != captura.DETENIDO:
            return
        if not self._confirmar_descarte():
            return
        if self._validar_filtro() is False:
            messagebox.showerror("Filtro BPF", self.lbl_validacion.cget("text")[2:] +
                                 "\n\nCorrige la expresión o elige un filtro predefinido.")
            self.ent_filtro.focus_set()
            return
        iface = self.interfaz_seleccionada()
        filtro = self.var_filtro.get().strip()
        try:
            self.motor.iniciar(iface, filtro, self.var_promiscuo.get())
        except Exception as error:
            messagebox.showerror("No se pudo iniciar la captura", self.motor.explicar_error(error))
            return
        self._limpiar_vista()
        self.filtro_activo = filtro
        self.origen = "vivo"
        self._tasa_ref = (time.time(), 0)
        self._poner_estado(captura.CAPTURANDO)
        nombre = iface.nombre if iface else "interfaz predeterminada"
        self._texto_captura = f"Capturando en {nombre}" + (f" con el filtro «{filtro}»" if filtro
                                                          else " sin filtro (todo el tráfico)")
        self._mensaje(f"Abriendo la interfaz {nombre}...")

    def detener(self) -> None:
        if self.motor.estado == captura.LEYENDO:
            self.motor.estado = captura.DETENIENDO   # el hilo lector se detiene solo
            self._poner_estado(captura.DETENIENDO)
            return
        if self.motor.estado != captura.CAPTURANDO:
            return
        self.motor.detener()
        self._poner_estado(captura.DETENIENDO)

    def limpiar(self) -> None:
        if self.motor.estado != captura.DETENIDO:
            messagebox.showinfo("Limpiar", "Detén la captura antes de limpiar la tabla.")
            return
        if not self._confirmar_descarte():
            return
        self.motor.descartar()
        self._limpiar_vista()
        self._poner_estado(captura.DETENIDO)
        self._mensaje("Tabla vacía.")

    def guardar_pcap(self) -> None:
        if self.motor.estado in (captura.CAPTURANDO, captura.DETENIENDO):
            messagebox.showinfo("Guardar PCAP", "Detén la captura antes de guardar.")
            return
        if self.motor.total == 0:
            messagebox.showinfo("Guardar PCAP", "Todavía no hay paquetes capturados.")
            return
        nombre = time.strftime("captura_%Y%m%d_%H%M%S")
        tipo = tk.StringVar(master=self.raiz, value="Archivo PCAP")
        # Sin defaultextension: si se usara, Windows agregaría siempre ".pcap" (y preguntaría
        # por reemplazar ese archivo) aunque se eligiera el tipo PCAPNG. La extensión la
        # pone el programa según el tipo elegido en el diálogo.
        destino = filedialog.asksaveasfilename(
            title="Guardar captura", initialfile=nombre, typevariable=tipo,
            filetypes=[("Archivo PCAP", "*.pcap"), ("Archivo PCAPNG", "*.pcapng"),
                       ("Todos los archivos", "*.*")])
        if not destino:
            return False
        if os.path.splitext(destino)[1].lower() not in (".pcap", ".pcapng"):
            destino += ".pcapng" if tipo.get() == "Archivo PCAPNG" else ".pcap"
            if os.path.exists(destino) and not messagebox.askyesno(
                    "Guardar PCAP", f"{os.path.basename(destino)} ya existe.\n\n"
                                    "¿Deseas reemplazarlo?"):
                return False
        formato = ("PCAPNG (PCAP Next Generation)" if destino.lower().endswith(".pcapng")
                   else "PCAP (formato clásico de libpcap)")
        try:
            guardados = self.motor.guardar_pcap(destino)
        except Exception as error:
            messagebox.showerror("Guardar PCAP", f"No se pudo guardar el archivo:\n{error}")
            return False
        self.sin_guardar = False
        tam = os.path.getsize(destino)
        self._mensaje(f"Se guardaron {guardados} paquetes en {destino} ({tam:,} bytes, {formato}).")
        messagebox.showinfo("Guardar PCAP", f"Se guardaron {guardados} paquetes en:\n{destino}\n\n"
                                            f"Formato: {formato}\nTamaño: {tam:,} bytes\n\n"
                                            "Puedes abrir el archivo con Wireshark para validarlo.")
        return True

    def abrir_pcap(self) -> None:
        if self.motor.estado != captura.DETENIDO:
            messagebox.showinfo("Abrir PCAP", "Detén la captura antes de abrir un archivo.")
            return
        if not self._confirmar_descarte():
            return
        ruta = filedialog.askopenfilename(
            title="Abrir captura", filetypes=[("Capturas", "*.pcap *.pcapng *.cap"),
                                               ("Todos los archivos", "*.*")])
        if not ruta:
            return
        try:
            self.motor.abrir_pcap(ruta)
        except Exception as error:
            messagebox.showerror("Abrir PCAP", f"No se pudo abrir el archivo:\n{error}")
            return
        self._limpiar_vista()
        self.filtro_activo = ""
        self.origen = "archivo"
        self._poner_estado(captura.LEYENDO)
        self._mensaje(f"Leyendo {os.path.basename(ruta)}...")

    def _confirmar_descarte(self) -> bool:
        """Si hay paquetes sin guardar, pregunta antes de borrarlos."""
        if not self.sin_guardar or self.motor.total == 0:
            return True
        respuesta = messagebox.askyesnocancel(
            "Captura sin guardar",
            f"La captura actual tiene {self.motor.total} paquetes que no se han guardado.\n\n"
            "¿Deseas guardarlos antes de continuar?")
        if respuesta is None:
            return False
        if respuesta:
            return bool(self.guardar_pcap())
        return True

    # ------------------------------------------------------------------
    # Ciclo de actualización (hilo principal)
    # ------------------------------------------------------------------
    def _ciclo(self) -> None:
        """Saca los paquetes de la cola y los agrega a la tabla. Se repite con after()."""
        if self._cerrando:
            return
        agregados = 0
        ultimo = None
        cola = self.motor.cola
        try:
            while agregados < LOTE_MAXIMO:
                tipo, dato = cola.get_nowait()
                if tipo == "paquete":
                    if self._agregar_paquete(dato):
                        ultimo = dato.numero
                    agregados += 1
                elif tipo == "fin":
                    self._al_terminar(dato)
                elif tipo == "iniciado":
                    self._mensaje(self._texto_captura)
                elif tipo == "aviso":
                    self._mensaje(dato)
        except queue.Empty:
            pass
        if ultimo is not None and self.var_autoscroll.get():
            self.tabla.see(str(ultimo))
        self.motor.revisar()
        self._actualizar_contadores()
        self.raiz.after(INTERVALO_MS, self._ciclo)

    def _agregar_paquete(self, registro: RegistroPaquete) -> bool:
        self.registros[registro.numero] = registro
        if len(self.registros) > MAX_PAQUETES_EN_MEMORIA:
            viejo, _ = self.registros.popitem(last=False)
            if self.tabla.exists(str(viejo)):
                self.tabla.delete(str(viejo))
        protocolo = registro.resumen.protocolo
        clave = protocolo if protocolo in ("TCP", "UDP", "ARP") else \
            "ICMP" if protocolo.startswith("ICMP") else "Otros"
        self.contadores[clave] = self.contadores.get(clave, 0) + 1
        if registro.resumen.aplicacion:
            app = registro.resumen.aplicacion
            self.contadores["app:" + app] = self.contadores.get("app:" + app, 0) + 1
        if self.motor.estado == captura.CAPTURANDO:
            self.sin_guardar = True
        if self.filtro_vista and not self._coincide(registro):
            return False
        self.tabla.insert("", "end", iid=str(registro.numero), values=registro.fila(),
                          tags=(registro.resumen.etiqueta,))
        return True

    def _al_terminar(self, error: Optional[str]) -> None:
        self._poner_estado(captura.DETENIDO)
        if error:
            self._poner_estado("error")
            messagebox.showerror("Captura detenida", error)
            self._mensaje("La captura se detuvo por un error.")
        elif self.origen == "archivo":
            self._mensaje(f"Archivo cargado: {self.motor.total} paquetes.")
        else:
            self._mensaje(f"Captura detenida: {self.motor.total} paquetes. "
                          "Usa Guardar PCAP para conservarlos.")

    def _actualizar_contadores(self) -> None:
        total = self.motor.total
        self.lbl_contador.configure(text=f"{total:,}")
        orden = ("TCP", "UDP", "ICMP", "ARP", "Otros")
        partes = [f"{p} {self.contadores.get(p, 0)}" for p in orden]
        apps = [(k[4:], v) for k, v in self.contadores.items() if k.startswith("app:")]
        apps = [f"{k} {v}" for k, v in sorted(apps, key=lambda x: -x[1])[:3]]
        self.lbl_protocolos.configure(text="  ·  ".join(partes) + ("   |   " + "  ·  ".join(apps)
                                                                   if apps else ""))
        ahora = time.time()
        if self.motor.estado == captura.CAPTURANDO:
            t_ref, n_ref = self._tasa_ref
            if ahora - t_ref >= 1.0:
                self._tasa = (total - n_ref) / (ahora - t_ref)
                self._tasa_ref = (ahora, total)
            transcurrido = int(ahora - (self.motor.inicio_captura or ahora))
            tasa = round(self._tasa)
            self.lbl_tasa.configure(text=f"{tasa} paquete{'' if tasa == 1 else 's'}/s")
            self.lbl_tiempo.configure(text=time.strftime("%H:%M:%S", time.gmtime(transcurrido)))
        elif self.motor.estado == captura.DETENIDO:
            self.lbl_tasa.configure(text="")

    def _poner_estado(self, estado: str) -> None:
        colores = {captura.DETENIDO: ("#9E9E9E", "Detenido"),
                   captura.CAPTURANDO: ("#2EAD4B", "Capturando..."),
                   captura.DETENIENDO: ("#F0A202", "Deteniendo..."),
                   captura.LEYENDO: ("#1E88E5", "Leyendo archivo..."),
                   "error": (COLOR_ROJO, "Error en la captura")}
        color, texto = colores[estado]
        self.lienzo_estado.itemconfigure(self.circulo, fill=color)
        self.lbl_estado.configure(text=texto, foreground=color if estado != captura.DETENIDO
                                  else COLOR_TEXTO_SUAVE)
        libre = estado in (captura.DETENIDO, "error")
        activo = "normal" if libre else "disabled"
        for widget in (self.btn_iniciar, self.btn_abrir, self.btn_limpiar, self.btn_actualizar):
            widget.configure(state=activo)
        self.btn_guardar.configure(state="normal" if libre and self.motor.total else "disabled")
        self.btn_detener.configure(state="normal" if estado in (captura.CAPTURANDO, captura.LEYENDO)
                                   else "disabled")
        self.combo_interfaz.configure(state="readonly" if libre else "disabled")
        self.combo_filtro.configure(state="readonly" if libre else "disabled")
        self.ent_filtro.configure(state=activo)
        self.chk_promiscuo.configure(state=activo)

    def _limpiar_vista(self) -> None:
        self.tabla.delete(*self.tabla.get_children())
        self.registros.clear()
        self.contadores.clear()
        self.registro_actual = None
        self._limpiar_detalle()
        self.sin_guardar = False
        self._tasa = 0.0
        self.lbl_tiempo.configure(text="")

    # ------------------------------------------------------------------
    # Filtro de visualización (post-captura)
    # ------------------------------------------------------------------
    def _coincide(self, registro: RegistroPaquete) -> bool:
        texto = " ".join(str(v) for v in registro.fila()).lower()
        return all(palabra in texto for palabra in self.filtro_vista)

    def aplicar_filtro_vista(self) -> None:
        self.filtro_vista = self.var_vista.get().lower().split()
        self._repoblar_tabla()

    def quitar_filtro_vista(self) -> None:
        self.var_vista.set("")
        self.filtro_vista = []
        self._repoblar_tabla()

    def _repoblar_tabla(self) -> None:
        self.tabla.delete(*self.tabla.get_children())
        visibles = 0
        for registro in self.registros.values():
            if not self.filtro_vista or self._coincide(registro):
                self.tabla.insert("", "end", iid=str(registro.numero), values=registro.fila(),
                                  tags=(registro.resumen.etiqueta,))
                visibles += 1
        self.lbl_vista.configure(text=f"Mostrando {visibles} de {len(self.registros)}"
                                 if self.filtro_vista else "")
        # si el paquete que estaba seleccionado sigue visible, se vuelve a seleccionar
        if self.registro_actual is not None:
            iid = str(self.registro_actual.numero)
            if self.tabla.exists(iid):
                self.tabla.selection_set(iid)
                self.tabla.see(iid)

    # ------------------------------------------------------------------
    # Panel de detalle y panel hexadecimal
    # ------------------------------------------------------------------
    def _al_seleccionar_paquete(self) -> None:
        seleccion = self.tabla.selection()
        if not seleccion:
            return
        registro = self.registros.get(int(seleccion[0]))
        if registro is None:
            return
        self.registro_actual = registro
        try:
            paquete = analisis.reconstruir(registro)
            secciones = analisis.detallar(paquete, registro.aplicacion, registro.numero,
                                          registro.tiempo_relativo)
            transporte = analisis.capa_transporte(analisis.capa_red(paquete))
            self.rango_carga = analisis.rango_carga(paquete, transporte, len(registro.datos))
        except Exception as error:
            self._limpiar_detalle()
            self.detalle.insert("", "end", text="No se pudo analizar el paquete", values=(str(error),))
            return
        self.detalle.delete(*self.detalle.get_children())
        self.rangos_detalle.clear()
        for seccion in secciones:
            nodo = self.detalle.insert("", "end", text=seccion.titulo, values=(seccion.resumen,),
                                       open=True, tags=("seccion",))
            self.rangos_detalle[nodo] = (seccion.inicio, seccion.longitud)
            self._insertar_campos(nodo, seccion.campos, (seccion.inicio, seccion.longitud))
        self.rango_seleccion = None
        self._mostrar_hex()

    def _insertar_campos(self, padre: str, campos, rango: Tuple[int, int]) -> None:
        for campo in campos:
            nodo = self.detalle.insert(padre, "end", text=campo.nombre, values=(campo.valor,),
                                       open=campo.expandido)
            self.rangos_detalle[nodo] = rango
            if campo.hijos:
                self._insertar_campos(nodo, campo.hijos, rango)

    def _al_seleccionar_detalle(self) -> None:
        seleccion = self.detalle.selection()
        if seleccion:
            self.rango_seleccion = self.rangos_detalle.get(seleccion[0])
            self._mostrar_hex()

    def _limpiar_detalle(self) -> None:
        self.detalle.delete(*self.detalle.get_children())
        self.rangos_detalle.clear()
        self.rango_seleccion = None
        self.rango_carga = (0, 0)
        self.texto_hex.configure(state="normal")
        self.texto_hex.delete("1.0", "end")
        self.texto_hex.configure(state="disabled")
        self.lbl_hex.configure(text="Selecciona un paquete de la tabla.")

    def _mostrar_hex(self) -> None:
        registro = self.registro_actual
        if registro is None:
            return
        datos = registro.datos
        inicio_carga, largo_carga = self.rango_carga
        solo_carga = self.var_modo_hex.get() == "carga"
        base = inicio_carga if solo_carga else 0
        mostrar = datos[inicio_carga:inicio_carga + largo_carga] if solo_carga else datos

        self.texto_hex.configure(state="normal")
        self.texto_hex.delete("1.0", "end")
        if solo_carga and not largo_carga:
            self.texto_hex.insert("1.0", "Este paquete no lleva carga útil: todos sus bytes son "
                                         "encabezados.")
        else:
            self.texto_hex.insert("1.0", "\n".join(volcado.volcado_hex(mostrar, base)))
            if not solo_carga and largo_carga:
                self._resaltar(inicio_carga, largo_carga, "carga")
            if self.rango_seleccion:
                inicio, largo = self.rango_seleccion
                ini_rel = max(inicio, base) - base
                fin_rel = min(inicio + largo, base + len(mostrar)) - base
                if fin_rel > ini_rel:
                    self._resaltar(ini_rel, fin_rel - ini_rel, "seleccion")
                    self.texto_hex.see(f"{ini_rel // volcado.BYTES_POR_LINEA + 1}.0")
        self.texto_hex.configure(state="disabled")

        encabezados = len(datos) - largo_carga
        texto = f"Trama: {len(datos)} bytes   ·   Encabezados: {encabezados} bytes   ·   "
        texto += (f"Carga útil: {largo_carga} bytes (desde el byte {inicio_carga}, "
                  f"0x{inicio_carga:04x})" if largo_carga else "Carga útil: 0 bytes")
        self.lbl_hex.configure(text=texto)

    def _resaltar(self, inicio: int, longitud: int, etiqueta: str) -> None:
        for linea, h0, h1, a0, a1 in volcado.tramos(inicio, longitud):
            self.texto_hex.tag_add(etiqueta, f"{linea + 1}.{h0}", f"{linea + 1}.{h1}")
            self.texto_hex.tag_add(etiqueta, f"{linea + 1}.{a0}", f"{linea + 1}.{a1}")

    # ------------------------------------------------------------------
    # Copiar al portapapeles
    # ------------------------------------------------------------------
    def _copiar_fila(self) -> None:
        seleccion = self.tabla.selection()
        if seleccion:
            valores = self.tabla.item(seleccion[0], "values")
            self._al_portapapeles("\t".join(str(v) for v in valores))

    def _copiar_detalle(self) -> None:
        seleccion = self.detalle.selection()
        if seleccion:
            item = self.detalle.item(seleccion[0])
            valor = item["values"][0] if item["values"] else ""
            self._al_portapapeles(f"{item['text']}: {valor}" if valor else item["text"])

    def _al_portapapeles(self, texto: str) -> None:
        self.raiz.clipboard_clear()
        self.raiz.clipboard_append(texto)
        self._mensaje("Copiado al portapapeles.")

    # ------------------------------------------------------------------
    # Ventanas de ayuda y cierre
    # ------------------------------------------------------------------
    def mostrar_guia_bpf(self) -> None:
        ventana = tk.Toplevel(self.raiz)
        ventana.title("Guía de filtros BPF")
        ventana.configure(background=COLOR_FONDO)
        texto = tk.Text(ventana, font=(self.fuente_mono, 10), width=90, height=34, wrap="word",
                        padx=12, pady=10, relief="flat")
        texto.insert("1.0", TEXTO_GUIA_BPF)
        texto.configure(state="disabled")
        texto.pack(fill="both", expand=True, padx=10, pady=10)
        ttk.Button(ventana, text="Cerrar", command=ventana.destroy).pack(pady=(0, 10))

    def mostrar_acerca_de(self) -> None:
        import scapy
        messagebox.showinfo(
            "Acerca de",
            "Analizador de Tráfico de Red (Sniffer)\n"
            "Proyecto 3 - Redes de Computadoras, ESCOM - IPN\n\n"
            f"Python {sys.version.split()[0]}  ·  Scapy {scapy.__version__}  ·  Tk {tk.TkVersion}")

    def _mensaje(self, texto: str) -> None:
        self.lbl_mensaje.configure(text=texto)

    def al_cerrar(self) -> None:
        if self.motor.estado == captura.CAPTURANDO:
            if not messagebox.askyesno("Salir", "Hay una captura en curso. ¿Detenerla y salir?"):
                return
            self.motor.detener()
        elif not self._confirmar_descarte():
            return
        self._cerrando = True
        self._esperar_y_cerrar(time.time())

    def _esperar_y_cerrar(self, inicio: float) -> None:
        """Espera (sin bloquear) a que el hilo de captura termine; máximo 3 segundos."""
        if self.motor.estado != captura.DETENIDO and time.time() - inicio < 3:
            if self.motor.estado == captura.LEYENDO:
                self.motor.estado = captura.DETENIENDO
            self.raiz.after(100, lambda: self._esperar_y_cerrar(inicio))
            return
        self.motor.descartar()
        self.raiz.destroy()


def _activar_dpi_windows() -> None:
    """Texto nítido en pantallas con escalado (125 %, 150 %) en Windows."""
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass


def iniciar() -> None:
    _activar_dpi_windows()
    raiz = tk.Tk()
    raiz.title("Analizador de Tráfico de Red (Sniffer) — Proyecto 3, Redes de Computadoras")
    ancho = min(1500, raiz.winfo_screenwidth() - 40)
    alto = min(900, raiz.winfo_screenheight() - 80)
    raiz.geometry(f"{ancho}x{alto}+10+10")
    raiz.minsize(1100, 680)
    if sys.platform.startswith("win"):
        try:
            raiz.state("zoomed")
        except tk.TclError:
            pass
    AplicacionSniffer(raiz)
    raiz.mainloop()
