"""
RedShield · Cajathon 2026 · Eje 3 (Descubrir redes de riesgo ocultas)
Ejecutar:  python -m streamlit run redshield_app.py

Todos los datos de la demostración son SINTÉTICOS.
El sistema no acusa a nadie: la prioridad ordena qué revisar primero y toda
decisión que afecte a una persona la toma un analista.
"""
import hashlib
import hmac
import json
import math
import os
import time
import zlib
from datetime import datetime

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network

import redshield_core as rc

st.set_page_config(page_title="RedShield", page_icon="🛡️", layout="wide")

# ------------------------------------------------------------------ identidad visual (Canva)
C = dict(rojo="#fc4f4f", naranja="#ff8a62", amarillo="#f5d66f", verde="#96f0a8", lila="#c4a1ff",
         azul="#8ab4ff", celeste="#6ee7d8", rosa="#ff9ad5", gris="#9a97b5", blanco="#f4f3ff")
NIVEL_COL = {"Alta": C["rojo"], "Media": C["amarillo"], "Baja": C["verde"]}
REL_COL = {"Alta relevancia": C["rojo"], "Revisar": C["amarillo"], "Contextualizar": C["verde"]}
ESCALA = [[0, C["verde"]], [.3, "#f5e27a"], [.6, C["naranja"]], [1, C["rojo"]]]
PANELES = ["Inicio", "Investigaciones", "Investigación de red", "Análisis temporal",
           "Evaluación del modelo", "Datos y auditoría"]
ESTADOS = ["Pendiente", "En investigación", "Requiere escalamiento", "Relación legítima"]
USUARIOS = {"Jurado": "Jurado", "Ana Torres": "Analista", "Luis Paredes": "Supervisor"}
CUENTAS_PERSONAL = ["Ana Torres", "Luis Paredes"]
# Permisos por rol. «Jurado» es el rol de visitante: solo lectura y con datos mínimos (se asigna al entrar).
PANELES_ROL = {"Jurado": [p for p in PANELES if p != "Inicio"], "Analista": [p for p in PANELES if p != "Inicio"],
               "Supervisor": PANELES}
TABS_DATOS = {
    "Jurado": ["Calidad de datos", "Usuarios y roles", "Privacidad y cumplimiento", "Equidad (sesgo)"],
    "Analista": ["Calidad de datos", "Usuarios y roles", "Registro de decisiones", "Privacidad y cumplimiento", "Equidad (sesgo)"],
    "Supervisor": ["Importar datos", "Calidad de datos", "Historial de importaciones", "Usuarios y roles",
                   "Registro de decisiones", "Privacidad y cumplimiento", "Equidad (sesgo)"]}
# Claves: se guardan como hash (SHA-256). Para cambiarlas sin tocar el código, define en los «Secrets» de Streamlit:
#   [claves]
#   supervisor = "..."
#   analista = "..."
_SAL = "redshield-2026|"
_HASH_DEFECTO = {"Luis Paredes": "a9d5757b398bc56e7cf59cb7f0103e0dbb80be95cb362829986f98e090db4eca",
                 "Ana Torres": "022fab0c0d7c27e8e0d6cacd06a8db6a72116c9e3002d5d1fa09d6c48c737cff"}


def _h(clave):
    return hashlib.sha256((_SAL + clave).encode("utf-8")).hexdigest()


def hashes_claves():
    h = dict(_HASH_DEFECTO)
    try:
        sec = st.secrets.get("claves", {})
        if sec.get("supervisor"):
            h["Luis Paredes"] = _h(str(sec["supervisor"]))
        if sec.get("analista"):
            h["Ana Torres"] = _h(str(sec["analista"]))
    except Exception:
        pass
    return h
TIPOS_CONEXION = ["Dispositivo", "Teléfono", "IP", "Correo", "Negocio", "Dirección", "Referencia"]
ESTILO = {"persona": (C["azul"], "dot"), "negocio": (C["lila"], "hexagon"), "dispositivo": (C["naranja"], "square"),
          "telefono": (C["amarillo"], "triangle"), "direccion": (C["verde"], "diamond"),
          "ip": (C["celeste"], "triangleDown"), "correo": (C["rosa"], "star")}
COM_COL = [C["azul"], C["rosa"], C["celeste"], C["amarillo"], C["lila"], C["naranja"]]
LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "redshield_auditoria.jsonl")
OPC_GRAFO = ('{"physics":{"solver":"forceAtlas2Based","forceAtlas2Based":{"gravitationalConstant":-60,'
             '"springLength":110,"avoidOverlap":0.4},"stabilization":{"iterations":160}},'
             '"interaction":{"hover":true,"tooltipDelay":120,"navigationButtons":true},"edges":{"smooth":false}}')

st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=Hanken+Grotesk:wght@400;500;600;700;800&display=swap');
html, body, [class*="css"], .stMarkdown, .stButton button, input, textarea {font-family:'Hanken Grotesk',sans-serif;}
.stApp {background:linear-gradient(180deg,#000000 0%,#0c0b12 18%,#1c1a2b 42%,#34296f 78%,#4631b4 100%);
  background-attachment:fixed;color:#f4f3ff;}
[data-testid="stHeader"] {background:transparent;}
#MainMenu, footer {visibility:hidden;}
.block-container {padding-top:1.1rem;padding-bottom:3rem;max-width:1480px;}
[data-testid="stSidebar"] {background:rgba(8,7,18,.94);border-right:1px solid rgba(255,255,255,.08);}
h1,h2,h3,h4,h5 {color:#fff;letter-spacing:-.01em;}
.logo {font-size:1.45rem;font-weight:800;color:#fff;letter-spacing:-.03em;padding-top:.3rem;}
.hero-t {font-size:2.7rem;font-weight:600;line-height:1.08;color:#fff;margin:.6rem 0 .3rem;max-width:900px;letter-spacing:-.02em;}
.sub {color:rgba(255,255,255,.74);font-size:1.05rem;margin:0 0 1.1rem;max-width:980px;line-height:1.5;}
.card {background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.13);border-radius:20px;padding:17px 20px;margin-bottom:12px;}
.kpi {background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.13);border-radius:20px;padding:16px 20px;min-height:118px;}
.k-t {font-size:.86rem;color:rgba(255,255,255,.7);font-weight:600;}
.k-v {font-size:2.15rem;font-weight:700;color:#fff;line-height:1.15;letter-spacing:-.02em;margin:3px 0;}
.k-n {font-size:.8rem;color:rgba(255,255,255,.6);}
.badge {display:inline-block;padding:2px 11px;border-radius:999px;font-size:.76rem;font-weight:700;color:#14101f;}
.badge.Alta {background:#fc4f4f;} .badge.Media {background:#f5d66f;} .badge.Baja {background:#96f0a8;}
.tag {display:inline-block;padding:2px 10px;border-radius:999px;font-size:.74rem;font-weight:600;
  border:1px solid rgba(255,255,255,.3);color:#fff;margin-left:6px;}
.muted {color:rgba(255,255,255,.64);}
.ev {background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.12);border-left:5px solid #c4a1ff;
  border-radius:14px;padding:11px 15px;margin-bottom:9px;}
.ev b {font-size:.98rem;} .ev small {color:rgba(255,255,255,.66);display:block;margin-top:3px;line-height:1.4;}
.fila {display:flex;justify-content:space-between;gap:14px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.09);font-size:.93rem;}
.fila span:first-child {color:rgba(255,255,255,.62);min-width:150px;} .fila span:last-child {text-align:right;}
.leyenda {display:flex;gap:16px;flex-wrap:wrap;font-size:.86rem;color:rgba(255,255,255,.75);margin:8px 0 4px;}
.pend {border:1px dashed rgba(255,255,255,.35);border-radius:14px;padding:12px 16px;color:rgba(255,255,255,.8);}
.stButton > button, .stDownloadButton > button {border-radius:999px;border:1px solid rgba(255,255,255,.28);
  background:rgba(255,255,255,.05);color:#fff;font-weight:600;min-height:2.5rem;}
.stButton > button:hover, .stDownloadButton > button:hover {border-color:#c4a1ff;color:#fff;background:rgba(196,161,255,.14);}
.stButton > button[kind="primary"], .stButton > button[data-testid="baseButton-primary"] {
  background:linear-gradient(90deg,#c9bcff,#ffffff);color:#1b1730;border:none;}
div[data-testid="stVerticalBlockBorderWrapper"] {border-color:rgba(255,255,255,.14)!important;border-radius:20px;background:rgba(255,255,255,.04);}
[data-testid="stDataFrame"] {border:1px solid rgba(255,255,255,.12);border-radius:14px;overflow:hidden;}
.stTabs [data-baseweb="tab"] {color:rgba(255,255,255,.75);} .stTabs [aria-selected="true"] {color:#fff!important;}
/* clic: siempre cae sobre el botón (no sobre el texto interno) */
.stButton > button *, .stDownloadButton > button * {pointer-events:none;}
.stButton > button, .stDownloadButton > button {cursor:pointer;
  transition:transform .18s ease,border-color .2s ease,background .2s ease,box-shadow .2s ease;}
.stButton > button:hover, .stDownloadButton > button:hover {transform:translateY(-1px);box-shadow:0 6px 18px rgba(130,100,255,.28);}
.stButton > button:active, .stDownloadButton > button:active {transform:scale(.97);}
/* botones ocultos que usa el mapa de inicio para abrir un caso */
[class*="st-key-go_"] {position:absolute !important;left:-9999px;width:1px;height:1px;overflow:hidden;opacity:0;}
/* animaciones sutiles */
@keyframes rsUp {from{opacity:0;transform:translateY(10px);} to{opacity:1;transform:none;}}
@keyframes rsFade {from{opacity:0;} to{opacity:1;}}
.logo, .hero-t, .sub, .kpi, .card, .ev, .leyenda, .pend {animation:rsUp .55s cubic-bezier(.2,.7,.2,1) backwards;}
[data-testid="stColumn"]:nth-child(2) .kpi, [data-testid="column"]:nth-child(2) .kpi {animation-delay:.07s;}
[data-testid="stColumn"]:nth-child(3) .kpi, [data-testid="column"]:nth-child(3) .kpi {animation-delay:.14s;}
[data-testid="stColumn"]:nth-child(4) .kpi, [data-testid="column"]:nth-child(4) .kpi {animation-delay:.21s;}
.kpi, .card, .ev {transition:transform .2s ease,border-color .25s ease,background .25s ease;}
.kpi:hover, .card:hover {transform:translateY(-2px);border-color:rgba(196,161,255,.45);background:rgba(255,255,255,.085);}
.ev:hover {transform:translateX(3px);background:rgba(255,255,255,.08);}
.fila {transition:background .2s ease;} .fila:hover {background:rgba(255,255,255,.04);}
[data-testid="stPlotlyChart"], [data-testid="stDataFrame"], iframe, [data-testid="stAlert"],
[data-testid="stExpander"], [data-testid="stImage"] {animation:rsFade .7s ease backwards;}
[data-testid="stSidebar"] {animation:rsFade .6s ease backwards;}
.stTabs [data-baseweb="tab"] {transition:color .2s ease;}
@media (prefers-reduced-motion: reduce){*{animation:none !important;transition:none !important;}}
@media(max-width:850px){.hero-t{font-size:1.9rem;}}
</style>""", unsafe_allow_html=True)

# ------------------------------------------------------------------ estado y auditoría
ss = st.session_state


def cargar_log():
    try:
        with open(LOG_PATH, encoding="utf-8") as f:
            return [json.loads(x) for x in f if x.strip()]
    except (OSError, ValueError):
        return []


def escribir_log(e):
    ss.log.append(e)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    except OSError:
        pass            # en un servidor de solo lectura el registro queda solo en la sesión


for k, v in dict(panel="Inicio", caso=None, zona=None, prov=None, preview=None, foco=None, t0={},
                 importaciones=[], usuario="Jurado", aviso=None, ult_sel=None, fallos=0, bloqueo=0.0, login_msg=None).items():
    ss.setdefault(k, v)
if "log" not in ss:
    ss.log = cargar_log()


def registrar(caso, accion, detalle=""):
    ahora = time.time()
    seg = round(ahora - ss.t0.get(caso, ahora)) if accion in ESTADOS else None
    escribir_log(dict(ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), usuario=ss.usuario, rol=USUARIOS[ss.usuario],
                      caso=caso, accion=accion, detalle=detalle, segundos=seg, fuente=ss.fuente_id))


def decidir(caso, accion):
    registrar(caso, accion, ss.get(f"nota_{caso}", ""))


def agregar_evidencia(caso):
    t = ss.get(f"evid_{caso}", "").strip()
    if t:
        registrar(caso, "Evidencia agregada", t)
        ss[f"evid_{caso}"] = ""


def ir(panel):
    ss.panel = panel


def ingresar():
    u, clave = ss.get("login_user"), ss.get("login_pw") or ""
    if time.time() < ss.bloqueo:
        ss.login_msg = f"Demasiados intentos. Espera {int(ss.bloqueo - time.time()) + 1} s."
        return
    if u in CUENTAS_PERSONAL and hmac.compare_digest(_h(clave), hashes_claves()[u]):
        ss.usuario, ss.fallos, ss.login_msg, ss.login_pw = u, 0, None, ""
        ss.panel = "Inicio" if USUARIOS[u] == "Supervisor" else "Investigaciones"
        ss.caso = ss.foco = None
    else:
        ss.fallos += 1
        if ss.fallos >= 5:
            ss.fallos, ss.bloqueo = 0, time.time() + 30
        ss.login_msg = "Clave incorrecta."
        ss.login_pw = ""


def salir():
    ss.usuario, ss.panel, ss.caso, ss.foco, ss.login_msg = "Jurado", "Investigaciones", None, None, None


def abrir(caso):
    ss.caso, ss.panel, ss.foco = caso, "Investigación de red", None


def ubicar(caso):
    ss.mapa_foco = caso
    ss.mapa_n = ss.get("mapa_n", 0) + 1


def elegir(nivel, nombre):
    if nivel == 0:
        ss.zona, ss.prov, ss.preview = nombre, None, None
    elif nivel == 1:
        ss.prov, ss.preview = nombre, None
    else:
        ss.preview = nombre


def subir(nivel):
    if nivel == 0:
        ss.zona = ss.prov = ss.preview = None
    else:
        ss.prov = ss.preview = None


# ------------------------------------------------------------------ datos
@st.cache_resource(show_spinner=False)
def datos_demo():
    return rc.generar_datos()


@st.cache_resource(show_spinner="Analizando redes…")
def correr(sols, refs):
    return rc.analizar(sols, refs)


imp = ss.get("datos_import")
sols, refs = (imp["sols"], imp["refs"]) if imp else datos_demo()
try:
    R = correr(sols, tuple(map(tuple, refs)))
except ValueError as e:                      # archivo importado sin redes analizables: se vuelve a la demo
    ss.pop("datos_import", None)
    ss.aviso, imp = str(e), None
    sols, refs = datos_demo()
    R = correr(sols, tuple(map(tuple, refs)))
ss.fuente_id = f"import:{imp['nombre']}" if imp else "sintetico"
D, G = R["d"], R["G"]

EST = {}
for e in ss.log:
    if e.get("fuente") == ss.fuente_id and e["accion"] in ESTADOS:
        EST[e["caso"]] = e["accion"]
DF = R["df"].copy()
DF["estado"] = DF.id.map(EST).fillna("Pendiente")

with st.sidebar:
    st.markdown("### RedShield")
    ROL = USUARIOS[ss.usuario]
    if ROL == "Jurado":
        st.caption("Rol: Jurado · solo lectura · datos limitados")
        with st.expander("Acceso del personal"):
            st.selectbox("Cuenta", CUENTAS_PERSONAL, key="login_user")
            st.text_input("Clave", type="password", key="login_pw")
            st.button("Ingresar", on_click=ingresar, use_container_width=True)
            if ss.login_msg:
                st.error(ss.login_msg)
    else:
        st.markdown(f"**{ss.usuario}**")
        st.caption(f"Rol: {ROL}")
        st.button("Cerrar sesión", on_click=salir, use_container_width=True)
    st.slider("Capacidad de revisión hoy (horas de analista)", 2, 40, 12, key="horas")
    st.caption("RedShield propone qué casos caben en ese tiempo para cubrir la mayor exposición con el menor esfuerzo.")
    st.toggle("Calibrar con decisiones del analista", key="calib",
              help="Reduce el peso de las señales que los analistas suelen descartar y aumenta el de las que escalan. "
                   "Requiere al menos 3 decisiones por tipo de señal.")
    st.divider()
    st.caption("Fuente de datos: " + ("archivo importado «" + imp["nombre"] + "»" if imp else "sintéticos (demostración)"))
    st.caption("Sin conexión a sistemas reales · Sin decisiones automatizadas")

PESOS = rc.calibrar_pesos(DF, EST)
CALIBRADO = bool(ss.get("calib")) and any(v["aplica"] for v in PESOS.values())
if CALIBRADO:
    DF["prioridad"] = rc.aplicar_pesos(DF, PESOS)
    DF["nivel"] = DF.prioridad.map(rc.nivel)
    DF["indice"] = (0.75 * DF.prioridad + 25 * DF.exposicion / max(DF.exposicion.max(), 1)).round(1)
    DF = DF.sort_values("indice", ascending=False).reset_index(drop=True)
if ss.get("calib") and not CALIBRADO:
    st.sidebar.caption("Aún no hay decisiones suficientes para calibrar (mínimo 3 por tipo de señal).")

cand = DF[(DF.prioridad >= rc.ALERTA) & (DF.estado != "Relación legítima")]
PLAN = rc.plan_revision([(r.id, round(r.indice * 10), r.esfuerzo_h) for r in cand.itertuples()], ss.horas)
DF["hoy"] = DF.id.isin(PLAN)
cand = DF.loc[cand.index]          # la cola también necesita la columna «hoy»
ROL = USUARIOS[ss.usuario]
PERMITIDOS = PANELES_ROL[ROL]
if ss.panel not in PERMITIDOS:            # p. ej. el jurado o el analista nunca ven «Inicio»
    ss.panel = PERMITIDOS[0]
S = R["serie"]


# ------------------------------------------------------------------ utilidades de interfaz
def money(x):
    return f"S/ {x:,.0f}"


def kpi(col, titulo, valor, nota):
    col.markdown(f'<div class="kpi"><div class="k-t">{titulo}</div><div class="k-v">{valor}</div>'
                 f'<div class="k-n">{nota}</div></div>', unsafe_allow_html=True)


def badge(n):
    return f'<span class="badge {n}">{n}</span>'


def rgba(h, a):
    h = h.lstrip("#")
    return f"rgba({int(h[:2], 16)},{int(h[2:4], 16)},{int(h[4:], 16)},{a})"


def tema(fig, alto=320):
    fig.update_layout(template="plotly_dark", height=alto, margin=dict(l=10, r=10, t=36, b=10),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      font=dict(color="#f4f3ff", family="Hanken Grotesk, sans-serif"),
                      legend=dict(orientation="h", y=-0.18))
    fig.update_xaxes(gridcolor="rgba(255,255,255,.08)")
    fig.update_yaxes(gridcolor="rgba(255,255,255,.08)")
    return fig


def titulo(t, sub=None):
    st.markdown(f"## {t}")
    if sub:
        st.markdown(f'<div class="sub">{sub}</div>', unsafe_allow_html=True)


def etq(n):
    a = G.nodes[n]
    return f"{rc.ETQ_TIPO[a['tipo']]} · {rc.etiqueta_nodo(a)}"


def seleccion(ev):
    return ((ev.get("selection") or {}).get("rows", []) if ev else [])


# ------------------------------------------------------------------ navegación
ANCHOS = {"Inicio": .8, "Investigaciones": 1.15, "Investigación de red": 1.3, "Análisis temporal": 1.25,
          "Evaluación del modelo": 1.55, "Datos y auditoría": 1.3}
cols = st.columns([1.15] + [ANCHOS[p] for p in PERMITIDOS])
cols[0].markdown('<div class="logo">RedShield</div>', unsafe_allow_html=True)
for c, p in zip(cols[1:], PERMITIDOS):
    c.button(p, key=f"nav_{p}", type="primary" if ss.panel == p else "secondary",
             use_container_width=True, on_click=ir, args=(p,))
st.markdown('<div class="muted" style="font-size:.82rem;margin:6px 0 0">La prioridad es un orden sugerido de revisión, no una '
            'probabilidad ni una acusación de fraude. Compartir datos puede tener motivos legítimos. '
            'Esta demostración usa únicamente datos sintéticos.</div>', unsafe_allow_html=True)
if ss.aviso:
    st.warning(f"No se pudo analizar el archivo importado: {ss.aviso} Se volvió a los datos sintéticos.")
    ss.aviso = None


# ================================================================== 1. INICIO
MAPA_HTML = r'''<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
html,body{margin:0;height:100%;background:transparent;font-family:'Hanken Grotesk',system-ui,-apple-system,'Segoe UI',sans-serif;color:#f4f3ff;overflow:hidden}
#w{position:relative;width:100%;height:100%;border-radius:18px;overflow:hidden;border:1px solid rgba(255,255,255,.14);
  background:radial-gradient(ellipse at 50% 42%,rgba(150,120,255,.14),rgba(255,255,255,.02) 72%);animation:fade .8s ease backwards}
svg{width:100%;height:100%;display:block;touch-action:none;cursor:grab;user-select:none;-webkit-user-select:none}
svg.drag{cursor:grabbing}
.n{cursor:pointer}
.n .c{vector-effect:non-scaling-stroke;stroke:rgba(255,255,255,.75);stroke-width:1.5px;transition:fill-opacity .3s ease,stroke-width .2s ease}
.n:hover .c{stroke-width:3.5px;stroke:#fff}
.lbl{fill:#0b0a14;text-anchor:middle;pointer-events:none;font-weight:600}
.lbl .b{font-weight:800}
.l0{animation:pop .75s cubic-bezier(.2,.8,.2,1) backwards;animation-delay:calc(var(--i)*80ms);transform-box:fill-box;transform-origin:center}
.sel .c{stroke:#fff;stroke-width:4px;animation:pulse 1.7s ease-in-out infinite}
/* conexiones tipo red neuronal */
.e line{vector-effect:non-scaling-stroke;stroke-linecap:round;fill:none}
.e .b{stroke-opacity:.5}
.e .f{stroke-opacity:.95;stroke-dasharray:.1 13;stroke-width:3px;animation:flow 1.5s linear infinite}
.e.hot .b{stroke:#fff!important;stroke-opacity:.95;stroke-width:3px}
.e.hot .f{stroke:#fff!important}
@keyframes flow{to{stroke-dashoffset:-13.1}}
@keyframes pop{from{opacity:0;transform:scale(.3)}to{opacity:1;transform:scale(1)}}
@keyframes pulse{50%{stroke-opacity:.4}}
@keyframes fade{from{opacity:0}to{opacity:1}}
@keyframes up{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
@media (prefers-reduced-motion: reduce){.e .f{animation:none}.l0{animation:none}.sel .c{animation:none}}
.bar{position:absolute;top:10px;left:12px;right:12px;display:flex;gap:8px;align-items:center;pointer-events:none}
.bar>*{pointer-events:auto}
#crumb{font-size:12.5px;color:rgba(255,255,255,.85);background:rgba(10,8,30,.55);padding:6px 12px;border-radius:999px;border:1px solid rgba(255,255,255,.14);backdrop-filter:blur(6px);margin-right:auto;pointer-events:none;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
button{font:inherit;color:#fff;background:rgba(10,8,30,.6);border:1px solid rgba(255,255,255,.28);border-radius:999px;min-width:34px;height:34px;padding:0 13px;cursor:pointer;font-size:15px;font-weight:700;backdrop-filter:blur(6px);transition:transform .18s ease,background .2s,border-color .2s}
button:hover{background:rgba(196,161,255,.25);border-color:#c4a1ff;transform:translateY(-1px)}
button:active{transform:scale(.94)}
button *{pointer-events:none}
#back{font-size:12.5px;font-weight:600;opacity:0;pointer-events:none;transition:opacity .25s}
#back.on{opacity:1;pointer-events:auto}
#hint{position:absolute;left:50%;bottom:14px;transform:translateX(-50%);font-size:12.5px;color:rgba(255,255,255,.8);background:rgba(10,8,30,.6);padding:7px 14px;border-radius:999px;border:1px solid rgba(255,255,255,.14);transition:opacity .6s;animation:up .7s .5s ease backwards;white-space:nowrap;max-width:92%;overflow:hidden;text-overflow:ellipsis}
#leg{position:absolute;right:12px;bottom:14px;font-size:11px;color:rgba(255,255,255,.75);text-align:center}
#leg i{display:block;width:120px;height:8px;border-radius:6px;margin-bottom:3px;background:linear-gradient(90deg,#96f0a8,#f5e27a 30%,#ff8a62 60%,#fc4f4f)}
#tip{position:absolute;pointer-events:none;background:rgba(10,8,30,.92);border:1px solid rgba(255,255,255,.2);border-radius:10px;padding:6px 10px;font-size:12px;max-width:260px;opacity:0;transition:opacity .15s;z-index:5}
#det{box-sizing:border-box;position:absolute;left:12px;bottom:44px;max-height:calc(100% - 100px);width:min(310px,46%);display:flex;flex-direction:column;background:rgba(15,12,40,.92);border:1px solid rgba(255,255,255,.2);border-radius:16px;padding:12px 14px;animation:up .35s ease backwards;backdrop-filter:blur(8px);z-index:4}
#det[hidden]{display:none}
#det .t{font-weight:800;font-size:15px;margin-bottom:2px}
#det .loc{font-size:12px;color:#c4a1ff;margin-bottom:3px}
#det .s{font-size:12.5px;color:rgba(255,255,255,.75);line-height:1.4;margin-bottom:8px}
#det .h{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:rgba(255,255,255,.6);margin-bottom:5px}
#sig{overflow-y:auto;flex:1;min-height:0;padding-right:4px;margin-bottom:9px}
.sg{margin:0 0 6px;padding:7px 9px;border-radius:10px;background:rgba(255,255,255,.06);border-left:3px solid #f5d66f;font-size:12.5px;line-height:1.35}
.sg b{display:block;font-size:12.5px}
.sg .p{float:right;font-size:11px;color:rgba(255,255,255,.6);margin-left:6px}
.sg .a{display:block;margin-top:3px;font-size:11.5px;color:rgba(255,255,255,.62);font-style:italic}
#det .r{display:flex;gap:8px;align-items:center}
#msg{font-size:11.5px;color:#f5d66f}
#rev{background:linear-gradient(90deg,#c9bcff,#fff);color:#1b1730;border:none;font-size:13px}
</style></head><body>
<div id="w">
 <svg id="svg"><g id="world"><g id="edges"></g><g id="nodes"></g></g></svg>
 <div class="bar"><div id="crumb">Departamentos</div><button id="back">← Volver</button><button id="zin" title="Acercar">+</button><button id="zout" title="Alejar">−</button><button id="zhome" title="Vista inicial">⌂</button></div>
 <div id="hint">Acerca con la rueda o pellizca · toca un nodo: Departamento › Provincia › Distrito › Casos</div>
 <div id="leg"><i></i>prioridad baja → alta</div>
 <div id="tip"></div>
 <div id="det" hidden><div class="t"></div><div class="loc"></div><div class="s"></div><div class="h">Cuestiones sospechosas</div><div id="sig"></div><div class="r"><button id="rev">Revisar →</button><button id="x">✕</button><span id="msg"></span></div></div>
</div>
<script>
const DATA=__DATA__;
const STOPS=[[0,[150,240,168]],[.3,[245,226,122]],[.6,[255,138,98]],[1,[252,79,79]]];
function col(p){p=Math.max(0,Math.min(100,p))/100;for(let i=1;i<STOPS.length;i++){if(p<=STOPS[i][0]){const a=STOPS[i-1],b=STOPS[i],t=(p-a[0])/(b[0]-a[0]);return 'rgb('+a[1].map((v,j)=>Math.round(v+(b[1][j]-v)*t)).join(',')+')';}}return 'rgb(252,79,79)';}
const NS='http://www.w3.org/2000/svg',$=id=>document.getElementById(id);
const svg=$('svg'),world=$('world'),gE=$('edges'),gN=$('nodes'),wrap=$('w'),tip=$('tip'),det=$('det');
let W=600,H=500,k=1,tx=0,ty=0,k0=1,ext=1,raf=0,ready=false,sel=null,focus=null;
const Q=.34,SUF=['%','%',' máx.',' pts'];
const cl=(v,a,b)=>Math.max(a,Math.min(b,v));
const mk=(t,a)=>{const e=document.createElementNS(NS,t);for(const q in a)e.setAttribute(q,a[q]);return e;};

/* ---- árbol: departamento › provincia › distrito › caso ---- */
const T=(o,lvl,kids)=>Object.assign({},o,{lvl,kids});
const regs=DATA.regs.map(r=>T(r,0,r.provs.map(p=>T(p,1,p.dists.map(d=>T(d,2,d.cases.map(c=>T(c,3,[]))))))));
regs.sort((a,b)=>b.exp-a.exp);

/* ---- diseño: cada nodo es el centro de su celda y sus hijos giran a su alrededor ---- */
function lay(n){
  n.kids.sort((a,b)=>b.exp-a.exp||b.pct-a.pct);
  if(!n.kids.length){n.F=n.lvl===3?1:1.8;n.rho=0;n.r=Q*n.F;return;}
  n.kids.forEach(lay);
  const m=n.kids.length,Fm=Math.max(...n.kids.map(c=>c.F));
  n.rho=Math.max((2*Q+.25)/(1-Q)*Fm,m>1?(2*Q+.25)*Fm/(2*Math.sin(Math.PI/m)):0);
  n.F=n.rho+Fm;n.r=Q*n.F;
}
function place(n){
  const m=n.kids.length,ph=n.lvl*.55;
  n.kids.forEach((c,i)=>{const a=-Math.PI/2+ph+2*Math.PI*i/m;c.x=n.x+n.rho*Math.cos(a);c.y=n.y+n.rho*Math.sin(a);c.parent=n;place(c);});
}
regs.forEach(lay);
regs[0].x=0;regs[0].y=0;
{const ring=regs.slice(1),m=ring.length;
 if(m){const Fm=Math.max(...ring.map(c=>c.F));
  const rho=Math.max(Q*regs[0].F+Q*Fm+.3*Fm,m>1?(2*Q+.3)*Fm/(2*Math.sin(Math.PI/m)):0);
  ring.forEach((c,i)=>{const a=-Math.PI/2+2*Math.PI*i/m;c.x=rho*Math.cos(a);c.y=rho*Math.sin(a);});}}
regs.forEach(place);
const lv=[regs];for(let L=1;L<4;L++)lv.push(lv[L-1].flatMap(n=>n.kids));
const all=lv.flat();
ext=Math.max(...regs.map(r=>Math.hypot(r.x,r.y)+r.F));

/* ---- nodos ---- */
lv.forEach((arr,L)=>arr.forEach((n,i)=>{
  const g=mk('g',{class:'n'+(L===0?' l0':'')});g.style.setProperty('--i',i);g.__n=n;
  n.c=mk('circle',{class:'c',cx:n.x,cy:n.y,r:n.r,fill:col(n.pct)});
  n.t=mk('text',{class:'lbl',x:n.x,y:n.y});
  const a=mk('tspan',{class:'b'});a.textContent=n.n;
  const b=mk('tspan',{x:n.x,dy:'1.15em'});b.textContent=n.pct+SUF[L];
  n.t.append(a,b);g.append(n.c,n.t);n.g=g;gN.appendChild(g);
}));

/* ---- conexiones: centro → hijos, hijos vecinos y saltos de dos (malla neuronal) ---- */
const edges=[];
function E(a,b,owner,tipo){
  const hi=Math.max(a.pct,b.pct),lo=Math.min(a.pct,b.pct),c=col(hi);
  const g=mk('g',{class:'e'});
  const base=mk('line',{class:'b',x1:a.x,y1:a.y,x2:b.x,y2:b.y,stroke:c,'stroke-width':(1+1.8*lo/100).toFixed(2)});
  g.appendChild(base);
  if(hi>=50){g.appendChild(mk('line',{class:'f',x1:a.x,y1:a.y,x2:b.x,y2:b.y,stroke:c}));}
  gE.appendChild(g);
  edges.push({g,a,b,o:owner,d:tipo==='s'?[b]:[a,b],child:b});
}
function conectar(owner,hub,kids){
  const m=kids.length;
  kids.forEach(c=>E(hub,c,owner,'s'));
  if(m<2)return;
  for(let i=0;i<m;i++){if(m===2&&i===1)break;E(kids[i],kids[(i+1)%m],owner,'m');}
  if(m>=5)for(let i=0;i<m;i+=2)E(kids[i],kids[(i+2)%m],owner,'m');
}
conectar(null,regs[0],regs.slice(1));
all.forEach(n=>{if(n.kids.length)conectar(n,n,n.kids);});

/* ---- dibujo según el zoom ---- */
function render(){
  world.setAttribute('transform','translate('+tx+','+ty+') scale('+k+')');
  const S=Math.min(W,H),cx=(W/2-tx)/k,cy=(H/2-ty)/k;
  for(const n of all)n.cv=n.kids.length?cl((n.F*k-.34*S)/(.14*S),0,1):0;
  /* solo se abre la rama que contiene lo que la persona está mirando: el nodo visible más cercano al centro */
  let N=null,nd=1e9;
  for(const n of all){if(n.r*k<10)continue;const d=Math.hypot(cx-n.x,cy-n.y);if(d<nd){nd=d;N=n;}}
  if(sel&&Math.hypot(cx-sel.parent.x,cy-sel.parent.y)<sel.parent.F)N=sel;
  const chain=new Set();for(let m=N;m;m=m.parent)chain.add(m);
  for(const n of all)if(!chain.has(n))n.cv=0;
  for(const n of all){
    n.show=n.parent?n.parent.cv*n.parent.show:1;
    const sib=n.parent?n.parent.kids:regs;
    let sm=0,km=0;for(const s of sib)if(s!==n&&s.cv>sm)sm=s.cv;for(const c of n.kids)if(c.cv>km)km=c.cv;
    n.op=n.show*(1-.9*sm)*(1-.85*km);
    const g=n.g,sr=n.r*k;
    g.style.opacity=n.op.toFixed(3);
    g.style.display=n.op<.02?'none':'';
    g.style.pointerEvents=(n.show<.5||n.cv>.5||n.op<.35)?'none':'auto';
    n.c.setAttribute('fill-opacity',(.92-.4*n.cv).toFixed(3));
    n.t.style.fontSize=(Math.min(cl(sr*.2,10,16),Math.max(7,sr*1.75/(n.n.length*.56)))/k)+'px';
    n.t.style.opacity=cl((sr-18)/10,0,1)*(1-km)*(1-sm);
  }
  const rmx=Math.max(0,...regs.map(r=>r.cv));
  for(const e of edges){
    const base=e.o?e.o.cv*e.o.show:1;
    let dm=0;for(const x of e.d)if(x.cv>dm)dm=x.cv;
    const o=base*(1-.85*dm)*(e.o?1:1-.85*rmx);
    e.g.style.opacity=o.toFixed(3);e.g.style.display=o<.02?'none':'';
  }
  const path=['Departamentos'];
  let f=null;
  for(const m of [...chain].reverse()){if(m.lvl<3&&m.cv>.3){path.push(m.n);f=m;}}
  focus=f;
  if(sel)path.push(sel.n);
  const txt=path.join(' › ');if($('crumb').textContent!==txt)$('crumb').textContent=txt;
  $('back').classList.toggle('on',!!(f||sel));
}
function clampK(v){return cl(v,k0*.7,k0*600);}
function go(cx,cy,kk,dur){
  cancelAnimationFrame(raf);kk=clampK(kk);
  const a={x:(W/2-tx)/k,y:(H/2-ty)/k,l:Math.log(k)},b={x:cx,y:cy,l:Math.log(kk)},t0=performance.now();dur=dur||600;
  (function step(now){
    const t=Math.min(1,(now-t0)/dur),e=t<.5?4*t*t*t:1-Math.pow(-2*t+2,3)/2;
    k=Math.exp(a.l+(b.l-a.l)*e);tx=W/2-(a.x+(b.x-a.x)*e)*k;ty=H/2-(a.y+(b.y-a.y)*e)*k;render();
    if(t<1)raf=requestAnimationFrame(step);
  })(t0);
}
const home=()=>go(0,0,k0);
const FIT=.5,fit=(n,fr)=>go(n.x,n.y,Math.min(W,H)*(fr||FIT)/n.F);
function zoomAt(f,mx,my){const nk=clampK(k*f);f=nk/k;tx=mx-(mx-tx)*f;ty=my-(my-ty)*f;k=nk;render();}

/* ---- caso: ubicación + cuestiones sospechosas (el panel lateral de la app se mantiene) ---- */
function caseView(n,dur){
  const d=n.parent,kk=clampK(Math.min(W,H)*FIT/d.F),sh=W>560?.2*W/kk:0;
  go(n.x-sh,n.y,kk,dur);
}
function showCase(n){
  sel&&sel.g.classList.remove('sel');edges.forEach(e=>e.g.classList.toggle('hot',e.child===n&&e.d.length===1));
  sel=n;n.g.classList.add('sel');
  det.hidden=false;det.style.animation='none';void det.offsetWidth;det.style.animation='';
  det.querySelector('.t').textContent=n.n+' · prioridad '+n.nivel;
  det.querySelector('.loc').textContent='📍 '+n.ruta.join(' › ');
  det.querySelector('.s').textContent=n.per+' personas · '+n.ex+' · '+n.est;
  const box=$('sig');box.textContent='';
  if(!n.sig.length){const q=document.createElement('div');q.className='sg';q.textContent='Sin señales relevantes en este caso.';box.appendChild(q);}
  n.sig.forEach(s=>{
    const q=document.createElement('div');q.className='sg';
    const b=document.createElement('b'),p=document.createElement('span'),a=document.createElement('span'),t=document.createElement('span');
    p.className='p';p.textContent='+'+s.p;b.textContent=s.t;b.appendChild(p);
    t.textContent=s.x;a.className='a';a.textContent='Podría ser: '+s.a;
    q.append(b,t,a);box.appendChild(q);
  });
  box.scrollTop=0;$('msg').textContent='';
}
function hideDet(){det.hidden=true;sel&&sel.g.classList.remove('sel');edges.forEach(e=>e.g.classList.remove('hot'));sel=null;}
function clickNode(n){
  hideHint();
  if(n.lvl===3){showCase(n);caseView(n);}else{hideDet();fit(n);}
}
function openCase(id){
  try{for(const b of window.parent.document.querySelectorAll('button')){if(b.textContent.trim()==='abrir_'+id){b.click();return;}}}catch(e){}
  $('msg').textContent='Ábrelo desde la cola de casos (derecha).';
}
$('rev').onclick=()=>sel&&openCase(sel.n);
$('x').onclick=hideDet;
$('zin').onclick=()=>go((W/2-tx)/k,(H/2-ty)/k,k*1.7,350);
$('zout').onclick=()=>go((W/2-tx)/k,(H/2-ty)/k,k/1.7,350);
$('zhome').onclick=()=>{hideDet();home();};
$('back').onclick=()=>{
  if(sel){const d=sel.parent;hideDet();fit(d);return;}
  focus&&focus.parent?fit(focus.parent):home();
};
let hinted=false;function hideHint(){if(!hinted){hinted=true;$('hint').style.opacity=0;}}
const ptr=new Map();let moved=false,downN=null,pinch=null;
svg.addEventListener('pointerdown',e=>{
  cancelAnimationFrame(raf);hideHint();try{svg.setPointerCapture(e.pointerId);}catch(_){}
  ptr.set(e.pointerId,{x:e.clientX,y:e.clientY});
  if(ptr.size===1){moved=false;const g=e.target.closest&&e.target.closest('.n');downN=g?g.__n:null;svg.classList.add('drag');}
  else{moved=true;pinch=null;}
});
svg.addEventListener('pointermove',e=>{
  const p=ptr.get(e.pointerId);
  if(!p){hover(e);return;}
  if(ptr.size===1){
    const dx=e.clientX-p.x,dy=e.clientY-p.y;
    if(!moved&&Math.hypot(dx,dy)<5)return;
    moved=true;tx+=dx;ty+=dy;p.x=e.clientX;p.y=e.clientY;tip.style.opacity=0;render();
  }else if(ptr.size===2){
    p.x=e.clientX;p.y=e.clientY;
    const [a,b]=[...ptr.values()],d=Math.hypot(a.x-b.x,a.y-b.y),mx=(a.x+b.x)/2,my=(a.y+b.y)/2,r=svg.getBoundingClientRect();
    if(pinch){zoomAt(d/pinch.d,mx-r.left,my-r.top);tx+=mx-pinch.mx;ty+=my-pinch.my;render();}
    pinch={d,mx,my};
  }
});
function up(e){
  if(!ptr.has(e.pointerId))return;ptr.delete(e.pointerId);pinch=null;
  if(ptr.size===0){svg.classList.remove('drag');if(!moved&&downN&&e.type==='pointerup')clickNode(downN);downN=null;}
}
svg.addEventListener('pointerup',up);svg.addEventListener('pointercancel',up);
svg.addEventListener('wheel',e=>{e.preventDefault();cancelAnimationFrame(raf);hideHint();const d=e.deltaMode===1?e.deltaY*16:e.deltaY,r=svg.getBoundingClientRect();zoomAt(Math.exp(-d*.0016),e.clientX-r.left,e.clientY-r.top);},{passive:false});
svg.addEventListener('dblclick',e=>{if(e.target.closest&&e.target.closest('.n'))return;const r=svg.getBoundingClientRect();zoomAt(1.9,e.clientX-r.left,e.clientY-r.top);});
function hover(e){
  if(e.pointerType==='touch')return;
  const g=e.target.closest&&e.target.closest('.n');
  if(!g||ptr.size){tip.style.opacity=0;return;}
  const r=wrap.getBoundingClientRect();tip.textContent=g.__n.h;tip.style.opacity=1;
  tip.style.left=Math.min(e.clientX-r.left+14,r.width-270)+'px';tip.style.top=(e.clientY-r.top+14)+'px';
}
svg.addEventListener('pointerleave',()=>tip.style.opacity=0);
function layout(){
  const r=wrap.getBoundingClientRect();W=r.width||600;H=r.height||500;
  k0=Math.min(W,H)/(2*ext*1.06);
  if(!ready){ready=true;k=k0;tx=W/2;ty=H/2;}
  render();
}
new ResizeObserver(layout).observe(wrap);layout();
/* si se llega desde la cola de casos: vuelo directo hasta el caso */
if(DATA.foco){
  const n=lv[3].find(c=>c.n===DATA.foco);
  if(n){hideHint();setTimeout(()=>{showCase(n);caseView(n,1500);},450);}
}
</script></body></html>
'''


# Distritos de demostración: los datos sintéticos solo traen provincia. Si algún día el archivo trae una
# columna «distrito», se usa esa; si no, cada caso recibe de forma estable un distrito real de su provincia.
DISTRITOS = {
    "Trujillo": ["Trujillo", "La Esperanza", "El Porvenir", "Huanchaco", "Víctor Larco Herrera"],
    "Ascope": ["Ascope", "Chicama", "Paiján", "Casa Grande"],
    "Chepén": ["Chepén", "Pacanga", "Pueblo Nuevo"],
    "Pacasmayo": ["Pacasmayo", "San Pedro de Lloc", "Guadalupe"],
    "Lima": ["Cercado de Lima", "San Juan de Lurigancho", "Ate", "Comas"],
    "Huaral": ["Huaral", "Chancay", "Aucallama"],
    "Cañete": ["San Vicente de Cañete", "Imperial", "Mala"],
    "Huaura": ["Huacho", "Huaura", "Végueta"],
    "Huancayo": ["Huancayo", "El Tambo", "Chilca"],
    "Tarma": ["Tarma", "Acobamba", "La Unión"],
    "Jauja": ["Jauja", "Marco", "Sausa"],
    "Satipo": ["Satipo", "Mazamari", "Pangoa"],
    "Pasco": ["Chaupimarca", "Yanacancha", "Simón Bolívar"],
    "Oxapampa": ["Oxapampa", "Villa Rica", "Pozuzo"],
    "Daniel Carrión": ["Yanahuanca", "Chacayán", "Paucar"],
    "Arequipa": ["Cayma", "Cerro Colorado", "Yanahuara", "Paucarpata"],
    "Camaná": ["Camaná", "Samuel Pastor", "Ocoña"],
    "Islay": ["Mollendo", "Cocachacra", "Punta de Bombón"],
    "Caylloma": ["Chivay", "Majes", "Cabanaconde"],
}


def distrito_de(r):
    d = getattr(r, "distrito", None)
    if isinstance(d, str) and d.strip():
        return d.strip()
    cat = DISTRITOS.get(r.provincia) or ["Sin distrito"]
    return cat[zlib.crc32(sorted(r.ids)[0].encode()) % len(cat)]


def datos_mapa(foco=None):
    """Departamentos › provincias › distritos › casos. Todo se envía de una vez; el zoom revela cada nivel en el navegador."""
    regs = []
    for z in sorted(D.zona.unique()):
        cs = DF[DF.zona == z]
        al = cs[cs.prioridad >= rc.ALERTA]
        provs = []
        for p in sorted(D[D.zona == z].provincia.unique()):
            sdp, csp = D[D.provincia == p], DF[DF.provincia == p]
            alp = csp[csp.prioridad >= rc.ALERTA]
            por_dist = {}
            for r in csp.head(10).itertuples():
                sig = [dict(t=s["titulo"], x=s["texto"], a=s["alt"], p=int(s["pts"]))
                       for s in r.senales if s["tipo"] != "ia" and s["pts"] > 0]
                dis = distrito_de(r)
                por_dist.setdefault(dis, []).append(dict(
                    n=r.id, pct=int(r.prioridad), exp=int(r.exposicion), nivel=r.nivel, per=int(r.personas),
                    ex=money(r.exposicion), est=r.estado, sig=sig, ruta=[z, p, dis],
                    h=f"{r.id} · prioridad {r.nivel} · {r.personas} personas · {money(r.exposicion)}"))
            dists = [dict(n=dn, pct=max(c["pct"] for c in cc), exp=sum(c["exp"] for c in cc),
                          h=f"{dn} · {len(cc)} casos · prioridad máxima {max(c['pct'] for c in cc)}", cases=cc)
                     for dn, cc in por_dist.items()]
            provs.append(dict(n=p, pct=round(100 * alp.solicitudes.sum() / max(len(sdp), 1)), exp=int(alp.exposicion.sum()),
                              h=f"{p} · {len(alp)} casos con alerta · {money(alp.exposicion.sum())} bajo revisión", dists=dists))
        regs.append(dict(n=z, pct=round(100 * al.solicitudes.sum() / max(len(D[D.zona == z]), 1)), exp=int(al.exposicion.sum()),
                         h=f"{z} · {len(al)} casos con alerta · {money(al.exposicion.sum())} bajo revisión", provs=provs))
    return dict(regs=regs, foco=foco)


def html_mapa():
    foco = ss.get("mapa_foco")
    if foco not in set(DF.id):
        foco = None
    datos = datos_mapa(foco)
    # el contador hace que «Ubicar» vuelva a lanzar el vuelo aunque se elija el mismo caso otra vez
    return MAPA_HTML.replace("__DATA__", json.dumps(datos, ensure_ascii=False).replace("</", "<\\/")) + f"<!--{ss.get('mapa_n', 0)}-->"


def p_inicio():
    st.markdown('<div class="hero-t">Una forma segura de monitorear los riesgos de fraude</div>', unsafe_allow_html=True)
    pend = DF[(DF.estado == "Pendiente") & (DF.prioridad >= rc.ALERTA)]
    alta = pend[pend.nivel == "Alta"]
    if len(pend):
        t = pend.iloc[0]
        res = (f"Hay <b>{len(pend)} casos pendientes</b> de prioridad media o alta, <b>{len(alta)}</b> de ellos altos. "
               f"El primero de la cola es <b>{t.id}</b>: {t.personas} personas y {money(t.exposicion)} de exposición bajo revisión.")
    else:
        res = "No hay casos pendientes de prioridad media o alta."
    st.markdown(f'<div class="sub">{res}</div>', unsafe_allow_html=True)

    activos = DF[(DF.prioridad >= rc.ALERTA) & (DF.estado != "Relación legítima")]
    c = st.columns(4)
    kpi(c[0], "Solicitudes analizadas", f"{len(D):,}", f"{D.id_persona.nunique():,} personas")
    kpi(c[1], "Redes identificadas", R["redes"], f"{len(DF)} con señales para revisar")
    kpi(c[2], "Casos pendientes de revisión", len(pend), f"{len(alta)} de prioridad alta")
    kpi(c[3], "Exposición económica bajo revisión", money(activos.exposicion.sum()), "No es pérdida ni fraude confirmado")
    st.write("")

    izq, der = st.columns([1.55, 1], gap="large")
    with izq:
        st.markdown("#### Mapa de riesgo")
        st.markdown('<div class="muted" style="margin-top:-8px">Acerca el mapa (rueda, pellizco o clic en un nodo) para bajar de '
                    'departamentos a provincias, distritos y casos. Color: prioridad.</div>', unsafe_allow_html=True)
        components.html(html_mapa(), height=540)
        for cid in DF.id:                      # botones ocultos: el mapa los pulsa para abrir un caso
            st.button(f"abrir_{cid}", key=f"go_{cid}", on_click=abrir, args=(cid,))
        st.caption("Haz clic en un caso (en el mapa o con «Ubicar» en la cola) para ver dónde está y qué lo hace sospechoso; pulsa «Revisar» para abrir su investigación.")

    with der:
        st.markdown("#### Cola de casos que requieren atención")
        cobertura = cand[cand.id.isin(PLAN)].exposicion.sum() / max(cand.exposicion.sum(), 1)
        st.markdown(f'<div class="muted" style="margin-top:-8px">Plan para {ss.horas} h: <b>{len(PLAN)} casos</b> '
                    f'({round(100 * cobertura)}% de la exposición en alertas). Ordenados por prioridad y exposición.</div>',
                    unsafe_allow_html=True)
        for r in cand.head(6).itertuples():
            a, b = st.columns([3.1, 1])
            hoy = '<span class="tag">Hoy</span>' if r.hoy else ""
            a.markdown(f'<div class="card" style="padding:10px 16px;margin-bottom:6px"><b>{r.id}</b> {badge(r.nivel)}{hoy}<br>'
                       f'<span class="muted">{r.personas} personas · {money(r.exposicion)} · {r.estado}</span></div>',
                       unsafe_allow_html=True)
            b.button("Ubicar", key=f"cola_{r.id}", on_click=ubicar, args=(r.id,), use_container_width=True)
        if cand.empty:
            st.info("No quedan casos por atender.")

    a, b = st.columns([1, 1.7], gap="large")
    with a:
        st.markdown("#### Distribución de prioridades")
        cnt = DF.nivel.value_counts().reindex(["Alta", "Media", "Baja"], fill_value=0)
        fig = go.Figure(go.Pie(labels=cnt.index, values=cnt.values, hole=.62, sort=False, textinfo="value",
                               marker=dict(colors=[NIVEL_COL[n] for n in cnt.index], line=dict(color="#15122b", width=2))))
        fig.add_annotation(text=f"<b>{cnt.sum()}</b><br>casos", showarrow=False, font=dict(size=18))
        st.plotly_chart(tema(fig, 300), use_container_width=True)
    with b:
        st.markdown("#### Evolución de alertas por fecha")
        fig = go.Figure()
        for n in ("Alta", "Media", "Baja"):
            fig.add_bar(x=S.dia, y=S[f"vinculadas_{n}"], name=n, marker_color=NIVEL_COL[n])
        fig.update_layout(barmode="stack", yaxis_title="Solicitudes vinculadas a casos")
        st.plotly_chart(tema(fig, 300), use_container_width=True)


# ================================================================== 2. INVESTIGACIONES
def p_inv():
    titulo("Investigaciones", "Cada fila es un grupo de solicitudes relacionadas. Haz clic en una fila para entrar directamente a su investigación.")
    f = st.columns([1.1, 1.2, 1.2, 1.3, 1.3])
    prio = f[0].multiselect("Prioridad", ["Alta", "Media", "Baja"], default=["Alta", "Media", "Baja"])
    est = f[1].multiselect("Estado de investigación", ESTADOS, default=ESTADOS)
    tip = f[2].multiselect("Tipo de conexión", TIPOS_CONEXION, default=[])
    lo, hi = DF.f_ini.min().date(), DF.f_fin.max().date()
    rango = f[3].date_input("Fecha de las solicitudes", value=(lo, hi), min_value=lo, max_value=hi)
    emin, emax = int(DF.exposicion.min()), int(DF.exposicion.max())
    exp = f[4].slider("Exposición (S/)", emin, emax, (emin, emax), step=500) if emin < emax else (emin, emax)

    m = DF.nivel.isin(prio) & DF.estado.isin(est) & DF.exposicion.between(*exp)
    if tip:
        m &= DF.tipos.map(lambda t: any(x in t for x in tip))
    if isinstance(rango, (tuple, list)) and len(rango) == 2:
        m &= (DF.f_fin.dt.date >= rango[0]) & (DF.f_ini.dt.date <= rango[1])
    orden = st.selectbox("Ordenar por", ["Orden sugerido de revisión", "Exposición económica", "Prioridad", "Fecha más reciente"])
    col = {"Orden sugerido de revisión": "indice", "Exposición económica": "exposicion", "Prioridad": "prioridad",
           "Fecha más reciente": "f_fin"}[orden]
    v = DF[m].sort_values(col, ascending=False).reset_index(drop=True)

    c = st.columns(4)
    kpi(c[0], "Casos que coinciden", len(v), f"de {len(DF)} en total")
    kpi(c[1], "Solicitudes vinculadas", int(v.solicitudes.sum()), f"{int(v.personas.sum())} personas")
    kpi(c[2], "Exposición bajo revisión", money(v.exposicion.sum()), "No es pérdida confirmada")
    kpi(c[3], "Para revisar hoy", int(v.hoy.sum()), f"con {ss.horas} h de capacidad")
    st.write("")
    if v.empty:
        st.info("Ningún caso coincide con los filtros. Amplía la prioridad, el estado o el rango de fechas.")
        return
    t = pd.DataFrame({"ID": v.id, "Solicitudes vinculadas": v.solicitudes, "Personas": v.personas, "Negocios": v.negocios,
                      "Señales detectadas": v.n_senales, "Exposición (S/)": v.exposicion, "Prioridad": v.nivel,
                      "Puntaje": v.prioridad, "Estado": v.estado, "Revisar hoy": v.hoy.map({True: "Sí", False: ""})})
    ev = st.dataframe(t, hide_index=True, use_container_width=True, on_select="rerun", selection_mode="single-row",
                      key="tabla_inv", height=min(60 + 35 * len(t), 560),
                      column_config={"Puntaje": st.column_config.ProgressColumn("Puntaje", format="%d", min_value=0, max_value=100),
                                     "Exposición (S/)": st.column_config.NumberColumn("Exposición", format="S/ %d")})
    fila = seleccion(ev)
    if fila:
        abrir(v.iloc[fila[0]].id)
        st.rerun()
    st.caption("El puntaje ordena la revisión; no es una probabilidad de fraude. Los casos de prioridad baja suelen ser relaciones normales "
               "(por ejemplo, familias que comparten dirección) y se muestran para facilitar su validación.")
    if ROL != "Jurado":
        st.download_button("Exportar casos filtrados (CSV)", t.to_csv(index=False).encode("utf-8"),
                           file_name="redshield_casos.csv", mime="text/csv")


# ================================================================== 3. INVESTIGACIÓN DE RED
def dibujar(r, foco, mostrar_sol, por_comunidad, hojas, casos_rel=True):
    ids = {f"persona:{p}" for p in r.ids}
    sup = R["sup"]
    com = rc.comunidades_caso(G, [n for n in r.nodos if n not in sup]) if por_comunidad else {}

    def k(n):
        return sum(1 for x in G.neighbors(n) if x in ids)

    mostrar = [n for n in r.nodos if G.nodes[n]["tipo"] == "persona" or n in sup or hojas or n == foco
               or k(n) >= 2 or G.degree(n) >= 2]
    vec = (set(G.neighbors(foco)) | {foco}) if foco else None
    net = Network(height="580px", width="100%", bgcolor="#0d0b20", font_color="#f4f3ff", cdn_resources="in_line")
    net.set_options(OPC_GRAFO)
    for n in mostrar:
        a = G.nodes[n]
        t = a["tipo"]
        col, forma = ESTILO[t]
        if t == "persona" and por_comunidad:
            col = COM_COL[com.get(n, 0) % len(COM_COL)]
        puente = t == "persona" and a["valor"] in r.brid
        if n in sup:
            col = C["gris"]
        op = 1 if vec is None or n in vec else .2
        kk = k(n)
        net.add_node(n, label=rc.etiqueta_nodo(a), shape=forma,
                     size=(26 if puente else 16) if t == "persona" else 14 + 6 * min(kk, 8),
                     color={"background": rgba(col, op), "border": rgba(C["rojo"] if puente else "#ffffff", op)},
                     borderWidth=4 if (puente or n == foco) else 1.5,
                     shapeProperties={"borderDashes": [4, 4] if n in sup else False},
                     title=(f"{rc.ETQ_TIPO[t]}: {rc.etiqueta_nodo(a)}" + ("" if t == "persona" else f" · {kk} persona(s) en este caso")
                            + (" · persona puente" if puente else "") + (" · supernodo (contexto)" if n in sup else "")))
    shown = set(mostrar)
    for u, v, dd in G.subgraph(shown).edges(data=True):
        enf = vec is None or u == foco or v == foco
        if dd["rel"] == "ref":
            net.add_edge(u, v, color=rgba(C["lila"], .95 if enf else .12), dashes=True, width=2.2)
        elif dd["rel"] == "declara":
            net.add_edge(u, v, color=rgba(C["lila"], .6 if enf else .1), width=1.6)
        else:
            net.add_edge(u, v, color=rgba("#ffffff", .34 if enf else .06), width=1.4, dashes=(u in sup or v in sup))
    if casos_rel:                      # círculos de caso (como en el mapa de inicio), en blanco para distinguirlos
        info = DF.set_index("id")
        yo = info.loc[r.id]                # el propio caso: círculo central unido a sus personas
        net.add_node(f"caso:{r.id}", label=f"{r.id}\n{int(yo.prioridad)} pts", shape="circle", size=36, borderWidth=3,
                     color={"background": rgba(C["blanco"], .95), "border": rgba(NIVEL_COL[yo.nivel], 1)},
                     font={"color": "#0b0a14", "size": 14},
                     title=f"Caso {r.id} · prioridad {yo.nivel} · {int(yo.personas)} personas · {money(yo.exposicion)}")
        for n in mostrar:
            if G.nodes[n]["tipo"] == "persona":
                net.add_edge(f"caso:{r.id}", n, color=rgba(C["blanco"], .3 if vec is None or n in vec else .06), dashes=True, width=1.2)
        for n in mostrar:
            for cid in sorted(R["nodo_casos"].get(n, set()) - {r.id}):
                if cid not in info.index:
                    continue
                cn, c_ = f"caso:{cid}", info.loc[cid]
                op = 1 if vec is None or n in vec else .2
                if cn not in net.node_ids:
                    net.add_node(cn, label=f"{cid}\n{int(c_.prioridad)} pts", shape="circle", size=30, borderWidth=2,
                                 color={"background": rgba(C["blanco"], .95 * op), "border": rgba(C["lila"], op)},
                                 font={"color": "#0b0a14", "size": 13},
                                 title=f"Caso {cid} · prioridad {c_.nivel} · {int(c_.personas)} personas · {money(c_.exposicion)}")
                net.add_edge(n, cn, color=rgba(C["blanco"], .8 * op), dashes=True, width=2,
                             title=f"{etq(n)} también aparece en {cid}")
    if mostrar_sol:
        for s in D[D.id_persona.isin(r.ids)].itertuples():
            sid = f"sol:{s.id_solicitud}"
            net.add_node(sid, label=str(s.id_solicitud), shape="dot", size=8, color=rgba("#ffffff", .85),
                         title=f"Solicitud {s.id_solicitud} · {money(s.monto)} · {s.fecha:%d/%m %H:%M}", font={"size": 9})
            net.add_edge(f"persona:{s.id_persona}", sid, color=rgba("#ffffff", .22), width=1)
    components.html(net.generate_html(), height=600)


def fila_info(a, b):
    return f'<div class="fila"><span>{a}</span><span>{b}</span></div>'


def p_red():
    if ss.caso not in set(DF.id):
        ss.caso = DF.id.iloc[0]
    ids = list(DF.id)
    top = st.columns([1.2, 3, 1.4])
    top[0].button("← Investigaciones", key="volver", on_click=ir, args=("Investigaciones",), use_container_width=True)
    sel = top[1].selectbox("Caso en investigación", ids, index=ids.index(ss.caso), label_visibility="collapsed",
                           format_func=lambda c: f"{c} · prioridad {DF.set_index('id').at[c, 'nivel']} · "
                                                 f"{money(DF.set_index('id').at[c, 'exposicion'])}")
    ss.caso = sel
    r = DF.set_index("id").loc[sel]
    r = r.rename("x")
    r.id = sel
    ss.t0.setdefault(sel, time.time())
    estado = r["estado"]
    st.markdown(f'<div class="card" style="padding:14px 20px"><span style="font-size:1.5rem;font-weight:700">{sel}</span> '
                f'{badge(r["nivel"])} <span class="tag">{estado}</span> '
                f'<span class="muted" style="margin-left:10px">{r["personas"]} personas · {r["negocios"]} negocios · '
                f'{r["solicitudes"]} solicitudes · {money(r["exposicion"])} de exposición · {r["provincia"]} ({r["zona"]})</span></div>',
                unsafe_allow_html=True)

    h = st.columns(4)
    kpi(h[0], "Personas puente", len(r["brid"]), "conectan grupos separados" if r["brid"] else "ninguna detectada")
    kpi(h[1], "Comunidades en la red", r["comunidades"], r["origen"])
    kpi(h[2], "Conexión más indirecta", f"{r['saltos']} saltos", "entre dos personas del caso")
    kpi(h[3], "Supernodos de contexto", r["n_ctx"], "no se usan para unir personas")
    st.write("")

    izq, der = st.columns([1.85, 1], gap="large")
    caso = types_ns(r, sel)
    with izq:
        st.markdown("#### 1. Red de conexiones")
        o = st.columns([2.1, 1, 1.1, 1, 1])
        nodos_sel = ["Ninguna"] + sorted(r["nodos"], key=lambda n: (G.nodes[n]["tipo"] != "persona", etq(n)))
        foco = o[0].selectbox("Explorar una entidad", nodos_sel, format_func=lambda n: n if n == "Ninguna" else etq(n))
        m_sol = o[1].toggle("Solicitudes", value=False, disabled=ROL == "Jurado",
                            help="Solo personal autorizado." if ROL == "Jurado" else None)
        m_com = o[2].toggle("Comunidades", value=False)
        m_hoj = o[3].toggle("Usos únicos", value=False)
        m_cas = o[4].toggle("Casos", value=True, help="Muestra este caso y los que comparten entidades con él como círculos blancos (como en el mapa de inicio).")
        dibujar(caso, None if foco == "Ninguna" else foco, m_sol, m_com, m_hoj, m_cas)
        st.markdown('<div class="leyenda">' + "".join(
            f'<span><span style="color:{ESTILO[t][0]}">●</span> {rc.ETQ_TIPO[t]}</span>' for t in ESTILO)
            + f'<span><span style="color:{C["rojo"]}">◎</span> Persona puente</span>'
            f'<span><span style="color:{C["gris"]}">●</span> Supernodo (contexto)</span>'
            f'<span><span style="color:{C["blanco"]}">⬤</span> Caso vinculado</span>'
            '<span>┅ Referencia</span><span>Tamaño: personas que lo comparten</span></div>', unsafe_allow_html=True)

        if foco != "Ninguna":
            st.markdown(f"##### Relaciones de {etq(foco)}")
            vec = [{"Tipo": rc.ETQ_TIPO[G.nodes[x]["tipo"]], "Entidad": rc.etiqueta_nodo(G.nodes[x]),
                    "Relación": {"usa": "usa", "declara": "declara", "ref": "se refieren"}[G.edges[foco, x]["rel"]],
                    "Caso": R["persona_caso"].get(G.nodes[x]["valor"], "—") if G.nodes[x]["tipo"] == "persona" else "—"}
                   for x in G.neighbors(foco)]
            st.dataframe(pd.DataFrame(vec), hide_index=True, use_container_width=True)
            otros = sorted(R["nodo_casos"].get(foco, set()) - {sel})
            if otros:
                st.markdown("Esta entidad también aparece en:")
                cc = st.columns(min(len(otros), 5))
                for i, c_ in enumerate(otros):
                    cc[i % len(cc)].button(f"Abrir {c_}", key=f"ent_{c_}", on_click=abrir, args=(c_,), use_container_width=True)
            if foco in R["sup"]:
                st.info("Este elemento lo usan muchas personas durante muchos días. Puede ser un cibercafé, una agencia o un servicio "
                        "legítimo, por eso no se usa para unir personas en el mismo caso.")

        with st.expander("Hallazgos estructurales"):
            if r["brid"]:
                for p, cs in r["brid"].items():
                    st.write(f"**Persona puente {p}**: " + (f"conecta este caso con {', '.join(cs)}." if cs
                                                        else "conecta comunidades dentro de este mismo caso."))
            else:
                st.write("No hay personas puente en este caso.")
            sups = [n for n in r["nodos"] if n in R["sup"]]
            for n in sups:
                a = G.nodes[n]
                st.write(f"**Supernodo {etq(n)}**: lo usan {G.degree(n)} personas durante "
                         f"{round((a['fmax'] - a['fmin']).total_seconds() / 86400)} días. Posible agencia, cibercafé o servicio legítimo.")
            st.dataframe(R["per"][R["per"].Caso == sel].drop(columns="Caso").sort_values("Centralidad (%)", ascending=False),
                         hide_index=True, use_container_width=True)
        if ROL != "Jurado":                # el jurado no ve datos por solicitud (seguridad)
            with st.expander("Solicitudes del caso"):
                vista = D[D.id_persona.isin(r["ids"])].sort_values("fecha")[["id_solicitud", "id_persona", "id_negocio", "fecha", "monto",
                                                                               "dispositivo", "telefono", "direccion", "ip", "correo"]].copy()
                vista["telefono"] = vista.telefono.map(lambda x: rc.mask_tel(x) if pd.notna(x) else x)
                vista["direccion"] = vista.direccion.map(lambda x: rc.mask_dir(x) if pd.notna(x) else x)
                vista["ip"] = vista.ip.map(lambda x: rc.mask_ip(x) if pd.notna(x) else x)
                vista["correo"] = vista.correo.map(lambda x: rc.mask_mail(x) if pd.notna(x) else x)
                st.dataframe(vista, hide_index=True, use_container_width=True)
                st.download_button("Descargar caso (CSV)", vista.to_csv(index=False).encode("utf-8"),
                                   file_name=f"{sel}.csv", mime="text/csv")

    with der:
        sen = sorted([s for s in r["senales"] if s["pts"] > 0], key=lambda s: -s["pts"])
        tipos = {}
        for n in r["nodos"]:
            tipos[G.nodes[n]["tipo"]] = tipos.get(G.nodes[n]["tipo"], 0) + 1
        ent = " · ".join(f"{v} {rc.ETQ_TIPO[k].lower()}{'s' if v > 1 and k != 'ip' else ''}" for k, v in tipos.items())
        alts = []
        for s in sen:
            if s["alt"] not in alts and s["tipo"] != "ia":
                alts.append(s["alt"])
        motivo = "; ".join(s["texto"][0].lower() + s["texto"][1:] for s in sen[:2]) or "sin señales relevantes"
        st.markdown("#### Explicación de la conexión")
        st.markdown('<div class="card">'
                    + fila_info("Conexión detectada", r["ruta_txt"] or "—")
                    + fila_info("Número de saltos", r["saltos"])
                    + fila_info("Entidades involucradas", ent)
                    + fila_info("Evidencia disponible", f"{r['n_senales']} señales · {r['solicitudes']} solicitudes · "
                                f"{r['f_ini']:%d/%m} al {r['f_fin']:%d/%m}")
                    + fila_info("Posible explicación legítima", " · ".join(alts[:2]) or "—")
                    + fila_info("Motivo de revisión", motivo) + '</div>', unsafe_allow_html=True)

        st.markdown("#### 2. Evidencias detectadas")
        for s in sen:
            st.markdown(f'<div class="ev" style="border-left-color:{REL_COL[s["rel"]]}"><b>{s["titulo"]}</b> '
                        f'<span class="tag" style="border-color:{REL_COL[s["rel"]]}">{s["rel"]}</span>'
                        f'<small>{s["texto"]}. Podría ser: {s["alt"]}.</small></div>', unsafe_allow_html=True)
        st.caption("Las señales son indicios, no pruebas. La señal de estructura poco habitual es exploratoria y no está validada.")

        st.markdown("#### 3. Explicación del sistema")
        st.markdown(f'<div class="card">{r["explicacion"]}</div>', unsafe_allow_html=True)

        st.markdown("#### 4. Decisión del analista")
        with st.container(border=True):
            st.text_area("Nota de verificación (qué se comprobó y con qué fuente)", key=f"nota_{sel}", height=90,
                         value="" if ROL == "Jurado" else next((e["detalle"] for e in reversed(ss.log) if e["caso"] == sel
                                     and e["accion"] in ESTADOS and e.get("fuente") == ss.fuente_id), ""), disabled=ROL == "Jurado")
            b = st.columns(3)
            for c_, acc in zip(b, ["Relación legítima", "En investigación", "Requiere escalamiento"]):
                c_.button(acc, key=f"dec_{acc}", on_click=decidir, args=(sel, acc), use_container_width=True,
                          disabled=ROL == "Jurado", type="primary" if estado == acc else "secondary")
            with st.expander("Agregar evidencia"):
                st.text_input("Describe la evidencia y su fuente", key=f"evid_{sel}", disabled=ROL == "Jurado")
                st.button("Agregar evidencia", key="b_evid", on_click=agregar_evidencia, args=(sel,), disabled=ROL == "Jurado")
            hist = [] if ROL == "Jurado" else [e for e in ss.log if e["caso"] == sel and e.get("fuente") == ss.fuente_id]
            if hist:
                st.dataframe(pd.DataFrame(hist)[["ts", "usuario", "accion", "detalle"]].rename(
                    columns={"ts": "Fecha y hora", "usuario": "Responsable", "accion": "Acción", "detalle": "Detalle"}).iloc[::-1],
                    hide_index=True, use_container_width=True)
            if ROL == "Jurado":
                st.caption("Modo solo lectura: las decisiones y notas internas las ven únicamente el personal autorizado.")
            st.markdown('<div class="muted" style="font-size:.84rem">El sistema no bloquea ni rechaza clientes: toda decisión que '
                        'afecte a una persona requiere revisión humana.</div>', unsafe_allow_html=True)


def types_ns(r, sel):
    """Adapta la fila del caso para dibujar (acceso por atributo)."""
    class Caso:
        pass
    c = Caso()
    c.ids, c.nodos, c.brid, c.id = list(r["ids"]), list(r["nodos"]), r["brid"], sel
    return c


# ================================================================== 4. ANÁLISIS TEMPORAL
def p_temporal():
    titulo("Análisis temporal", "¿Las conexiones aparecen de forma normal o están creciendo rápido? "
           "Una concentración repentina puede justificar una revisión, pero no demuestra fraude por sí sola.")
    n = st.slider("Días por periodo a comparar", 3, 14, 7)
    fin = S.dia.max()
    a0 = fin - pd.Timedelta(days=n - 1)
    b0 = a0 - pd.Timedelta(days=n)
    A, B = S[S.dia >= a0], S[(S.dia >= b0) & (S.dia < a0)]
    ini = DF.f_ini.dt.normalize()

    def nuevos(lo, hi):
        return DF[(ini >= lo) & (ini <= hi) & (DF.prioridad >= rc.ALERTA)]
    NA, NB = nuevos(a0, fin), nuevos(b0, a0 - pd.Timedelta(days=1))
    c = st.columns(4)
    c[0].metric("Solicitudes", int(A.solicitudes.sum()), int(A.solicitudes.sum() - B.solicitudes.sum()), delta_color="off")
    c[1].metric("Nuevas conexiones", int(A.nuevas_conexiones.sum()), int(A.nuevas_conexiones.sum() - B.nuevas_conexiones.sum()), delta_color="off")
    c[2].metric("Casos nuevos con alerta", len(NA), len(NA) - len(NB), delta_color="off")
    c[3].metric("Exposición de casos nuevos", money(NA.exposicion.sum()), int(NA.exposicion.sum() - NB.exposicion.sum()), delta_color="off")
    st.caption(f"Últimos {n} días ({a0:%d/%m} al {fin:%d/%m}) frente a los {n} anteriores ({b0:%d/%m} al {(a0 - pd.Timedelta(days=1)):%d/%m}).")

    izq, der = st.columns(2, gap="large")
    with izq:
        st.markdown("#### Línea de tiempo de solicitudes")
        fig = go.Figure()
        fig.add_bar(x=S.dia, y=S.solicitudes, name="Solicitudes", marker_color=rgba(C["lila"], .75))
        fig.add_scatter(x=S.dia, y=S.nuevas_conexiones, name="Nuevas conexiones", mode="lines+markers",
                        line=dict(color=C["amarillo"], width=3))
        st.plotly_chart(tema(fig, 330), use_container_width=True)
    with der:
        st.markdown("#### Entidades conectadas (acumulado)")
        fig = go.Figure(go.Scatter(x=S.dia, y=S.entidades_conectadas, mode="lines", fill="tozeroy",
                                   line=dict(color=C["celeste"], width=3), fillcolor=rgba(C["celeste"], .22)))
        st.plotly_chart(tema(fig, 330), use_container_width=True)

    izq, der = st.columns([1, 1.3], gap="large")
    with izq:
        st.markdown(f"#### Últimos {min(7, len(S))} días")
        t = S.tail(7)[["dia", "solicitudes", "nuevas_conexiones"]].copy()
        t["dia"] = t.dia.dt.strftime("%a %d/%m")
        st.dataframe(t.rename(columns={"dia": "Día", "solicitudes": "Solicitudes", "nuevas_conexiones": "Nuevas conexiones"}),
                     hide_index=True, use_container_width=True)
        st.markdown("#### Ráfagas de solicitudes")
        rf = DF[DF.rafaga >= 4].sort_values("rafaga_ini", ascending=False)
        if rf.empty:
            st.write("No hay ráfagas de 4 o más solicitudes vinculadas en menos de 72 horas.")
        else:
            st.dataframe(pd.DataFrame({"Caso": rf.id, "Solicitudes en 72 h": rf.rafaga, "Desde": rf.rafaga_ini.dt.strftime("%d/%m %H:%M"),
                                       "Prioridad": rf.nivel}), hide_index=True, use_container_width=True)
    with der:
        st.markdown("#### Crecimiento de comunidades")
        defecto = list(DF[DF.prioridad >= rc.ALERTA].id.head(4))
        sel = st.multiselect("Casos a comparar", list(DF.id), default=defecto)
        primero = D.groupby("id_persona").fecha.min().dt.normalize()
        fig = go.Figure()
        for i, cid in enumerate(sel):
            s = primero[DF.set_index("id").at[cid, "ids"]].value_counts().sort_index().cumsum()
            fig.add_scatter(x=s.index, y=s.values, name=cid, mode="lines+markers", line=dict(shape="hv", width=3, color=COM_COL[i % 6]))
        fig.update_layout(yaxis_title="Personas conectadas")
        st.plotly_chart(tema(fig, 330), use_container_width=True)
        st.caption("Cada línea muestra cuántas personas del caso ya habían solicitado crédito en cada fecha.")


# ================================================================== 5. EVALUACIÓN
def p_eval():
    titulo("Evaluación del modelo", "Evidencia de efectividad: ¿RedShield aporta valor o solo encuentra lo que se programó?")
    ev = R["ev"]
    reg = [e for e in ss.log if e.get("fuente") == ss.fuente_id and e["accion"] in ESTADOS and e.get("segundos") is not None]
    seg = pd.Series([e["segundos"] for e in reg]).median() if reg else None
    tiempo = (f"{seg / 60:.1f} min", f"mediana de {len(reg)} decisiones en esta sesión") if reg else \
        ("Pendiente de validación", "se medirá con analistas reales")
    if ev is None:
        st.markdown('<div class="pend"><b>Pendiente de validación.</b> El archivo cargado no trae etiquetas de casos conocidos '
                    '(columna <i>etiqueta</i> con «fraude» o «legitimo»), así que no se calculan precisión, recall ni falsos positivos. '
                    'No se muestran cifras inventadas.</div>', unsafe_allow_html=True)
        c = st.columns(5)
        for col_, t in zip(c, ["Precisión", "Recall", "Falsos positivos", "Comparación con SQL"]):
            kpi(col_, t, "Pendiente", "requiere datos etiquetados")
        kpi(c[4], "Tiempo de revisión", tiempo[0], tiempo[1])
    else:
        st.markdown('<div class="pend"><b>Cómo leer estas cifras.</b> Se calculan sobre un conjunto sintético con la verdad conocida, '
                    'que incluye casos difíciles a propósito (cibercafé, familias, negocio familiar y fraudes que el sistema no detecta). '
                    'Validan el funcionamiento del flujo, no el desempeño real: falta validarlo con casos históricos etiquetados de Caja Trujillo. '
                    'Isolation Forest es una señal exploratoria que aporta hasta 10 puntos y no es un detector validado.</div>',
                    unsafe_allow_html=True)
        st.write("")
        T = ev["tabla"].set_index("Método")
        rs, sql = T.loc["RedShield completo"], T.loc["Consulta SQL (dispositivo o teléfono compartido)"]
        c = st.columns(5)
        kpi(c[0], "Precisión", f"{rs['Precisión (%)']}%", f"{rs['Verdaderos positivos']} de {rs['Alertas']} alertas fueron relevantes")
        kpi(c[1], "Recall", f"{rs['Recall (%)']}%", f"{rs['Verdaderos positivos']} de {ev['fraudes']} personas con fraude simulado")
        kpi(c[2], "Falsos positivos", int(rs["Falsos positivos"]), f"consulta SQL: {int(sql['Falsos positivos'])}")
        kpi(c[3], "Tiempo de revisión", tiempo[0], tiempo[1])
        kpi(c[4], "Valor frente a SQL", f"+{int(rs['Precisión (%)'] - sql['Precisión (%)'])} pts", "de precisión con recall similar o mayor")
        st.write("")
        izq, der = st.columns([1.5, 1], gap="large")
        with izq:
            st.markdown("#### Reglas frente a análisis de grafos")
            fig = go.Figure()
            fig.add_bar(x=T.index, y=T["Precisión (%)"], name="Precisión", marker_color=C["lila"])
            fig.add_bar(x=T.index, y=T["Recall (%)"], name="Recall", marker_color=C["celeste"])
            fig.update_layout(barmode="group", yaxis_range=[0, 100])
            fig.update_xaxes(tickangle=-12)
            st.plotly_chart(tema(fig, 360), use_container_width=True)
        with der:
            st.markdown("#### Matriz de confusión (RedShield)")
            cf = ev["conf"]
            z = [[cf["tp"], cf["fn"]], [cf["fp"], cf["tn"]]]
            zc = [[cf["tp"] / max(cf["tp"] + cf["fn"], 1), cf["fn"] / max(cf["tp"] + cf["fn"], 1)],
                  [cf["fp"] / max(cf["fp"] + cf["tn"], 1), cf["tn"] / max(cf["fp"] + cf["tn"], 1)]]
            fig = go.Figure(go.Heatmap(z=zc, x=["Con alerta", "Sin alerta"], y=["Fraude simulado", "Legítimo"], text=z,
                                       texttemplate="%{text}", textfont=dict(size=22), showscale=False,
                                       colorscale=[[0, "#1d1a3a"], [1, "#8f7bff"]], xgap=4, ygap=4))
            fig.update_yaxes(autorange="reversed")
            st.plotly_chart(tema(fig, 360), use_container_width=True)
        st.markdown("#### Comparación completa (por persona)")
        st.dataframe(ev["tabla"], hide_index=True, use_container_width=True)
        st.caption("Con y sin señales temporales: compara las dos últimas filas. SQL = una consulta JOIN que marca a quien comparte "
                   "dispositivo o teléfono con otra persona, con valores exactos y sin normalizar.")
        if ev["fallos"] is not None:
            st.markdown("#### Qué se le escapa y dónde se equivoca RedShield")
            st.dataframe(ev["fallos"], hide_index=True, use_container_width=True)
            st.caption("Mostrar los límites es parte de la evaluación: estos casos alimentan la calibración futura.")

    st.markdown("#### Historial de retroalimentación del analista")
    dec = [e for e in ss.log if e.get("fuente") == ss.fuente_id and e["accion"] in ESTADOS]
    if not dec:
        st.markdown('<div class="pend">Aún no hay decisiones registradas. Cuando los analistas marquen casos como «Relación legítima», '
                    '«En investigación» o «Requiere escalamiento», aquí se medirá qué proporción de alertas fue descartada.</div>',
                    unsafe_allow_html=True)
    else:
        ultimo = {}
        for e in dec:
            ultimo[e["caso"]] = e["accion"]
        alertas = [c for c in ultimo if c in set(DF[DF.prioridad >= rc.ALERTA].id)]
        desc = sum(1 for c in alertas if ultimo[c] == "Relación legítima")
        c = st.columns(3)
        kpi(c[0], "Casos con decisión", len(ultimo), f"{len(dec)} acciones registradas")
        kpi(c[1], "Alertas descartadas por el analista", f"{desc} de {len(alertas)}" if alertas else "—", "marcadas como relación legítima")
        kpi(c[2], "Uso previsto", "Calibración", "las decisiones ajustarán pesos y umbrales (hoja de ruta)")
        if ROL != "Jurado":                # el jurado ve solo las cifras, sin notas ni responsables
            st.dataframe(pd.DataFrame(dec)[["ts", "usuario", "caso", "accion", "detalle", "segundos"]].iloc[::-1].rename(
                columns={"ts": "Fecha y hora", "usuario": "Responsable", "caso": "Caso", "accion": "Decisión", "detalle": "Nota",
                         "segundos": "Segundos de revisión"}), hide_index=True, use_container_width=True)

    st.markdown("#### Calibración con la retroalimentación del analista")
    if PESOS:
        tc = pd.DataFrame([dict(Señal=k.capitalize(), Decisiones=v["n"], Descartadas=v["legitimas"], Escaladas=v["escaladas"],
                                Multiplicador=v["mult"],
                                Estado="Aplicable" if v["aplica"] else f"Faltan {rc.MIN_CALIB - v['n']} decisiones")
                           for k, v in sorted(PESOS.items())])
        st.dataframe(tc, hide_index=True, use_container_width=True)
        st.caption("Ajuste simple y transparente, no un modelo entrenado: si los analistas descartan seguido los casos con una señal, "
                   "esa señal pesa menos. Actívalo con «Calibrar con decisiones del analista» en la barra lateral. "
                   + ("Está activo ahora." if CALIBRADO else "Ahora está desactivado."))
    else:
        st.markdown('<div class="pend">Cuando haya decisiones registradas se mostrará cómo cambiaría el peso de cada señal.</div>',
                    unsafe_allow_html=True)


# ================================================================== 6. DATOS Y AUDITORÍA
def p_datos():
    titulo("Datos y auditoría", "Trazabilidad: de dónde vienen los datos, quién decidió qué y cómo se protege la información.")
    nombres = TABS_DATOS[ROL]
    tabs = dict(zip(nombres, st.tabs(nombres)))
    if "Importar datos" in tabs:
        with tabs["Importar datos"]:
            st.markdown("Carga un archivo CSV o Excel con solicitudes. RedShield valida columnas y formatos antes de analizarlo.")
            st.caption("Requeridas: " + ", ".join(rc.REQUERIDAS) + ". Opcionales: " + ", ".join(rc.OPCIONALES)
                       + ". Con la columna «etiqueta» (fraude / legitimo) se habilita la evaluación del modelo.")
            st.download_button("Descargar plantilla CSV", rc.PLANTILLA.to_csv(index=False).encode("utf-8"),
                               file_name="plantilla_redshield.csv", mime="text/csv")
            f = st.file_uploader("Archivo CSV o Excel", type=["csv", "xlsx"])
            if f is not None:
                try:
                    raw = (pd.read_csv(f, dtype=str) if f.name.lower().endswith(".csv") else pd.read_excel(f, dtype=str))  # texto: no pierde ceros ni convierte teléfonos en decimales
                except Exception as ex:
                    st.error(f"No se pudo leer el archivo: {ex}")
                else:
                    limpio, refs_i, rep = rc.validar(raw)
                    st.dataframe(pd.DataFrame(rep, columns=["Validación", "Resultado", "Estado"]), hide_index=True, use_container_width=True)
                    if limpio is None:
                        st.error("Corrige los errores indicados y vuelve a cargar el archivo.")
                    elif ROL == "Supervisor" and st.button("Analizar este archivo", type="primary"):
                        ss.datos_import = dict(sols=limpio, refs=refs_i, nombre=f.name)
                        ss.importaciones.append(dict(fecha=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), usuario=ss.usuario,
                                                     archivo=f.name, filas=len(limpio), estado="Aplicado"))
                        ss.foco = ss.caso = None
                        st.rerun()
            if imp and st.button("Volver a los datos sintéticos"):
                ss.pop("datos_import", None)
                ss.caso = None
                st.rerun()
    if "Calidad de datos" in tabs:
        with tabs["Calidad de datos"]:
            cols_ = ["id_persona", "id_negocio", "dispositivo", "telefono", "direccion", "ip", "correo", "provincia", "monto"]
            q = pd.DataFrame({"Columna": cols_, "Completitud (%)": [round(100 * (1 - D[c].isna().mean())) for c in cols_],
                              "Valores distintos": [int(D[c].nunique()) for c in cols_]})
            st.dataframe(q, hide_index=True, use_container_width=True,
                         column_config={"Completitud (%)": st.column_config.ProgressColumn("Completitud (%)", format="%d%%", min_value=0, max_value=100)})
            c = st.columns(4)
            kpi(c[0], "Solicitudes duplicadas", int(D.id_solicitud.duplicated().sum()), "por identificador")
            kpi(c[1], "Direcciones unificadas", int(D.direccion.nunique() - D.direccion_n.nunique()), "variantes de escritura reconocidas")
            kpi(c[2], "Teléfonos unificados", int(D.telefono_orig.nunique() - D.telefono.nunique()),
                "números que difieren en un solo dígito")
            kpi(c[3], "Supernodos excluidos", len(R["sup"]), "elementos usados por muchas personas")
    if "Historial de importaciones" in tabs:
        with tabs["Historial de importaciones"]:
            if ss.importaciones:
                st.dataframe(pd.DataFrame(ss.importaciones), hide_index=True, use_container_width=True)
            else:
                st.markdown('<div class="pend">Todavía no se importó ningún archivo. Se están usando datos sintéticos de demostración.</div>',
                            unsafe_allow_html=True)
    if "Usuarios y roles" in tabs:
        with tabs["Usuarios y roles"]:
            si, no = "Sí", "No"
            st.dataframe(pd.DataFrame([
                dict(Rol="Jurado (visitante)", **{"Paneles": "Todos menos Inicio", "Ver casos": "Sí, datos limitados",
                     "Registrar decisión": no, "Ver notas y registro": no, "Descargar datos": no, "Importar datos": no}),
                dict(Rol="Analista", **{"Paneles": "Todos menos Inicio", "Ver casos": si, "Registrar decisión": si,
                     "Ver notas y registro": si, "Descargar datos": si, "Importar datos": no}),
                dict(Rol="Supervisor", **{"Paneles": "Todos", "Ver casos": si, "Registrar decisión": si,
                     "Ver notas y registro": si, "Descargar datos": si, "Importar datos": si}),
            ]), hide_index=True, use_container_width=True)
            st.caption("Demostración de control de acceso por rol. En producción se integraría con el directorio de usuarios de la institución.")
    if "Registro de decisiones" in tabs:
        with tabs["Registro de decisiones"]:
            lg = [e for e in ss.log if e.get("fuente") == ss.fuente_id]
            if lg:
                t = pd.DataFrame(lg)[["ts", "usuario", "rol", "caso", "accion", "detalle", "segundos"]].iloc[::-1].rename(
                    columns={"ts": "Fecha y hora", "usuario": "Responsable", "rol": "Rol", "caso": "Caso", "accion": "Acción",
                             "detalle": "Detalle", "segundos": "Segundos de revisión"})
                st.dataframe(t, hide_index=True, use_container_width=True)
                st.download_button("Exportar registro (CSV)", t.to_csv(index=False).encode("utf-8"),
                                   file_name="registro_auditoria.csv", mime="text/csv")
            else:
                st.markdown('<div class="pend">Aún no hay acciones. Cada decisión queda con fecha, hora y responsable.</div>', unsafe_allow_html=True)
            if ROL == "Supervisor" and st.button("Reiniciar demostración (borra el registro)"):
                ss.log = []
                try:
                    os.remove(LOG_PATH)
                except OSError:
                    pass
                st.rerun()
    if "Privacidad y cumplimiento" in tabs:
        with tabs["Privacidad y cumplimiento"]:
            st.dataframe(pd.DataFrame([
                ("Seudonimización en pantalla", "Teléfonos, direcciones, IP y correos se muestran enmascarados", "En el prototipo"),
                ("Minimización de datos", "No se usan nombres, DNI ni datos de cuentas", "En el prototipo"),
                ("Control de acceso por rol", "Jurado (solo lectura y datos mínimos), analista y supervisor, con clave para el personal", "En el prototipo"),
                ("Trazabilidad", "Fecha, hora, responsable y nota de cada decisión", "En el prototipo"),
                ("Decisión humana", "El sistema no bloquea ni rechaza clientes", "En el prototipo"),
                ("Ley 29733: finalidad, consentimiento y retención", "Definir con Caja Trujillo qué bases legales y plazos aplican", "Hoja de ruta"),
                ("Cifrado y gestión de accesos real", "Integración con el directorio y la bóveda de la institución", "Hoja de ruta"),
                ("Análisis de sesgo", "Verificar que señales como la dirección compartida no afecten más a ciertas zonas", "Hoja de ruta"),
            ], columns=["Control", "Qué hace", "Estado"]), hide_index=True, use_container_width=True)
            st.caption("Este panel describe controles de diseño; no es una certificación de cumplimiento legal.")
    if "Equidad (sesgo)" in tabs:
        with tabs["Equidad (sesgo)"]:
            st.markdown("¿Las alertas se concentran más en ciertas regiones? Una diferencia grande no prueba sesgo, pero obliga a "
                        "revisar si alguna señal (por ejemplo, compartir dirección) afecta más a ciertas zonas.")
            niv = DF.set_index("id").prioridad
            P1 = D.drop_duplicates("id_persona")[["id_persona", "zona"]].copy()
            P1["alerta"] = P1.id_persona.map(lambda p: R["persona_caso"].get(p) in niv.index and niv[R["persona_caso"][p]] >= rc.ALERTA)
            g = P1.groupby("zona").agg(Personas=("id_persona", "size"), En_alerta=("alerta", "sum")).reset_index()
            g["Tasa de alerta (%)"] = (100 * g.En_alerta / g.Personas).round(1)
            tot = 100 * g.En_alerta.sum() / max(g.Personas.sum(), 1)
            g["Frente al promedio"] = g["Tasa de alerta (%)"].map(lambda x: f"{x - tot:+.1f} pts")
            st.dataframe(g.rename(columns={"zona": "Región", "En_alerta": "Personas en casos con alerta"}),
                         hide_index=True, use_container_width=True)
            fig = go.Figure(go.Bar(x=g.zona, y=g["Tasa de alerta (%)"], marker_color=C["lila"]))
            fig.add_hline(y=tot, line_dash="dash", line_color=C["amarillo"], annotation_text=f"Promedio {tot:.1f}%")
            fig.update_layout(yaxis_title="% de personas con alerta")
            st.plotly_chart(tema(fig, 300), use_container_width=True)
            st.caption("Medida de diseño: la dirección compartida aporta solo 5 puntos y no alcanza por sí sola el umbral de alerta "
                       f"({rc.ALERTA}), para no penalizar a familias que viven juntas. Estas cifras provienen de datos sintéticos; "
                       "con datos reales habría que repetir el análisis, incluyendo variables socioeconómicas autorizadas.")


{"Inicio": p_inicio, "Investigaciones": p_inv, "Investigación de red": p_red, "Análisis temporal": p_temporal,
 "Evaluación del modelo": p_eval, "Datos y auditoría": p_datos}[ss.panel]()

st.markdown("---")
st.caption("RedShield · Prototipo para Cajathon 2026 (Eje 3) · Datos sintéticos · Los resultados requieren validación humana "
           "y no deben usarse para tomar decisiones crediticias.")
