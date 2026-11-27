"""
RedShield · motor de análisis (sin interfaz).

Todo el flujo vive aquí: datos -> normalización -> grafo -> casos -> señales
-> priorización -> evaluación -> serie temporal.
Los datos de demostración son SINTÉTICOS (no hay personas reales).

Principio de diseño: el sistema no acusa a nadie. La prioridad ordena qué
revisar primero; no es una probabilidad de fraude.
"""
import itertools
import math
import random
import re
import unicodedata
from datetime import datetime, timedelta

import networkx as nx
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# ------------------------------------------------------------------ constantes
ALERTA, ALTA = 30, 60            # prioridad mínima para "Media" y "Alta"
MIN_CALIB = 3                    # decisiones mínimas por tipo de señal para recalibrar su peso
SUPER_N, SUPER_H = 8, 240        # supernodo: >= 8 personas y uso sostenido >= 10 días
MITIGAR_DEMANDA = True           # descuenta la señal de ráfaga si la región vive un aumento de demanda (campaña, FEN)
DEMANDA_X = 2.5                  # veces el volumen habitual de la región en esa ventana para considerarlo aumento
EXPLICAR_RELACIONES = True       # un grupo con un mismo domicilio o un mismo negocio cuenta como UNA relación, no como varias
CAP_EXPLICADO = 25               # tope de puntos de las señales explicables (por debajo de ALERTA)
EXPLICABLES = ("telefono", "correo", "direccion", "referencia", "negocio")
TERRITORIO = {
    "La Libertad": ["Trujillo", "Ascope", "Chepén", "Pacasmayo"],
    "Lima": ["Lima", "Huaral", "Cañete", "Huaura"],
    "Junín": ["Huancayo", "Tarma", "Jauja", "Satipo"],
    "Pasco": ["Pasco", "Oxapampa", "Daniel Carrión"],
    "Arequipa": ["Arequipa", "Camaná", "Islay", "Caylloma"],
}
PROV2ZONA = {p: z for z, ps in TERRITORIO.items() for p in ps}
COLS_ATTR = [("dispositivo", "dispositivo"), ("telefono", "telefono"), ("direccion_n", "direccion"),
             ("ip", "ip"), ("correo", "correo")]
TIPOS_ATTR = ("dispositivo", "telefono", "direccion", "ip", "correo")
ETQ_TIPO = {"persona": "Persona", "negocio": "Negocio", "dispositivo": "Dispositivo", "telefono": "Teléfono",
            "direccion": "Dirección", "ip": "IP", "correo": "Correo", "solicitud": "Solicitud"}
REQUERIDAS = ["id_solicitud", "id_persona", "fecha", "monto", "dispositivo", "telefono", "direccion"]
OPCIONALES = ["ip", "correo", "id_negocio", "provincia", "etiqueta", "id_referencia"]
FEATURES_IA = ["personas", "negocios", "solicitudes", "max_dev", "max_tel", "max_ip", "max_neg",
               "rafaga", "refs", "densidad", "grado_max", "puentes", "saltos"]

ESCENARIOS = {
    "A": "Un dispositivo compartido por 6 solicitantes en menos de 2 días, con negocios compartidos",
    "B": "Un teléfono compartido por 5 solicitantes con referencias en cadena",
    "C": "Dos dispositivos unidos por una persona, ráfaga de solicitudes y referencias cruzadas",
    "F": "Dos grupos unidos por una sola persona puente",
    "M": "Un teléfono compartido, pero con un dígito distinto en cada solicitud (evasión por error de tipeo)",
    "I": "Misma IP y misma dirección escrita de formas distintas",
    "L": "Cadena: cada par comparte algo distinto (dispositivo, teléfono, negocio, referencia)",
    "J": "Tres personas enlazadas solo por dos referencias, sin nada compartido",
    "K": "Una IP compartida por 4 personas repartidas en un mes",
    "E": "Un dispositivo compartido por 3 personas de la misma familia o asesor (legítimo)",
    "H": "Negocio familiar que comparte teléfono y negocio (legítimo)",
    "D": "Familia con dirección común y referencias (legítimo)",
    "G": "Cibercafé o asesor con un elemento usado por muchos clientes (legítimo)",
}

# ------------------------------------------------------------ seudonimización
def mask_tel(t):
    t = str(t)
    return f"{t[0]}****{t[-3:]}" if len(t) >= 4 else "***"


def mask_dir(a):
    return re.sub(r"\d+", "***", str(a))


def mask_mail(m):
    u, _, dom = str(m).partition("@")
    return f"{u[:1]}***@{dom}"


def mask_ip(ip):
    p = str(ip).split(".")
    return ".".join(p[:2] + ["*", "*"]) if len(p) == 4 else "***"


def etiqueta_nodo(a):
    """Texto seguro (enmascarado) para mostrar un nodo del grafo."""
    t, v = a["tipo"], a["valor"]
    if t == "telefono":
        return mask_tel(v)
    if t == "direccion":
        return mask_dir(v).split(",")[0]
    if t == "correo":
        return mask_mail(v)
    if t == "ip":
        return mask_ip(v)
    return str(v)


def unificar_telefonos(tels, max_grupo=6):
    """Resolución de entidades: teléfonos que difieren en un solo dígito se tratan como el mismo.
    Evita que un tipeo distinto (o un dígito cambiado a propósito) oculte la conexión.
    Un grupo de más de `max_grupo` números no se une (riesgo de falsos vínculos)."""
    vals = sorted({t for t in tels.dropna() if len(t) == 9})
    padre = {t: t for t in vals}

    def raiz(x):
        while padre[x] != x:
            padre[x] = padre[padre[x]]
            x = padre[x]
        return x
    for i in range(1, 9):                                 # el primer dígito (9) se mantiene
        cubos = {}
        for t in vals:
            cubos.setdefault(t[:i] + "*" + t[i + 1:], []).append(t)
        for g in cubos.values():
            for t in g[1:]:
                padre[raiz(t)] = raiz(g[0])
    grupos = {}
    for t in vals:
        grupos.setdefault(raiz(t), []).append(t)
    uso = tels.value_counts()
    canon = {}
    for g in grupos.values():
        if len(g) <= max_grupo:
            c = max(g, key=lambda x: (int(uso.get(x, 0)), x))
            canon.update({t: c for t in g})
    return tels.map(lambda t: canon.get(t, t) if pd.notna(t) else t).astype("string")


def norm_dir(a):
    """'Av. Larco N° 215' y 'AVENIDA LARCO 215' se reconocen como la misma dirección."""
    a = unicodedata.normalize("NFKD", str(a)).encode("ascii", "ignore").decode().lower()
    a = re.sub(r"[^a-z0-9 ]", " ", a)
    rep = {"avenida": "av", "jiron": "jr", "calle": "cl", "nro": "", "numero": "", "no": "", "n": ""}
    return " ".join(t for t in (rep.get(t, t) for t in a.split()) if t)


# -------------------------------------------------------------- datos sintéticos
def generar_datos(seed=7):
    """Solicitudes sintéticas con verdad conocida (etiqueta/escenario) para validar el flujo.

    Incluye casos difíciles a propósito: legítimos que parecen sospechosos (cibercafé,
    familias, negocio familiar) y fraudes que el sistema NO detecta bien (J y K).
    """
    rnd = random.Random(seed)
    base = datetime(2026, 10, 27, 8, 0)
    cnt = dict(p=0, d=0, a=0, s=0, n=0)
    pool_tel = rnd.sample(range(10_000_000, 99_999_999), 3000)
    nombres = ["ana", "luis", "rosa", "jose", "maria", "carlos", "lucia", "pedro", "elena", "jorge",
               "carmen", "diego", "sofia", "victor", "julia", "mario", "paula", "raul", "nora", "hugo"]
    calles = ["Av. Larco", "Jr. Pizarro", "Av. España", "Calle Los Pinos",
              "Av. América", "Jr. Bolívar", "Calle Las Flores", "Av. Mansiche"]
    filas, refs = [], []

    def pid():
        cnt["p"] += 1
        return f"P{cnt['p']:03d}"

    def dev():
        cnt["d"] += 1
        return f"DEV-{cnt['d']:04d}"

    def neg():
        cnt["n"] += 1
        return f"NEG-{cnt['n']:03d}"

    def tel():
        return f"9{pool_tel.pop()}"

    def ip():
        return f"190.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"

    def mail():
        return f"{rnd.choice(nombres)}{rnd.randint(10, 99999)}@{rnd.choice(['gmail.com', 'hotmail.com', 'outlook.com'])}"

    def prov(z=None):
        z = z or rnd.choices(list(TERRITORIO), weights=[45, 25, 12, 6, 12])[0]
        return rnd.choice(TERRITORIO[z])

    def adr(pv):
        cnt["a"] += 1
        return f"{rnd.choice(calles)} {100 + cnt['a']}, {pv}"

    def fecha(h0, h1):
        return base + timedelta(hours=rnd.uniform(h0, h1))

    def alto():
        return rnd.randrange(8000, 30000, 500)

    def sol(p, d_, t, a, f, pv, et="legitimo", esc="normal", n=None, ip_=None, monto=None):
        cnt["s"] += 1
        filas.append(dict(id_solicitud=f"S{cnt['s']:04d}", id_persona=p, id_negocio=n, fecha=f,
                          monto=monto or rnd.randrange(1000, 30000, 500), dispositivo=d_, telefono=t,
                          direccion=a, ip=ip_ or ip(), correo=mail(), provincia=pv,
                          etiqueta=et, escenario=esc))

    # --- población normal
    normales = []
    for _ in range(230):
        p, pv = pid(), prov()
        normales.append(p)
        sol(p, dev(), tel(), adr(pv), fecha(0, 720), pv, n=neg() if rnd.random() < .4 else None)
    for _ in range(20):                                   # familias: solo comparten dirección
        pv, miembros = prov(), [pid() for _ in range(rnd.randint(2, 4))]
        a, n = adr(pv), (neg() if rnd.random() < .15 else None)
        for i, p in enumerate(miembros):
            sol(p, dev(), tel(), a, fecha(0, 720), pv, n=n if i < 2 else None)
        if rnd.random() < .5:
            refs += [(miembros[i], miembros[i + 1]) for i in range(len(miembros) - 1)]
    for _ in range(25):
        refs.append(tuple(rnd.sample(normales, 2)))

    # --- G: elementos usados por muchos clientes de forma sostenida (legítimos)
    cib, t_as = dev(), tel()
    for _ in range(14):                                   # cibercafé
        sol(pid(), cib, tel(), adr("Pasco"), fecha(20, 620), "Pasco", esc="G")
    for _ in range(9):                                    # asesor de créditos
        sol(pid(), dev(), t_as, adr("Arequipa"), fecha(20, 620), "Arequipa", esc="G")

    # --- A: un dispositivo, 6 personas, ~40 h, dos negocios compartidos (Lima)
    d_, n1, n2, ids = dev(), neg(), neg(), [pid() for _ in range(6)]
    for i, p in enumerate(ids):
        sol(p, d_, tel(), adr("Lima"), fecha(100, 138), "Lima", "fraude", "A", n=n1 if i < 3 else n2, monto=alto())
    sol(ids[0], cib, tel(), adr("Lima"), fecha(110, 130), "Lima", "fraude", "A", monto=alto())  # usa el cibercafé

    # --- B: un teléfono, 5 personas, referencias en cadena (Trujillo)
    t, ids = tel(), [pid() for _ in range(5)]
    for p in ids:
        sol(p, dev(), t, adr("Trujillo"), fecha(300, 340), "Trujillo", "fraude", "B", monto=alto())
    refs += [(ids[i], ids[i + 1]) for i in range(4)]

    # --- C: dos dispositivos unidos por una persona, dirección común, ráfaga (Arequipa)
    d1, d2, ids, a = dev(), dev(), [pid() for _ in range(7)], adr("Arequipa")
    for i, p in enumerate(ids):
        sol(p, d1 if i < 4 else d2, tel(), a if i < 2 else adr("Arequipa"), fecha(500, 550),
            "Arequipa", "fraude", "C", monto=alto())
    sol(ids[3], d2, tel(), adr("Arequipa"), fecha(500, 550), "Arequipa", "fraude", "C", monto=alto())
    refs += [(ids[0], ids[2]), (ids[2], ids[4]), (ids[4], ids[6]), (ids[1], ids[5])]

    # --- F: dos grupos unidos por una persona puente (Lima)
    dA, dB, gA, gB = dev(), dev(), [pid() for _ in range(6)], [pid() for _ in range(6)]
    for p in gA:
        sol(p, dA, tel(), adr("Lima"), fecha(600, 650), "Lima", "fraude", "F", monto=alto())
    for p in gB:
        sol(p, dB, tel(), adr("Lima"), fecha(660, 700), "Lima", "fraude", "F", monto=alto())
    sol(gA[0], dB, tel(), adr("Lima"), fecha(660, 700), "Lima", "fraude", "F", monto=alto())

    # --- I: misma IP y misma dirección escrita de formas distintas (Pasco)
    ip_c, calle, num = ip(), rnd.choice(calles), rnd.randint(1000, 1900)
    variantes = [f"{calle} {num}, Pasco", f"{calle.replace('Av.', 'Avenida')} {num} Pasco",
                 f"{calle.upper()} N° {num}, PASCO", f"{calle.replace('.', '')} {num}, Pasco"]
    for v in variantes:
        sol(pid(), dev(), tel(), v, fecha(650, 710), "Pasco", "fraude", "I", ip_=ip_c, monto=alto())

    # --- L: cadena de enlaces distintos: dispositivo -> teléfono -> negocio -> referencia (Huaral)
    X, Y, N, ids = dev(), tel(), neg(), [pid() for _ in range(5)]
    plan = [(X, tel(), None), (X, Y, None), (dev(), Y, N), (dev(), tel(), N), (dev(), tel(), None)]
    for i, (p, (dv, tl, ng)) in enumerate(zip(ids, plan)):
        sol(p, dv, tl, adr("Huaral"), fecha(380 + 60 * i, 386 + 60 * i), "Huaral", "fraude", "L", n=ng, monto=alto())
    refs.append((ids[3], ids[4]))

    # --- J: solo referencias, nada compartido (no se detecta)
    ids = [pid() for _ in range(3)]
    for p in ids:
        sol(p, dev(), tel(), adr("Huancayo"), fecha(100, 600), "Huancayo", "fraude", "J", monto=alto())
    refs += [(ids[0], ids[1]), (ids[1], ids[2])]

    # --- K: una IP compartida repartida en un mes (señal débil: no se detecta)
    ip_k, ids = ip(), [pid() for _ in range(4)]
    for p in ids:
        sol(p, dev(), tel(), adr("Camaná"), fecha(60, 700), "Camaná", "fraude", "K", ip_=ip_k, monto=alto())
    refs.append((ids[0], ids[1]))

    # --- E / D / H: relaciones legítimas que se parecen a un fraude
    d_ = dev()
    for _ in range(3):                                    # E: mismo dispositivo en 10 días
        sol(pid(), d_, tel(), adr("Tarma"), fecha(200, 440), "Tarma", esc="E")
    a, n, ids = adr("Ascope"), neg(), [pid() for _ in range(4)]
    for i, p in enumerate(ids):                           # D: familia
        sol(p, dev(), tel(), a, fecha(60, 300), "Ascope", esc="D", n=n if i < 2 else None)
    refs += [(ids[i], ids[i + 1]) for i in range(3)]
    t, n, ids = tel(), neg(), [pid() for _ in range(5)]
    for i, p in enumerate(ids):                           # H: negocio familiar
        sol(p, dev(), t, adr("Jauja"), fecha(250 + 60 * i, 256 + 60 * i), "Jauja", esc="H", n=n)

    # --- M: un teléfono con un dígito alterado en cada solicitud (coincidencia aproximada, Cañete)
    t0, ids = tel(), [pid() for _ in range(4)]
    for i, p in enumerate(ids):
        pos = 1 + 2 * i                                   # posición distinta en cada variante
        t_i = t0 if i == 0 else t0[:pos] + str((int(t0[pos]) + 3) % 10) + t0[pos + 1:]
        sol(p, dev(), t_i, adr("Cañete"), fecha(400, 440), "Cañete", "fraude", "M", monto=alto())

    return pd.DataFrame(filas).sort_values("fecha").reset_index(drop=True), refs


# ---------------------------------------------------------- validación e importación
def _ok(v):
    return v is not None and not (isinstance(v, float) and math.isnan(v)) and pd.notna(v) and str(v).strip() != ""


def validar(df):
    """Revisa un archivo cargado. Devuelve (dataframe limpio o None, refs, reporte)."""
    rep, df = [], df.copy()
    df.columns = [str(c).strip().lower() for c in df.columns]
    faltan = [c for c in REQUERIDAS if c not in df.columns]
    rep.append(("Columnas requeridas", "Faltan: " + ", ".join(faltan) if faltan else "Completas",
                "Error" if faltan else "OK"))
    ausentes = [c for c in OPCIONALES if c not in df.columns]
    rep.append(("Columnas opcionales", ("Ausentes: " + ", ".join(ausentes)) if ausentes else "Todas presentes",
                "Aviso" if ausentes else "OK"))
    if faltan:
        return None, [], rep
    n0 = len(df)
    dup = int(df.duplicated("id_solicitud").sum())
    df = df.drop_duplicates("id_solicitud")
    rep.append(("Solicitudes duplicadas", f"{dup} eliminadas", "Aviso" if dup else "OK"))
    df["fecha"] = pd.to_datetime(df["fecha"], errors="coerce")
    df["monto"] = pd.to_numeric(df["monto"], errors="coerce")
    malas = int((df.fecha.isna() | df.monto.isna() | (df.monto <= 0) | df.id_persona.isna()).sum())
    df = df[~(df.fecha.isna() | df.monto.isna() | (df.monto <= 0) | df.id_persona.isna())]
    rep.append(("Fechas, montos o personas inválidos", f"{malas} filas descartadas", "Aviso" if malas else "OK"))
    tel_mal = int((df.telefono.astype(str).str.replace(r"\D", "", regex=True).str.len() != 9).sum())
    rep.append(("Teléfonos que no tienen 9 dígitos", f"{tel_mal} registros", "Aviso" if tel_mal else "OK"))
    if "correo" in df:
        c_mal = int((df.correo.notna() & ~df.correo.astype(str).str.contains("@")).sum())
        rep.append(("Correos sin '@'", f"{c_mal} registros", "Aviso" if c_mal else "OK"))
    vacios = int(df[REQUERIDAS].isna().sum().sum())
    rep.append(("Datos faltantes en columnas requeridas", f"{vacios} celdas", "Aviso" if vacios else "OK"))
    rep.append(("Filas analizadas", f"{len(df)} de {n0}", "OK" if len(df) else "Error"))
    if df.empty:
        return None, [], rep
    refs = []
    if "id_referencia" in df:
        refs = [(a, b) for a, b in zip(df.id_persona, df.id_referencia) if _ok(b) and a != b]
    return df.drop(columns=["id_referencia"], errors="ignore").reset_index(drop=True), refs, rep


def normalizar(df):
    d = df.copy()
    for c in ["id_negocio", "ip", "correo", "provincia", "etiqueta", "escenario"]:
        if c not in d:
            d[c] = None
    d["fecha"] = pd.to_datetime(d["fecha"])
    d["monto"] = pd.to_numeric(d["monto"], errors="coerce").fillna(0).astype(int)

    def limpio(s):
        s = s.astype("string").str.strip()
        return s.where(~s.isin(["", "nan", "None", "<NA>"]), pd.NA)

    for c in ["id_persona", "id_solicitud", "dispositivo", "telefono", "direccion", "ip", "correo",
              "id_negocio", "provincia", "etiqueta", "escenario"]:
        d[c] = limpio(d[c])
    d["telefono"] = limpio(d.telefono.str.replace(r"\D", "", regex=True).str[-9:])
    d["telefono_orig"] = d["telefono"]                    # valor exacto, para las líneas base (SQL / reglas)
    d["telefono"] = unificar_telefonos(d["telefono"])
    d["dispositivo"] = d.dispositivo.str.upper()
    d["correo"] = d.correo.str.lower()
    d["direccion_n"] = d.direccion.map(lambda a: norm_dir(a) if _ok(a) else pd.NA).astype("string")
    d["provincia"] = d.provincia.fillna("Sin provincia")
    d["zona"] = d.provincia.map(PROV2ZONA).fillna("Sin región")
    return d


# ------------------------------------------------------------------------- grafo
def construir_grafo(d, refs):
    G = nx.Graph()

    def tocar(n, tipo, valor, f):
        if n not in G:
            G.add_node(n, tipo=tipo, valor=valor, fmin=f, fmax=f)
        else:
            a = G.nodes[n]
            a["fmin"], a["fmax"] = min(a["fmin"], f), max(a["fmax"], f)

    for r in d.itertuples(index=False):
        p = f"persona:{r.id_persona}"
        tocar(p, "persona", r.id_persona, r.fecha)
        for col, tipo in COLS_ATTR:
            v = getattr(r, col)
            if _ok(v):
                n = f"{tipo}:{v}"
                tocar(n, tipo, r.direccion if tipo == "direccion" else v, r.fecha)
                G.add_edge(p, n, rel="usa")
        if _ok(r.id_negocio):
            n = f"negocio:{r.id_negocio}"
            tocar(n, "negocio", r.id_negocio, r.fecha)
            G.add_edge(p, n, rel="declara")
    for a, b in refs:
        pa, pb = f"persona:{a}", f"persona:{b}"
        if pa in G and pb in G and pa != pb:
            G.add_edge(pa, pb, rel="ref")
    return G


def _demanda_contexto(d, zona, ids, ini, horas=72):
    """¿Cuántas veces el volumen habitual de solicitudes de OTRAS personas de la región hubo en la ventana de la ráfaga?
    Se excluye al propio caso para que una ráfaga de fraude no se descuente a sí misma. 1.0 = normal."""
    if ini is None:
        return 1.0
    otros = d[(d.zona == zona) & ~d.id_persona.isin(ids)]
    if otros.empty:
        return 1.0
    span = max((d.fecha.max() - d.fecha.min()).total_seconds() / 3600, horas)
    esperado = max(len(otros) * horas / span, 2.0)
    en_ventana = int(((otros.fecha >= ini) & (otros.fecha <= ini + pd.Timedelta(hours=horas))).sum())
    return round(en_ventana / esperado, 2)


def _rafaga(fechas, horas=72):
    f = sorted(fechas)
    mejor, ini, j = 0, None, 0
    for i in range(len(f)):
        while (f[i] - f[j]).total_seconds() / 3600 > horas:
            j += 1
        if i - j + 1 > mejor:
            mejor, ini = i - j + 1, f[j]
    return mejor, ini


def _ruta_mas_larga(H, pers, tope=25):
    pers = sorted(pers)[:tope]
    mejor, par = 0, None
    for p in pers:
        dist = nx.single_source_shortest_path_length(H, p)
        for q in pers:
            if q > p and dist.get(q, 0) > mejor:
                mejor, par = dist[q], (p, q)
    return (mejor, nx.shortest_path(H, *par)) if par else (0, [])


def ruta_txt(G, camino):
    out = []
    for i, n in enumerate(camino):
        a = G.nodes[n]
        out.append(str(a["valor"]) if a["tipo"] in ("persona", "negocio", "dispositivo")
                   else f"{ETQ_TIPO[a['tipo']]} {etiqueta_nodo(a)}")
        if i < len(camino) - 1 and a["tipo"] == "persona" and G.nodes[camino[i + 1]]["tipo"] == "persona":
            out.append("(referencia)")
    return " → ".join(out)


# ------------------------------------------------------------------------ señales
def nivel(p):
    return "Alta" if p >= ALTA else "Media" if p >= ALERTA else "Baja"


def evaluar(f, explicar=None):
    """Cada señal: qué se observó, cuántos puntos aporta y qué explicación legítima podría tener."""
    S = []
    explicar = EXPLICAR_RELACIONES if explicar is None else explicar
    f["cap_aplicado"] = False

    def add(tipo, titulo, texto, pts, alt, rel, temporal=False):
        S.append(dict(tipo=tipo, titulo=titulo, texto=texto, pts=pts, alt=alt, rel=rel, temporal=temporal))

    if f["max_dev"] >= 3:
        add("dispositivo", "Dispositivo compartido", f"Un mismo dispositivo aparece en solicitudes de {f['max_dev']} personas", 35,
            "Equipo de una familia, de un negocio o de un asesor que ayuda a varios clientes", "Alta relevancia")
    elif f["max_dev"] == 2:
        add("dispositivo", "Dispositivo compartido", "Un dispositivo aparece en solicitudes de 2 personas", 12,
            "Pareja o familiares que comparten un celular o computadora", "Revisar")
    if f["max_tel"] >= 3:
        add("telefono", "Teléfono compartido", f"Un mismo teléfono de contacto aparece en {f['max_tel']} solicitantes", 25,
            "Teléfono de un hogar o de un negocio familiar usado como contacto común", "Alta relevancia")
    elif f["max_tel"] == 2:
        add("telefono", "Teléfono compartido", "Un teléfono de contacto aparece en 2 solicitantes", 8,
            "Familiares que usan el mismo número", "Revisar")
    if f["max_ip"] >= 3:
        add("ip", "IP compartida", f"Una misma IP aparece en solicitudes de {f['max_ip']} personas", 15,
            "Red doméstica, oficina o proveedor de internet que comparte la IP", "Revisar")
    elif f["max_ip"] == 2:
        add("ip", "IP compartida", "Una IP aparece en solicitudes de 2 personas", 4,
            "Personas que viven o trabajan en el mismo lugar", "Contextualizar")
    if f["max_mail"] >= 2:
        add("correo", "Correo compartido", f"Un mismo correo aparece en {f['max_mail']} solicitantes", 20,
            "Cuenta de correo familiar o de un negocio", "Revisar")
    if f["max_neg"] >= 3:
        add("negocio", "Negocio compartido", f"Un mismo negocio es declarado por {f['max_neg']} solicitantes", 20,
            "Empleados o familiares vinculados a un negocio real", "Revisar")
    elif f["max_neg"] == 2:
        add("negocio", "Negocio compartido", "Un negocio es declarado por 2 solicitantes", 8,
            "Socios o familiares de un negocio real", "Contextualizar")
    if f["max_dir"] >= 2:
        add("direccion", "Dirección compartida", f"Dirección compartida por {f['max_dir']} personas", 5,
            "Personas que viven en la misma vivienda (muy común en familias)", "Contextualizar")
    if f["refs"] >= 3:
        add("referencia", "Referencias cruzadas", f"{f['refs']} referencias cruzadas entre los solicitantes", 10,
            "Familiares, socios o compañeros que se dan referencias con normalidad", "Revisar")
    elif f["refs"] == 2:
        add("referencia", "Referencias cruzadas", "2 referencias cruzadas entre los solicitantes", 5,
            "Familiares, socios o compañeros que se dan referencias con normalidad", "Contextualizar")
    if f["rafaga"] >= 4 and max(f["max_dev"], f["max_tel"], f["max_ip"], f["max_mail"]) >= 2:
        if MITIGAR_DEMANDA and f.get("demanda_x", 1.0) >= DEMANDA_X:
            add("temporal", "Solicitudes próximas en el tiempo (con aumento de demanda en la región)",
                f"{f['rafaga']} solicitudes vinculadas en menos de 72 horas, pero otras personas de la región también "
                f"solicitaron {f['demanda_x']:.1f} veces lo habitual en esas horas", 5,
                "Campaña, feria o evento (por ejemplo, medidas de apoyo tras el Fenómeno El Niño): un asesor o agencia puede "
                "tramitar muchas solicitudes seguidas", "Contextualizar", temporal=True)
        else:
            add("temporal", "Solicitudes próximas en el tiempo", f"{f['rafaga']} solicitudes vinculadas en menos de 72 horas", 20,
                "Campaña de créditos o evento que genera varias solicitudes a la vez", "Revisar", temporal=True)
    if f["puentes"] > 0:
        add("puente", "Persona puente", (f"{f['puentes']} personas conectan grupos" if f["puentes"] > 1 else "Una persona conecta grupos") + " que no se relacionan de otra forma", 10,
            "Un asesor o un familiar que participa legítimamente en dos grupos", "Revisar")
    if f["saltos"] >= 3:
        add("indirecta", "Conexión indirecta", f"Hay personas conectadas solo a través de {f['saltos']} saltos", 10,
            "Vecindad, trabajo o parentesco extendido", "Revisar")
    if explicar and f.get("explicado"):
        # Si todas las personas comparten domicilio o negocio, el teléfono, el correo, la dirección y las referencias en común
        # son parte de la misma explicación (hogar o negocio). Se cuentan una sola vez, con un tope por debajo de la alerta.
        ex = [x for x in S if x["tipo"] in EXPLICABLES]
        tot = sum(x["pts"] for x in ex)
        if tot > CAP_EXPLICADO:
            f["cap_aplicado"] = True
            k = CAP_EXPLICADO / tot
            for x in ex:
                x["pts"] = int(x["pts"] * k)
                x["texto"] += f" (todas las personas comparten {f['explicado']}: se cuenta como una sola relación)"
    return S


def _lista(xs):
    return xs[0] if len(xs) == 1 else ", ".join(xs[:-1]) + " y " + xs[-1]


def _redactar(r):
    tipos = {s["tipo"] for s in r["senales"] if s["tipo"] != "ia"}
    comp = [n for t, n in (("dispositivo", "dispositivos"), ("telefono", "teléfonos"), ("ip", "IP"),
                           ("correo", "correos"), ("negocio", "negocios")) if t in tipos]
    extra = [n for t, n in (("referencia", "referencias cruzadas"), ("temporal", "una concentración de solicitudes en pocas horas"),
                            ("puente", "una persona puente"), ("indirecta", "conexiones indirectas")) if t in tipos]
    if comp:
        txt = f"Se detectaron relaciones entre varias solicitudes mediante {_lista(comp)} en común"
        txt += f", junto con {_lista(extra)}." if extra else "."
    elif extra:
        txt = f"Se detectaron indicios de relación entre solicitudes: {_lista(extra)}."
    elif "direccion" in tipos:
        txt = "Se detectó una relación entre solicitudes solo por una dirección compartida."
    else:
        return "No se detectaron señales relevantes en este grupo."
    if "direccion" in tipos:
        txt += " La dirección común podría corresponder a un domicilio familiar o comercial."
    if r.get("cap_aplicado"):
        txt += f" Todas las personas comparten {r['explicado']}, lo que explica varias coincidencias; se contaron como una sola relación."
    return txt + " Se recomienda verificar la relación antes de tomar una decisión."


# ------------------------------------------------------------------- casos y modelo
def _formar_casos(G, d, explicar=None):
    sup = {n for n, a in G.nodes(data=True) if a["tipo"] in TIPOS_ATTR and G.degree(n) >= SUPER_N
           and (a["fmax"] - a["fmin"]).total_seconds() / 3600 >= SUPER_H}
    for n in sup:
        G.nodes[n]["super"] = True
    core = G.subgraph([n for n in G if n not in sup])
    filas, redes, k = [], 0, 0
    for comp in nx.connected_components(core):
        pers = [n for n in comp if G.nodes[n]["tipo"] == "persona"]
        if len(pers) < 2:
            continue
        redes += 1
        P = nx.Graph()                      # personas conectadas si comparten algo o se refieren
        P.add_nodes_from(pers)
        for n in comp:
            if G.nodes[n]["tipo"] != "persona":
                for a, b in itertools.combinations(core.neighbors(n), 2):
                    P.add_edge(a, b, weight=P.get_edge_data(a, b, {}).get("weight", 0) + 1)
        for a, b, dd in core.subgraph(comp).edges(data=True):
            if dd["rel"] == "ref":
                P.add_edge(a, b, weight=P.get_edge_data(a, b, {}).get("weight", 0) + 1)
        comms = [set(c) for c in nx.community.louvain_communities(P, weight="weight", seed=0)]
        cid = {p: i for i, c in enumerate(comms, k) for p in c}
        k += len(comms)
        brid = {}
        for p in nx.articulation_points(P):
            otros = [q for q in P[p] if cid[q] != cid[p]]
            if otros:
                brid[p] = otros
        partes = [c for c in comms if len(c) >= 2] if len(pers) >= 10 else [set(pers)]
        for c in partes:
            ids = [G.nodes[p]["valor"] for p in c]
            sub = d[d.id_persona.isin(ids)]
            nod = set(c)
            for p in c:
                nod |= {x for x in G.neighbors(p) if G.nodes[x]["tipo"] != "persona"}
            core_n = [n for n in nod if n not in sup]
            ctx = [n for n in nod if n in sup]
            H = G.subgraph(core_n)

            def pe(n):
                return sum(1 for x in G.neighbors(n) if x in c)

            def mx(t):
                return max([pe(n) for n in core_n if G.nodes[n]["tipo"] == t] or [0])

            raf, raf_ini = _rafaga(sub.fecha)
            zona_c = PROV2ZONA.get(sub.provincia.mode().iloc[0], "Sin región")
            saltos, camino = _ruta_mas_larga(H, c)
            mb = [p for p in c if p in brid]
            f = dict(personas=len(c), negocios=sum(1 for n in core_n if G.nodes[n]["tipo"] == "negocio"),
                     solicitudes=len(sub), max_dev=mx("dispositivo"), max_tel=mx("telefono"), max_dir=mx("direccion"),
                     max_ip=mx("ip"), max_mail=mx("correo"), max_neg=mx("negocio"),
                     refs=sum(1 for _, _, dd in H.edges(data=True) if dd["rel"] == "ref"),
                     ventana_h=(sub.fecha.max() - sub.fecha.min()).total_seconds() / 3600, rafaga=raf,
                     densidad=round(nx.density(H), 3), grado_max=max(dg for _, dg in H.degree()),
                     puentes=len(mb), saltos=saltos, exposicion=int(sub.monto.sum()),
                     demanda_x=_demanda_contexto(d, zona_c, ids, raf_ini))
            n_p = len(c)
            f["explicado"] = ("un mismo domicilio" if 2 <= n_p <= 4 and f["max_dir"] == n_p else
                              "un mismo negocio" if 2 <= n_p <= 5 and f["max_neg"] == n_p else "")
            f["senales"] = evaluar(f, explicar)
            f["ids"], f["nodos"], f["n_ctx"] = ids, core_n + ctx, len(ctx)
            f["origen"] = "Subgrupo (comunidad)" if len(pers) >= 10 else "Red conectada"
            f["comunidades"] = len(comms)
            f["brid"] = {G.nodes[p]["valor"]: [G.nodes[q]["valor"] for q in brid[p]] for p in mb}
            f["ruta"], f["ruta_txt"] = camino, ruta_txt(G, camino)
            f["f_ini"], f["f_fin"], f["rafaga_ini"] = sub.fecha.min(), sub.fecha.max(), raf_ini
            f["provincia"] = sub.provincia.mode().iloc[0]
            f["zona"] = PROV2ZONA.get(f["provincia"], "Sin región")
            f["tipos"] = [t for t, v in (("Dispositivo", f["max_dev"]), ("Teléfono", f["max_tel"]), ("IP", f["max_ip"]),
                                        ("Correo", f["max_mail"]), ("Negocio", f["max_neg"]), ("Dirección", f["max_dir"]),
                                        ("Referencia", f["refs"] and 2)) if v >= 2]
            filas.append(f)
    return pd.DataFrame(filas), redes, sup


def _pts(senales, temporal=True):
    return sum(s["pts"] for s in senales if s["tipo"] != "ia" and (temporal or not s["temporal"]))


def _sin_dato(a):
    return not (_ok(a) and str(a).strip())


def analizar(sols, refs=(), explicar=None):
    """Flujo completo. Devuelve un diccionario con todo lo que usa la interfaz.
    explicar: True/False fuerza la regla de relaciones explicables; None usa EXPLICAR_RELACIONES."""
    refs = list(refs)
    d = normalizar(sols)
    G = construir_grafo(d, refs)
    full, redes, sup = _formar_casos(G, d, explicar)
    if full.empty:
        raise ValueError("No se encontraron redes de al menos 2 personas con los datos cargados.")
    full["base"] = full.senales.map(_pts)
    full["base_nt"] = full.senales.map(lambda s: _pts(s, temporal=False))

    # Isolation Forest: señal exploratoria (aporta pocos puntos y no está validada)
    full["atipico"], full["ia"] = False, 0
    if len(full) >= 8:
        X = full[FEATURES_IA].astype(float)
        m = IsolationForest(n_estimators=200, contamination="auto", random_state=0).fit(X)
        raw = -m.score_samples(X)
        full["atipico"] = m.predict(X) == -1
        full["ia"] = (((raw - raw.min()) / (raw.max() - raw.min() + 1e-9)) * 10).round().astype(int)
    for i in full.index:
        if full.at[i, "base"] > 0 and full.at[i, "ia"] >= 3:
            full.at[i, "senales"] = full.at[i, "senales"] + [dict(
                tipo="ia", titulo="Estructura poco habitual", pts=int(full.at[i, "ia"]), rel="Contextualizar", temporal=False,
                texto="La forma de esta red se parece poco a la del resto (Isolation Forest, exploratorio, sin validar)",
                alt="Ser poco habitual no implica irregularidad: solo indica que conviene mirarlo")]
    ia = full.ia.where(full.base > 0, 0).where(full.ia >= 3, 0)
    full["prioridad"] = (full.base + ia).clip(upper=100).astype(int)
    full["prioridad_nt"] = (full.base_nt + ia).clip(upper=100).astype(int)

    df = full[full.base > 0].copy()
    if df.empty:
        raise ValueError("Las redes encontradas no presentan señales para revisar.")
    df["nivel"] = df.prioridad.map(nivel)
    df["indice"] = (0.75 * df.prioridad + 25 * df.exposicion / max(df.exposicion.max(), 1)).round(1)
    df = df.sort_values("indice", ascending=False).reset_index(drop=True)
    df["id"] = [f"RS-{i + 1:03d}" for i in range(len(df))]
    df["n_senales"] = df.senales.map(lambda s: sum(1 for x in s if x["tipo"] != "ia"))
    df["explicacion"] = df.apply(_redactar, axis=1)
    df["esfuerzo_h"] = (0.5 + 0.15 * df.personas + 0.1 * df.negocios).round(2)

    persona_caso = {p: r.id for r in df.itertuples() for p in r.ids}
    for i, r in df.iterrows():          # a qué casos conecta cada persona puente
        df.at[i, "brid"] = {p: sorted({persona_caso[q] for q in qs if q in persona_caso} - {r["id"]})
                            for p, qs in r["brid"].items()}
    nodo_casos = {}
    for r in df.itertuples():
        for n in r.nodos:
            nodo_casos.setdefault(n, set()).add(r.id)

    ent = []
    for n, a in G.nodes(data=True):
        if a["tipo"] == "persona" or G.degree(n) < 2:
            continue
        cids = [persona_caso[G.nodes[x]["valor"]] for x in G.neighbors(n) if G.nodes[x]["valor"] in persona_caso]
        ent.append({"Tipo": ETQ_TIPO[a["tipo"]], "Elemento": etiqueta_nodo(a), "Personas": G.degree(n),
                    "Horas entre solicitudes": round((a["fmax"] - a["fmin"]).total_seconds() / 3600),
                    "Supernodo": "Sí" if n in sup else "No",
                    "Caso": max(set(cids), key=cids.count) if cids else "—"})
    ent = pd.DataFrame(ent)

    per = []
    for r in df.itertuples():
        H = G.subgraph([n for n in r.nodos if n not in sup])
        cent = nx.betweenness_centrality(H)
        enlaces = set(nx.articulation_points(H))
        for n in H.nodes:
            if G.nodes[n]["tipo"] != "persona":
                continue
            comp_ = [x for x in H.neighbors(n) if G.nodes[x]["tipo"] != "persona" and H.degree(x) >= 2]
            directas = {x for x in H.neighbors(n) if G.nodes[x]["tipo"] == "persona"}
            for x in comp_:
                directas |= {y for y in H.neighbors(x) if G.nodes[y]["tipo"] == "persona"}
            directas.discard(n)
            per.append({"Persona": G.nodes[n]["valor"], "Caso": r.id, "Elementos compartidos": len(comp_),
                        "Conexiones directas": len(directas), "Conexiones indirectas": r.personas - 1 - len(directas),
                        "Nodo de enlace": "Sí" if n in enlaces else "No", "Centralidad (%)": round(cent[n] * 100)})
    per = pd.DataFrame(per)

    return dict(d=d, G=G, df=df, persona_caso=persona_caso, nodo_casos=nodo_casos, ent=ent, per=per,
                redes=redes, sup=sup, refs=refs, ev=evaluar_modelo(d, df, persona_caso),
                serie=serie_temporal(d, df, persona_caso, refs, sup))


# --------------------------------------------------------------------- evaluación
def _comparten(d, cols, minimo):
    out = set()
    for c in cols:
        for _, s in d.dropna(subset=[c]).groupby(c).id_persona:
            if s.nunique() >= minimo:
                out |= set(s)
    return out


def evaluar_modelo(d, df, persona_caso):
    """Precisión/recall por persona contra etiquetas conocidas. None si no hay etiquetas."""
    if d.etiqueta.isna().all():
        return None
    ver = set(d.loc[d.etiqueta.str.lower().str.startswith("fraude").fillna(False).astype(bool), "id_persona"])
    todos = set(d.id_persona)
    if not ver or ver == todos:
        return None

    def desde(col):
        casos = set(df.loc[df[col] >= ALERTA, "id"])
        return {p for p, c in persona_caso.items() if c in casos}

    variantes = {
        "Consulta SQL (dispositivo o teléfono compartido)": _comparten(d, ["dispositivo", "telefono_orig"], 2),
        "Reglas por umbral (3+ personas por elemento)": _comparten(d, ["dispositivo", "telefono_orig", "ip", "correo"], 3),
        "RedShield sin señales temporales": desde("prioridad_nt"),
        "RedShield completo": desde("prioridad"),
    }
    filas, detalle = [], {}
    for nombre, al in variantes.items():
        tp, fp, fn = len(al & ver), len(al - ver), len(ver - al)
        pre, rec = tp / (tp + fp) if tp + fp else 0, tp / (tp + fn) if tp + fn else 0
        filas.append({"Método": nombre, "Alertas": len(al), "Verdaderos positivos": tp, "Falsos positivos": fp,
                      "Falsos negativos": fn, "Precisión (%)": round(pre * 100), "Recall (%)": round(rec * 100),
                      "F1 (%)": round(200 * pre * rec / (pre + rec)) if pre + rec else 0})
        detalle[nombre] = dict(tp=tp, fp=fp, fn=fn, tn=len(todos) - tp - fp - fn)
    ev = dict(tabla=pd.DataFrame(filas), conf=detalle["RedShield completo"], personas=len(todos),
              fraudes=len(ver), fallos=None)
    if d.escenario.notna().any():
        esc = d.drop_duplicates("id_persona").set_index("id_persona").escenario
        al = variantes["RedShield completo"]
        fallos = [(esc.get(p), "Falso negativo") for p in ver - al] + [(esc.get(p), "Falso positivo") for p in al - ver]
        if fallos:
            t = pd.DataFrame(fallos, columns=["Escenario", "Tipo"]).value_counts().reset_index(name="Personas")
            t["Qué era"] = t.Escenario.map(ESCENARIOS)
            ev["fallos"] = t
    return ev


def comunidades_caso(G, nodos):
    """Comunidades (Louvain) dentro de un caso, para colorear a las personas. {nodo_persona: n}"""
    pers = {n for n in nodos if G.nodes[n]["tipo"] == "persona"}
    P = nx.Graph()
    P.add_nodes_from(pers)
    for n in nodos:
        if G.nodes[n]["tipo"] != "persona" and not G.nodes[n].get("super"):
            for a, b in itertools.combinations([x for x in G.neighbors(n) if x in pers], 2):
                P.add_edge(a, b, weight=P.get_edge_data(a, b, {}).get("weight", 0) + 1)
    for a, b, dd in G.subgraph(pers).edges(data=True):
        if dd["rel"] == "ref":
            P.add_edge(a, b, weight=P.get_edge_data(a, b, {}).get("weight", 0) + 1)
    comms = nx.community.louvain_communities(P, weight="weight", seed=0)
    return {p: i for i, c in enumerate(sorted(comms, key=lambda c: (-len(c), sorted(c)[0]))) for p in c}


# ------------------------------------------------------------------ serie temporal
def serie_temporal(d, df, persona_caso, refs, sup):
    d = d.copy()
    d["dia"] = d.fecha.dt.normalize()
    d["caso"] = d.id_persona.map(persona_caso)
    d["nivel"] = d.caso.map(df.set_index("id").nivel)
    dias = pd.date_range(d.dia.min(), d.dia.max())
    out = pd.DataFrame(index=dias)
    out["solicitudes"] = d.groupby("dia").size()
    for n in ("Alta", "Media", "Baja"):
        out[f"vinculadas_{n}"] = d[d.nivel == n].groupby("dia").size()
    ev = []
    for col, tipo in COLS_ATTR + [("id_negocio", "negocio")]:
        x = d.dropna(subset=[col]).sort_values("fecha").drop_duplicates(["id_persona", col])
        for v, g in x.groupby(col):
            if len(g) >= 2 and f"{tipo}:{v}" not in sup:
                ev += list(g.dia.iloc[1:])
    primero = d.groupby("id_persona").fecha.min()
    for a, b in refs:
        if a in primero.index and b in primero.index:
            ev.append(max(primero[a], primero[b]).normalize())
    out["nuevas_conexiones"] = pd.Series(ev, dtype="datetime64[ns]").value_counts() if ev else 0
    ent = d[d.caso.notna()].groupby("id_persona").dia.min().value_counts()
    out["entidades_conectadas"] = ent.reindex(dias, fill_value=0).cumsum()
    out = out.fillna(0).astype(int)
    out.index.name = "dia"
    return out.reset_index()


# ----------------------------------------------------- calibración con el analista
ESTADOS_DEC = ("Relación legítima", "En investigación", "Requiere escalamiento")


def calibrar_pesos(df, decisiones, minimo=MIN_CALIB):
    """Ajuste simple y transparente (no es un modelo entrenado): si los analistas descartan con
    frecuencia los casos que tienen cierta señal, esa señal pesa menos; si los escalan, pesa algo más.
    decisiones = {id_caso: estado}. Devuelve {tipo_señal: {n, legitimas, escaladas, mult, aplica}}."""
    acum = {}
    for r in df.itertuples():
        est = decisiones.get(r.id)
        if est not in ESTADOS_DEC:
            continue
        for t in {s["tipo"] for s in r.senales if s["tipo"] != "ia" and s["pts"] > 0}:
            a = acum.setdefault(t, [0, 0, 0])
            a[0] += 1
            a[1] += est == "Relación legítima"
            a[2] += est == "Requiere escalamiento"
    out = {}
    for t, (n, l, e) in acum.items():
        m = round(min(1.2, max(0.5, 1 - 0.5 * l / n + 0.2 * e / n)), 2)
        out[t] = dict(n=n, legitimas=int(l), escaladas=int(e), mult=m if n >= minimo else 1.0, aplica=n >= minimo)
    return out


def aplicar_pesos(df, pesos):
    """Recalcula la prioridad de cada caso con los multiplicadores por tipo de señal."""
    def f(r):
        base = sum(s["pts"] * pesos.get(s["tipo"], {}).get("mult", 1.0) for s in r["senales"] if s["tipo"] != "ia")
        ia = sum(s["pts"] for s in r["senales"] if s["tipo"] == "ia")
        return int(min(100, round(base + ia)))
    return df.apply(f, axis=1)


# --------------------------------------------------------------- plan de revisión
def plan_revision(items, horas):
    """Mochila 0/1: qué casos conviene revisar con las horas disponibles.
    items = [(id, valor, esfuerzo_horas)]. Devuelve el conjunto de ids elegidos."""
    W = int(horas * 4)
    w = [max(1, math.ceil(e * 4)) for _, _, e in items]
    best = [[0] * (W + 1) for _ in range(len(items) + 1)]
    for i, (_, v, _) in enumerate(items, 1):
        for c in range(W + 1):
            best[i][c] = best[i - 1][c]
            if w[i - 1] <= c:
                best[i][c] = max(best[i][c], best[i - 1][c - w[i - 1]] + v)
    c, elegidos = W, set()
    for i in range(len(items), 0, -1):
        if best[i][c] != best[i - 1][c]:
            elegidos.add(items[i - 1][0])
            c -= w[i - 1]
    return elegidos


PLANTILLA = pd.DataFrame([
    dict(id_solicitud="S0001", id_persona="P001", fecha="2026-11-01 09:30", monto=5000, dispositivo="DEV-0001",
         telefono="987654321", direccion="Av. Larco 101, Trujillo", ip="190.10.20.30", correo="ana@gmail.com",
         id_negocio="NEG-001", provincia="Trujillo", id_referencia="P002", etiqueta=""),
    dict(id_solicitud="S0002", id_persona="P002", fecha="2026-11-01 10:15", monto=8000, dispositivo="DEV-0001",
         telefono="987654322", direccion="Jr. Pizarro 55, Trujillo", ip="190.10.20.31", correo="luis@gmail.com",
         id_negocio="", provincia="Trujillo", id_referencia="", etiqueta="")])
