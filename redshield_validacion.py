"""
RedShield · validación robusta (sin interfaz).

Por qué existe este módulo
--------------------------
El generador original (`redshield_core.generar_datos`) crea UNA instancia de cada patrón y las reglas de
puntaje se diseñaron mirando esos mismos patrones, así que medir ahí es medir contra el examen que ya se
conocía. Este módulo hace lo contrario:

* genera MUCHAS instancias aleatorias (tamaños, fechas y ruido distintos) con semillas distintas;
* incluye legítimos difíciles (familias que comparten teléfono o dispositivo, socios, cibercafés,
  campañas de demanda tipo FEN) y fraudes que intentan pasar desapercibidos (enlaces de a pares,
  repartidos en semanas, apoyados en un cibercafé);
* NO se usó para ajustar umbrales: las reglas de `redshield_core` se escribieron antes;
* reporta promedio y desviación entre semillas, y también por patrón (no solo por persona).

Todos los datos siguen siendo SINTÉTICOS: esto mide robustez del flujo, no desempeño real.
"""
import random
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

import redshield_core as rc

N_SEMILLAS = 12
SEMILLA_INICIO = 100      # semillas 0-11 se usaron para explorar y diseñar reglas; la validación usa otras
PATRONES_FRAUDE = {
    "RA": "Dispositivo compartido por un grupo (3 a 7 personas) en pocos días",
    "RB": "Teléfono compartido por un grupo con referencias en cadena",
    "RC": "Dos dispositivos unidos por una persona puente",
    "RM": "Teléfono con un dígito alterado en cada solicitud",
    "RI": "Misma IP y dirección escrita de formas distintas",
    "RL": "Cadena donde cada par comparte algo distinto",
    "X1": "Evasión: enlaces de a pares (un dispositivo por pareja) repartidos en 3 semanas",
    "X2": "Evasión: solo direcciones parecidas y referencias, sin dispositivo ni teléfono común",
    "X3": "Evasión: apoyado en un cibercafé (supernodo) más una IP en común",
    "X4": "Evasión: domicilio falso compartido por 3 o 4 personas, con teléfono común",
    "X5": "Evasión: negocio ficticio declarado por 3 a 5 personas, con teléfono común",
}
PATRONES_LEGITIMOS = {
    "LF": "Familia que comparte dirección y un teléfono de contacto",
    "LP": "Pareja que comparte dispositivo",
    "LS": "Socios de un negocio con teléfono común",
    "LC": "Cibercafé o asesor con muchos clientes (supernodo)",
    "LE": "Campaña o evento de demanda (tipo FEN): muchas solicitudes legítimas en pocos días, con familias dentro",
    "LA": "Asesor o agencia que tramita 8 a 12 solicitudes de productores durante la campaña (mismo dispositivo y teléfono)",
}
NOMBRE = {**PATRONES_FRAUDE, **PATRONES_LEGITIMOS}


def generar_adversarial(seed=0, fen=True):
    """Devuelve (solicitudes, referencias). Columnas extra: `etiqueta`, `escenario` y `instancia`."""
    rnd = random.Random(10_000 + seed)
    base = datetime(2026, 10, 27, 8, 0)
    cnt = dict(p=0, d=0, a=0, s=0, n=0)
    tels = iter(rnd.sample(range(10_000_000, 99_999_999), 4000))
    calles = ["Av. Larco", "Jr. Pizarro", "Av. España", "Calle Los Pinos", "Av. América", "Jr. Bolívar",
              "Calle Las Flores", "Av. Mansiche", "Jr. Ayacucho", "Av. Grau"]
    nombres = ["ana", "luis", "rosa", "jose", "maria", "carlos", "lucia", "pedro", "elena", "jorge"]
    filas, refs = [], []

    def pid():
        cnt["p"] += 1
        return f"P{cnt['p']:04d}"

    def dev():
        cnt["d"] += 1
        return f"DEV-{cnt['d']:05d}"

    def neg():
        cnt["n"] += 1
        return f"NEG-{cnt['n']:04d}"

    def tel():
        return f"9{next(tels)}"

    def ip():
        return f"190.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"

    def mail():
        return f"{rnd.choice(nombres)}{rnd.randint(10, 99999)}@{rnd.choice(['gmail.com', 'hotmail.com', 'outlook.com'])}"

    def prov(z=None):
        z = z or rnd.choices(list(rc.TERRITORIO), weights=[40, 25, 12, 8, 15])[0]
        return rnd.choice(rc.TERRITORIO[z])

    def adr(pv):
        cnt["a"] += 1
        return f"{rnd.choice(calles)} {100 + cnt['a']}, {pv}"

    def fecha(h0, h1):
        return base + timedelta(hours=rnd.uniform(h0, h1))

    def monto(riesgo):
        # los montos de fraude y legítimos se solapan a propósito: el monto no delata la etiqueta
        return rnd.randrange(3000, 30000, 500) if riesgo else rnd.randrange(1000, 30000, 500)

    def sol(inst, esc, et, p, d_, t, a, f, pv, n=None, ip_=None):
        cnt["s"] += 1
        filas.append(dict(id_solicitud=f"S{cnt['s']:05d}", id_persona=p, id_negocio=n, fecha=f,
                          monto=monto(et == "fraude"), dispositivo=d_, telefono=t, direccion=a, ip=ip_ or ip(),
                          correo=mail(), provincia=pv, etiqueta=et, escenario=esc, instancia=inst))

    # --- población normal: hogares y negocios que no se parecen a ningún patrón
    for _ in range(260):
        pv = prov()
        sol("N", "normal", "legitimo", pid(), dev(), tel(), adr(pv), fecha(0, 720), pv, n=neg() if rnd.random() < .35 else None)
    for _ in range(25):                                   # referencias al azar entre personas normales
        a, b = rnd.sample([f["id_persona"] for f in filas if f["escenario"] == "normal"], 2)
        refs.append((a, b))

    # --- legítimos difíciles (varias instancias, tamaños variables)
    for k in range(rnd.randint(8, 12)):                   # LF: familia, misma dirección y a veces teléfono común
        pv, m = prov(), rnd.randint(2, 4)
        a, t_comun = adr(pv), tel()
        usa_tel = rnd.random() < .7
        ini = rnd.uniform(0, 650)
        ids = [pid() for _ in range(m)]
        for p in ids:
            sol(f"LF{k}", "LF", "legitimo", p, dev(), t_comun if usa_tel else tel(), a, fecha(ini, ini + rnd.choice([40, 200])), pv)
        refs += [(ids[i], ids[i + 1]) for i in range(m - 1)]
    for k in range(rnd.randint(5, 8)):                    # LP: pareja con dispositivo común
        pv, d_, ini = prov(), dev(), rnd.uniform(0, 650)
        for _ in range(2):
            sol(f"LP{k}", "LP", "legitimo", pid(), d_, tel(), adr(pv), fecha(ini, ini + rnd.choice([20, 150])), pv)
    for k in range(rnd.randint(3, 5)):                    # LS: socios, negocio y teléfono comunes
        pv, t_c, n_c, ini = prov(), tel(), neg(), rnd.uniform(0, 600)
        for _ in range(rnd.randint(3, 4)):
            sol(f"LS{k}", "LS", "legitimo", pid(), dev(), t_c, adr(pv), fecha(ini, ini + 90), pv, n=n_c)
    for k in range(rnd.randint(1, 2)):                    # LC: supernodos legítimos
        pv, d_c = prov(), dev()
        for _ in range(rnd.randint(10, 15)):
            sol(f"LC{k}", "LC", "legitimo", pid(), d_c, tel(), adr(pv), fecha(10, 650), pv)
    cibercafe = dev()                                     # un cibercafé que también usarán fraudes X3
    pv_cc = prov("Pasco")
    for _ in range(11):
        sol("LC9", "LC", "legitimo", pid(), cibercafe, tel(), adr(pv_cc), fecha(10, 650), pv_cc)

    if fen:                                               # LE: campaña de demanda en una región (tipo FEN)
        zona = rnd.choice(["La Libertad", "Lima", "Arequipa"])
        dia0 = rnd.uniform(200, 560)
        for k in range(rnd.randint(40, 55)):
            pv = rnd.choice(rc.TERRITORIO[zona])
            f = base + timedelta(hours=dia0 + rnd.uniform(0, 70))
            if rnd.random() < .22:                        # grupo familiar dentro de la campaña (comparte teléfono)
                t_c, a, m = tel(), adr(pv), rnd.randint(2, 3)
                for _ in range(m):
                    sol(f"LE{k}", "LE", "legitimo", pid(), dev(), t_c, a, f + timedelta(hours=rnd.uniform(0, 6)), pv)
            else:
                sol(f"LE{k}", "LE", "legitimo", pid(), dev(), tel(), adr(pv), f, pv)
        pv_a, d_a, t_a = rnd.choice(rc.TERRITORIO[zona]), dev(), tel()          # LA: el asesor de la campaña
        for _ in range(rnd.randint(8, 12)):
            sol("LA0", "LA", "legitimo", pid(), d_a, t_a, adr(pv_a), base + timedelta(hours=dia0 + rnd.uniform(0, 60)), pv_a)

    # --- fraudes (2 o 3 instancias por patrón, con tamaño y fechas aleatorios)
    def reps():
        return rnd.randint(2, 3)

    for k in range(reps()):                               # RA
        pv, d_, n_c = prov(), dev(), neg()
        ids, ini = [pid() for _ in range(rnd.randint(3, 7))], rnd.uniform(50, 620)
        for i, p in enumerate(ids):
            sol(f"RA{k}", "RA", "fraude", p, d_, tel(), adr(pv), fecha(ini, ini + rnd.choice([30, 60])), pv, n=n_c if i % 2 == 0 else None)
    for k in range(reps()):                               # RB
        pv, t_c, ids, ini = prov(), tel(), [pid() for _ in range(rnd.randint(3, 6))], rnd.uniform(50, 620)
        for p in ids:
            sol(f"RB{k}", "RB", "fraude", p, dev(), t_c, adr(pv), fecha(ini, ini + 50), pv)
        refs += [(ids[i], ids[i + 1]) for i in range(len(ids) - 1)]
    for k in range(reps()):                               # RC
        pv, d1, d2, ini = prov(), dev(), dev(), rnd.uniform(50, 600)
        g1, g2 = [pid() for _ in range(rnd.randint(2, 4))], [pid() for _ in range(rnd.randint(2, 4))]
        for p in g1:
            sol(f"RC{k}", "RC", "fraude", p, d1, tel(), adr(pv), fecha(ini, ini + 50), pv)
        for p in g2:
            sol(f"RC{k}", "RC", "fraude", p, d2, tel(), adr(pv), fecha(ini, ini + 50), pv)
        sol(f"RC{k}", "RC", "fraude", g1[0], d2, tel(), adr(pv), fecha(ini, ini + 50), pv)
    for k in range(reps()):                               # RM
        pv, t0, ini = prov(), tel(), rnd.uniform(50, 600)
        for i, p in enumerate([pid() for _ in range(rnd.randint(3, 4))]):
            pos = 1 + 2 * i
            t_i = t0 if i == 0 else t0[:pos] + str((int(t0[pos]) + rnd.randint(1, 8)) % 10) + t0[pos + 1:]
            sol(f"RM{k}", "RM", "fraude", p, dev(), t_i, adr(pv), fecha(ini, ini + 70), pv)
    for k in range(reps()):                               # RI
        pv, ip_c, calle, num, ini = prov(), ip(), rnd.choice(calles), rnd.randint(1000, 1900), rnd.uniform(50, 600)
        vari = [f"{calle} {num}, {pv}", f"{calle.replace('Av.', 'Avenida')} {num} {pv}",
                f"{calle.upper()} N° {num}, {pv.upper()}", f"{calle.replace('.', '')} {num}, {pv}"]
        for v in vari[:rnd.randint(3, 4)]:
            sol(f"RI{k}", "RI", "fraude", pid(), dev(), tel(), v, fecha(ini, ini + 60), pv, ip_=ip_c)
    for k in range(reps()):                               # RL
        pv, X, Y, N, ini = prov(), dev(), tel(), neg(), rnd.uniform(50, 500)
        plan = [(X, tel(), None), (X, Y, None), (dev(), Y, N), (dev(), tel(), N), (dev(), tel(), None)]
        ids = [pid() for _ in plan]
        for i, (p, (dv, tl, ng)) in enumerate(zip(ids, plan)):
            sol(f"RL{k}", "RL", "fraude", p, dv, tl, adr(pv), fecha(ini + 50 * i, ini + 50 * i + 8), pv, n=ng)
        refs.append((ids[3], ids[4]))
    for k in range(reps()):                               # X1: pares encadenados, 3 semanas
        pv, n_par = prov(), rnd.randint(3, 4)
        ids, ds = [pid() for _ in range(2 * n_par)], [dev() for _ in range(n_par)]
        ini = rnd.uniform(0, 300)
        for i, p in enumerate(ids):
            sol(f"X1{k}", "X1", "fraude", p, ds[i // 2], tel(), adr(pv), fecha(ini + 120 * (i // 2), ini + 120 * (i // 2) + 20), pv)
        refs += [(ids[2 * j + 1], ids[2 * j + 2]) for j in range(n_par - 1)]
    for k in range(reps()):                               # X2: solo direcciones parecidas y referencias
        pv, ini = prov(), rnd.uniform(50, 600)
        ids = [pid() for _ in range(rnd.randint(3, 5))]
        for p in ids:
            sol(f"X2{k}", "X2", "fraude", p, dev(), tel(), adr(pv), fecha(ini, ini + 200), pv)
        refs += [(ids[i], ids[i + 1]) for i in range(len(ids) - 1)]
    for k in range(reps()):                               # X3: cibercafé + IP en común
        ip_c, ini = ip(), rnd.uniform(50, 600)
        for p in [pid() for _ in range(rnd.randint(3, 4))]:
            sol(f"X3{k}", "X3", "fraude", p, cibercafe, tel(), adr(pv_cc), fecha(ini, ini + 100), pv_cc, ip_=ip_c)

    for k in range(reps()):                               # X4: domicilio falso + teléfono común
        pv, a, t_c, ini = prov(), None, tel(), rnd.uniform(50, 600)
        a = adr(pv)
        ids = [pid() for _ in range(rnd.randint(3, 4))]
        for p in ids:
            sol(f"X4{k}", "X4", "fraude", p, dev(), t_c, a, fecha(ini, ini + 150), pv)
        refs += [(ids[i], ids[i + 1]) for i in range(len(ids) - 1)]
    for k in range(reps()):                               # X5: negocio ficticio + teléfono común
        pv, n_c, t_c, ini = prov(), neg(), tel(), rnd.uniform(50, 600)
        for p in [pid() for _ in range(rnd.randint(3, 5))]:
            sol(f"X5{k}", "X5", "fraude", p, dev(), t_c, adr(pv), fecha(ini, ini + 150), pv, n=n_c)

    df = pd.DataFrame(filas).sort_values("fecha").reset_index(drop=True)
    return df, [tuple(r) for r in refs]


# ------------------------------------------------------------------------ evaluación
def _alertados(df, minimo=None):
    minimo = rc.ALERTA if minimo is None else minimo
    return {p for r in df.itertuples() if r.prioridad >= minimo for p in r.ids}


def evaluar_semilla(seed, fen=True, explicar=None):
    sols, refs = generar_adversarial(seed, fen)
    R = rc.analizar(sols, tuple(refs), explicar=explicar)
    ev, al = R["ev"], _alertados(R["df"])
    pers = sols.drop_duplicates("id_persona")
    inst = sols.drop_duplicates("id_persona").set_index("id_persona")
    por_patron = []
    for (esc, ins), g in sols.groupby(["escenario", "instancia"]):
        if esc == "normal":
            continue
        ids = set(g.id_persona)
        por_patron.append(dict(escenario=esc, instancia=ins, personas=len(ids),
                               frac_alertada=len(ids & al) / len(ids)))
    fraude = set(sols[sols.etiqueta == "fraude"].id_persona)
    alta = _alertados(R["df"], rc.ALTA)
    return dict(tabla=ev["tabla"].assign(semilla=seed), patrones=pd.DataFrame(por_patron),
                cobertura=cobertura_plan(R, sols, seed=seed), personas=len(pers),
                alta=dict(alertas=len(alta), falsos_positivos=len(alta - fraude), semilla=seed))


def cobertura_plan(R, sols, horas=8, simulaciones=300, seed=0):
    """¿Cuánto fraude se alcanza a revisar con `horas` de analista si se sigue el plan de RedShield
    frente a revisar casos al azar? Solo tiene sentido con etiquetas."""
    df = R["df"]
    fraude = set(sols[sols.etiqueta == "fraude"].id_persona)
    items = [(r.id, int(r.prioridad), float(r.esfuerzo_h)) for r in df.itertuples() if r.prioridad >= rc.ALERTA]
    if not items or not fraude:
        return None
    plan = rc.plan_revision(items, horas)
    mapa = {r.id: set(r.ids) for r in df.itertuples()}
    rs = len(set().union(*[mapa[i] for i in plan]) & fraude) / len(fraude) if plan else 0
    rnd, res = random.Random(seed), []
    for _ in range(simulaciones):
        orden, h, vistos = list(mapa), 0.0, set()
        rnd.shuffle(orden)
        esf = {r.id: float(r.esfuerzo_h) for r in df.itertuples()}
        for cid in orden:
            if h + esf[cid] > horas:
                continue
            h += esf[cid]
            vistos |= mapa[cid]
        res.append(len(vistos & fraude) / len(fraude))
    return dict(horas=horas, redshield=rs, azar=float(np.mean(res)))


def evaluar_robusto(n_semillas=N_SEMILLAS, fen=True, progreso=None, inicio=SEMILLA_INICIO, explicar=None):
    """Corre el flujo completo con `n_semillas` conjuntos distintos y resume media y desviación."""
    tablas, patrones, cob = [], [], []
    for s in range(inicio, inicio + n_semillas):
        r = evaluar_semilla(s, fen, explicar)
        tablas.append(r["tabla"])
        patrones.append(r["patrones"].assign(semilla=s))
        if r["cobertura"]:
            cob.append(r["cobertura"])
        if progreso:
            progreso((s - inicio + 1) / n_semillas)
    T = pd.concat(tablas)
    num = ["Alertas", "Verdaderos positivos", "Falsos positivos", "Falsos negativos", "Precisión (%)", "Recall (%)", "F1 (%)"]
    resumen = T.groupby("Método", sort=False)[num].agg(["mean", "std"]).round(1)
    resumen.columns = [f"{a} ({'media' if b == 'mean' else 'desv.'})" for a, b in resumen.columns]
    P = pd.concat(patrones)
    P["detectado"] = P.frac_alertada >= .5
    fr = P[P.escenario.isin(PATRONES_FRAUDE)]
    lg = P[P.escenario.isin(PATRONES_LEGITIMOS)]
    pat_fraude = (fr.groupby("escenario").detectado.mean() * 100).round(0).rename("Detectado (%)").reset_index()
    pat_fraude["Qué era"] = pat_fraude.escenario.map(NOMBRE)
    pat_legit = (lg.groupby("escenario").detectado.mean() * 100).round(0).rename("Con alerta (%)").reset_index()
    pat_legit["Qué era"] = pat_legit.escenario.map(NOMBRE)
    return dict(resumen=resumen, tabla=T, patrones_fraude=pat_fraude.rename(columns={"escenario": "Patrón"}),
                patrones_legitimos=pat_legit.rename(columns={"escenario": "Patrón"}), n_semillas=n_semillas,
                cobertura=dict(horas=cob[0]["horas"] if cob else 8,
                               redshield=float(np.mean([c["redshield"] for c in cob])) if cob else None,
                               azar=float(np.mean([c["azar"] for c in cob])) if cob else None))


# ---------------------------------------------------------------------- impacto económico
PERDIDA_REFERENCIA = 0.10        # dato dado por Caja Trujillo: pérdida aprox. de operaciones especiales del FEN 2017
DIAS_DETERIORO = 30              # referencia de Caja para "señal de deterioro" (atraso > 30 días)


def escenario_impacto(df, plan_ids, tasas=(0.10, 0.25, 0.40), perdida=PERDIDA_REFERENCIA):
    """Escenario con SUPUESTOS explícitos, no una predicción.

    exposición en alertas  = monto asociado a casos de prioridad media o alta
    exposición del plan    = la parte que alcanza a revisarse con las horas de analista disponibles
    pérdida evitable       = exposición del plan x % de alertas que resultaran irregulares x pérdida referencial

    El % de alertas irregulares se desconoce hasta validar con casos reales de Caja (por eso hay tres
    escenarios) y la pérdida referencial es la del FEN 2017 (operaciones especiales), no una pérdida por fraude.
    """
    alertas = df[df.prioridad >= rc.ALERTA]
    exp_alertas = int(alertas.exposicion.sum())
    exp_plan = int(alertas[alertas.id.isin(plan_ids)].exposicion.sum())
    filas = [dict(Escenario=f"{int(t * 100)}% de las alertas resultan irregulares", Supuesto_irregulares=t,
                  Exposicion_irregular=int(exp_plan * t), Perdida_evitable=int(exp_plan * t * perdida))
             for t in tasas]
    return dict(exposicion_alertas=exp_alertas, exposicion_plan=exp_plan, perdida_ref=perdida,
                dias_deterioro=DIAS_DETERIORO, escenarios=pd.DataFrame(filas))


def comparar_modos(n_semillas=N_SEMILLAS, inicio=SEMILLA_INICIO):
    """Corre la validación con y sin la regla «domicilio o negocio común = una sola relación» y resume el costo y el beneficio."""
    modos, filas = {}, []
    for explicar, nombre in ((False, "Sin la regla (cada coincidencia suma)"), (True, "Con la regla (domicilio o negocio común = una relación)")):
        V = evaluar_robusto(n_semillas, inicio=inicio, explicar=explicar)
        modos[explicar] = V
        r = V["resumen"].loc["RedShield completo"]
        pf = V["patrones_fraude"].set_index("Patrón")["Detectado (%)"]
        pl = V["patrones_legitimos"].set_index("Patrón")["Con alerta (%)"]
        filas.append({"Modo": nombre, "Precisión (%)": r["Precisión (%) (media)"], "Recall (%)": r["Recall (%) (media)"],
                      "Falsos positivos": r["Falsos positivos (media)"], "Patrones de fraude detectados (%)": round(pf.mean()),
                      "Familias con alerta (%)": pl["LF"], "Socios con alerta (%)": pl["LS"],
                      "Domicilio falso detectado (%)": pf["X4"], "Negocio ficticio detectado (%)": pf["X5"]})
    return dict(modos=modos, tabla=pd.DataFrame(filas), n_semillas=n_semillas)
