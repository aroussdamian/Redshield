"""Pruebas del motor de RedShield (sin interfaz).  Ejecutar:  python -m pytest -q   (o:  python tests/test_core.py)"""
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import redshield_core as rc  # noqa: E402

_cache = {}


def analisis():
    if "R" not in _cache:
        sols, refs = rc.generar_datos()
        _cache["sols"], _cache["R"] = sols, rc.analizar(sols, tuple(map(tuple, refs)))
    return _cache["sols"], _cache["R"]


# ---------------------------------------------------------------- normalización
def test_direcciones_escritas_distinto_son_la_misma():
    assert rc.norm_dir("Av. Larco N° 215") == rc.norm_dir("AVENIDA LARCO 215") == rc.norm_dir("Av Larco 215")


def test_telefonos_con_un_digito_distinto_se_unifican():
    t = pd.Series(["987654321", "987654322", "911111111", None], dtype="string")
    u = rc.unificar_telefonos(t)
    assert u.iloc[0] == u.iloc[1]
    assert u.iloc[2] == "911111111"
    assert pd.isna(u.iloc[3])


def test_no_se_unifican_grupos_demasiado_grandes():
    base = "98765432"
    t = pd.Series([base + str(i) for i in range(10)], dtype="string")      # 10 números a un dígito entre sí
    assert rc.unificar_telefonos(t, max_grupo=6).nunique() == 10


def test_enmascaramiento():
    assert rc.mask_tel("987654321") == "9****321"
    assert rc.mask_mail("ana@gmail.com") == "a***@gmail.com"
    assert rc.mask_ip("190.12.34.56") == "190.12.*.*"
    assert "215" not in rc.mask_dir("Av. Larco 215, Trujillo")


# ------------------------------------------------------------------ validación
def test_validar_rechaza_columnas_faltantes():
    limpio, refs, rep = rc.validar(pd.DataFrame({"id_solicitud": ["S1"]}))
    assert limpio is None and any(r[2] == "Error" for r in rep)


def test_validar_elimina_duplicados_y_filas_invalidas():
    df = rc.PLANTILLA.copy()
    df = pd.concat([df, df.iloc[[0]]], ignore_index=True)                    # duplicado
    df.loc[1, "monto"] = -5                                                  # monto inválido
    limpio, refs, rep = rc.validar(df)
    assert len(limpio) == 1 and dict((r[0], r[1]) for r in rep)["Solicitudes duplicadas"].startswith("1")


# ------------------------------------------------------------- análisis de redes
def test_se_detectan_casos_y_supernodos():
    _, R = analisis()
    assert len(R["df"]) >= 20 and R["redes"] >= len(R["df"])
    assert len(R["sup"]) >= 2                       # cibercafé y asesor de créditos
    assert set(R["df"].nivel) <= {"Alta", "Media", "Baja"}


def test_los_supernodos_no_unen_a_los_clientes_del_cibercafe():
    sols, R = analisis()
    clientes = set(sols[sols.escenario == "G"].id_persona)
    mayor = max(sum(1 for p in R["df"].ids.iloc[i] if p in clientes) for i in range(len(R["df"])))
    assert mayor <= 2


def test_dispositivo_compartido_por_seis_es_prioridad_alta():
    sols, R = analisis()
    df = R["df"]
    ids = set(sols[sols.escenario == "A"].id_persona)
    fila = df[df.ids.map(lambda x: len(ids & set(x)) >= 5)].iloc[0]
    assert fila.nivel == "Alta"


def test_telefono_con_digito_alterado_forma_un_caso():
    sols, R = analisis()
    ids = set(sols[sols.escenario == "M"].id_persona)
    assert any(len(ids & set(x)) == 4 for x in R["df"].ids)


def test_persona_puente_detectada():
    _, R = analisis()
    assert any(len(b) > 0 for b in R["df"].brid)


# ------------------------------------------------------------------- evaluación
def test_evaluacion_mejora_la_linea_base():
    _, R = analisis()
    T = R["ev"]["tabla"].set_index("Método")
    rs, sql = T.loc["RedShield completo"], T.loc["Consulta SQL (dispositivo o teléfono compartido)"]
    assert rs["Precisión (%)"] > sql["Precisión (%)"] and rs["Falsos positivos"] < sql["Falsos positivos"]


def test_sin_etiquetas_no_se_inventan_metricas():
    sols, _ = analisis()
    sin = sols.drop(columns=["etiqueta", "escenario"])
    R = rc.analizar(sin, ())
    assert R["ev"] is None


# ------------------------------------------------------------- priorización / feedback
def test_plan_de_revision_respeta_la_capacidad():
    items = [("A", 90, 2.0), ("B", 80, 1.5), ("C", 70, 1.0), ("D", 20, 0.5)]
    plan = rc.plan_revision(items, 3)
    assert sum(e for i, _, e in items if i in plan) <= 3 + 1e-9
    assert plan == {"B", "C", "D"}                  # valor 170 > A+C = 160: la combinación óptima


def test_calibracion_exige_minimo_de_decisiones():
    _, R = analisis()
    df = R["df"]
    caso = df[df.senales.map(lambda s: any(x["tipo"] == "telefono" for x in s))].id.iloc[:2]
    p = rc.calibrar_pesos(df, {c: "Relación legítima" for c in caso})
    assert p["telefono"]["aplica"] is False and p["telefono"]["mult"] == 1.0


def test_calibracion_baja_el_peso_de_lo_que_el_analista_descarta():
    _, R = analisis()
    df = R["df"]
    casos = df[df.senales.map(lambda s: any(x["tipo"] == "telefono" for x in s))].id.iloc[:4]
    p = rc.calibrar_pesos(df, {c: "Relación legítima" for c in casos})
    assert p["telefono"]["aplica"] and p["telefono"]["mult"] < 1
    assert (rc.aplicar_pesos(df, p) <= df.prioridad).all()


def test_sin_pesos_la_prioridad_no_cambia():
    _, R = analisis()
    assert (rc.aplicar_pesos(R["df"], {}) == R["df"].prioridad).all()


if __name__ == "__main__":                                                   # ejecución sin pytest
    fallos = 0
    for nombre, fn in sorted(globals().items()):
        if nombre.startswith("test_") and callable(fn):
            try:
                fn(); print("OK  ", nombre)
            except Exception as e:
                fallos += 1; print("FALLA", nombre, repr(e))
    sys.exit(1 if fallos else 0)
