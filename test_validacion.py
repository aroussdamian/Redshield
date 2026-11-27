"""Pruebas de la validación robusta.  Ejecutar:  python -m pytest -q   (o:  python tests/test_validacion.py)"""
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import redshield_core as rc  # noqa: E402
import redshield_validacion as rv  # noqa: E402


def test_el_generador_es_reproducible_y_varia_con_la_semilla():
    a, _ = rv.generar_adversarial(3)
    b, _ = rv.generar_adversarial(3)
    c, _ = rv.generar_adversarial(4)
    assert a.equals(b)
    assert len(a) != len(c) or not a.equals(c)


def test_hay_varias_instancias_de_cada_patron_y_legitimos_dificiles():
    s, _ = rv.generar_adversarial(0)
    inst = s[s.escenario != "normal"].groupby("escenario").instancia.nunique()
    for p in rv.PATRONES_FRAUDE:
        assert inst[p] >= 2, p                       # el patrón no es una instancia única
    for p in ("LF", "LP", "LS", "LC", "LE", "LA"):
        assert p in inst.index


def test_el_analisis_no_depende_de_las_etiquetas():
    """Si quitamos etiqueta, escenario e instancia el resultado debe ser idéntico: no hay fuga de la verdad."""
    s, refs = rv.generar_adversarial(1)
    con = rc.analizar(s, tuple(refs))["df"]
    sin = rc.analizar(s.drop(columns=["etiqueta", "escenario", "instancia"]), tuple(refs))["df"]
    assert list(con.prioridad) == list(sin.prioridad)
    assert [sorted(x) for x in con.ids] == [sorted(x) for x in sin.ids]


def test_el_monto_no_delata_el_fraude():
    s, _ = rv.generar_adversarial(0)
    m = s.groupby("etiqueta").monto.median()
    assert abs(m["fraude"] - m["legitimo"]) / m["legitimo"] < 0.5


def test_la_mitigacion_de_demanda_descuenta_solo_con_aumento_regional():
    f = dict(max_dev=4, max_tel=1, max_ip=1, max_mail=1, max_neg=1, max_dir=1, refs=0, puentes=0, saltos=0, rafaga=5)
    pts = lambda x: [s["pts"] for s in rc.evaluar(dict(f, demanda_x=x)) if s["tipo"] == "temporal"][0]
    assert pts(1.0) == 20 and pts(3.0) == 5
    rc.MITIGAR_DEMANDA = False
    try:
        assert pts(3.0) == 20
    finally:
        rc.MITIGAR_DEMANDA = True


def test_el_propio_caso_no_se_descuenta_a_si_mismo():
    d = rc.normalizar(rv.generar_adversarial(0)[0])
    fr = d[d.instancia == "RA0"]
    ini = fr.fecha.min()
    x = rc._demanda_contexto(d, rc.PROV2ZONA[fr.provincia.iloc[0]], list(fr.id_persona), ini)
    assert x < rc.DEMANDA_X                           # el fraude concentrado no se confunde con una campaña


def test_evaluacion_robusta_devuelve_resumen_y_redshield_supera_a_sql():
    V = rv.evaluar_robusto(3)
    r = V["resumen"]
    rs, sql = "RedShield completo", "Consulta SQL (dispositivo o teléfono compartido)"
    assert r.loc[rs, "Precisión (%) (media)"] > r.loc[sql, "Precisión (%) (media)"]
    assert set(V["patrones_fraude"]["Patrón"]) == set(rv.PATRONES_FRAUDE)
    assert V["cobertura"]["redshield"] >= V["cobertura"]["azar"]


def test_escenario_de_impacto_es_coherente():
    R = rc.analizar(*[(s, tuple(map(tuple, r))) for s, r in [rc.generar_datos()]][0])
    df = R["df"]
    plan = set(df[df.prioridad >= rc.ALERTA].id.iloc[:3])
    im = rv.escenario_impacto(df, plan)
    assert 0 < im["exposicion_plan"] <= im["exposicion_alertas"]
    e = im["escenarios"]
    assert e.Perdida_evitable.is_monotonic_increasing
    assert abs(e.Perdida_evitable.iloc[-1] - int(im["exposicion_plan"] * 0.40 * rv.PERDIDA_REFERENCIA)) <= 1


def _f(**kw):
    base = dict(personas=4, max_dev=1, max_tel=4, max_ip=1, max_mail=1, max_neg=4, max_dir=1, refs=0, puentes=0, saltos=0,
                rafaga=2, explicado="")
    base.update(kw)
    return base


def test_socios_con_negocio_y_telefono_comun_no_alcanzan_alerta_con_la_regla():
    f = _f(explicado="un mismo negocio")
    assert rc._pts(rc.evaluar(dict(f), explicar=True)) < rc.ALERTA
    assert rc._pts(rc.evaluar(dict(f), explicar=False)) >= rc.ALERTA


def test_la_regla_no_toca_dispositivos_compartidos():
    f = _f(max_dev=5, max_neg=1, max_tel=1, explicado="")
    assert rc._pts(rc.evaluar(dict(f), explicar=True)) == rc._pts(rc.evaluar(dict(f), explicar=False))


def test_el_parametro_explicar_no_cambia_el_estado_global():
    antes = rc.EXPLICAR_RELACIONES
    s, refs = rv.generar_adversarial(2)
    rc.analizar(s, tuple(refs), explicar=False)
    assert rc.EXPLICAR_RELACIONES == antes


def test_comparar_modos_muestra_el_costo():
    C = rv.comparar_modos(2, inicio=300)
    t = C["tabla"].set_index("Modo")
    sin, con = t.iloc[0], t.iloc[1]
    assert con["Falsos positivos"] < sin["Falsos positivos"]
    assert con["Domicilio falso detectado (%)"] <= sin["Domicilio falso detectado (%)"]


if __name__ == "__main__":
    fallos = 0
    for nombre, fn in sorted(globals().items()):
        if nombre.startswith("test_") and callable(fn):
            try:
                fn(); print("OK  ", nombre)
            except Exception as e:
                fallos += 1; print("FALLA", nombre, repr(e))
    sys.exit(1 if fallos else 0)
