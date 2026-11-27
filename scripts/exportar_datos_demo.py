"""Genera datos/solicitudes_sinteticas.csv y datos/plantilla_redshield.csv.

El archivo de muestra sirve para probar la importación de la app (Datos y auditoría > Importar datos).
Todos los datos son SINTÉTICOS: no hay personas reales.
Uso:  python scripts/exportar_datos_demo.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import redshield_core as rc  # noqa: E402

RAIZ = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "datos")


def main():
    os.makedirs(RAIZ, exist_ok=True)
    df, refs = rc.generar_datos()
    df["fecha"] = df.fecha.dt.strftime("%Y-%m-%d %H:%M")
    df["id_referencia"] = ""
    perdidas = 0
    for a, b in refs:                      # cada fila admite una sola referencia
        for x, y in ((a, b), (b, a)):
            libres = df.index[(df.id_persona == x) & (df.id_referencia == "")]
            if len(libres):
                df.loc[libres[0], "id_referencia"] = y
                break
        else:
            perdidas += 1
    cols = ["id_solicitud", "id_persona", "fecha", "monto", "dispositivo", "telefono", "direccion", "ip", "correo",
            "id_negocio", "provincia", "id_referencia", "etiqueta", "escenario"]
    df[cols].to_csv(os.path.join(RAIZ, "solicitudes_sinteticas.csv"), index=False, encoding="utf-8")
    rc.PLANTILLA.to_csv(os.path.join(RAIZ, "plantilla_redshield.csv"), index=False, encoding="utf-8")
    print(f"{len(df)} solicitudes escritas; referencias no representables en el CSV: {perdidas} de {len(refs)}")


if __name__ == "__main__":
    main()
