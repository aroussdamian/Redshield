# RedShield 🛡️

**Detección y priorización de redes de riesgo ocultas** · Cajathon 2026 · Eje 3 (Riesgo, fraude y recuperaciones inteligentes)

RedShield convierte solicitudes de crédito dispersas en una red de personas, negocios, dispositivos, teléfonos, direcciones, IP, correos y referencias. Detecta qué grupos de solicitudes conviene revisar primero y explica por qué, **pero no acusa a nadie**: la prioridad es un orden sugerido de revisión (no una probabilidad de fraude) y toda decisión la toma un analista.

> ⚠️ **Todos los datos de esta demostración son sintéticos.** No hay personas reales ni conexión con sistemas de Caja Trujillo. Las cifras de evaluación validan el funcionamiento del flujo, no el desempeño real: falta validarlo con casos históricos etiquetados.

## Qué hace

| Panel | Para qué sirve |
|---|---|
| **Inicio** | Situación general en menos de 30 segundos: solicitudes analizadas, redes, casos pendientes, exposición económica bajo revisión (no es pérdida confirmada), mapa de riesgo región → provincia → caso, prioridades, evolución por fecha y cola de atención. |
| **Investigaciones** | Bandeja de casos con filtros (prioridad, fecha, estado, tipo de conexión, exposición). Un clic abre la investigación. |
| **Investigación de red** | Red interactiva con personas puente, comunidades, conexiones indirectas (con número de saltos), supernodos, evidencias, explicación del sistema y decisión del analista. |
| **Análisis temporal** | Línea de tiempo, nuevas conexiones por día, ráfagas, crecimiento de comunidades y comparación entre periodos. |
| **Evaluación del modelo** | Precisión, recall, falsos positivos, matriz de confusión, comparación contra SQL y reglas, con y sin señales temporales, historial de retroalimentación y calibración. Sin datos etiquetados muestra «pendiente de validación». |
| **Datos y auditoría** | Importación CSV/Excel con validación, calidad de datos, historial de importaciones, usuarios y roles, registro de decisiones, privacidad (Ley 29733) y análisis de equidad por región. |

## Cómo funciona

1. **Validación y normalización:** columnas, duplicados, formatos; direcciones y teléfonos que difieren en un dígito se reconocen como la misma entidad.
2. **Grafo de relaciones** (NetworkX): personas, negocios, dispositivos, teléfonos, direcciones, IP, correos y referencias.
3. **Patrones:** comunidades (Louvain), personas puente (puntos de articulación), caminos indirectos, ráfagas en 72 h. Los **supernodos** (cibercafés, agencias, asesores) se tratan como contexto y no unen casos.
4. **Priorización:** señales explicables con su posible explicación legítima, un componente exploratorio de Isolation Forest (máximo 10 puntos, *no es un detector validado*), exposición económica y plan de revisión según las horas de analista (mochila 0/1).
5. **Análisis humano:** el analista registra «Relación legítima», «En investigación» o «Requiere escalamiento», y puede agregar evidencia.
6. **Aprendizaje:** las decisiones ajustan de forma transparente el peso de cada tipo de señal (opcional, desde la barra lateral). No es un modelo entrenado.

## Ejecutar en local

Requiere Python 3.11 o 3.12.

```bash
python -m venv .venv
source .venv/bin/activate          # En Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m streamlit run redshield_app.py
```

Abre la dirección que indica la terminal (normalmente http://localhost:8501).

## Probar con tus propios datos

En **Datos y auditoría → Importar datos** puedes descargar una plantilla o usar los archivos de la carpeta `datos/`:

- `datos/solicitudes_sinteticas.csv`: las mismas solicitudes de la demostración, con las columnas `etiqueta` (fraude / legitimo) y `escenario` (solo existe en datos sintéticos) para habilitar la evaluación completa.
- `datos/plantilla_redshield.csv`: ejemplo mínimo.

Columnas requeridas: `id_solicitud, id_persona, fecha, monto, dispositivo, telefono, direccion`.
Opcionales: `ip, correo, id_negocio, provincia, id_referencia, etiqueta`.

Para regenerar los datos de muestra: `python scripts/exportar_datos_demo.py`.

## Pruebas

```bash
pip install pytest
python -m pytest -q          # o:  python tests/test_core.py
```

Las pruebas cubren normalización, supernodos, personas puente, evaluación frente a la línea base, calibración y el plan de revisión.

## Despliegue (Streamlit Community Cloud)

1. Sube este repositorio a GitHub (rama `main`).
2. En [share.streamlit.io](https://share.streamlit.io) crea una app nueva y elige el repositorio.
3. Archivo principal: `redshield_app.py`. En *Advanced settings* elige Python 3.11 o 3.12.

El registro de decisiones se guarda en `redshield_auditoria.jsonl`. En la nube el disco no es permanente: si la app se reinicia, el registro se pierde (en producción iría a una base de datos).

## Estructura

```
redshield_app.py          Interfaz (Streamlit)
redshield_core.py         Motor de análisis: datos, grafo, señales, evaluación, calibración
requirements.txt          Dependencias
datos/                    Datos sintéticos de muestra y plantilla
scripts/                  Generador de los datos de muestra
tests/                    Pruebas automáticas del motor
.streamlit/config.toml    Tema visual
```

## Límites y hoja de ruta

- Datos sintéticos; sin validación con casos históricos reales.
- Geolocalización solo a nivel de región y provincia.
- Todo corre en memoria con NetworkX. Para millones de solicitudes: base de grafos, procesamiento por lotes y actualización incremental.
- Control de acceso, cifrado y retención de datos son una demostración; definir con la institución las bases legales (Ley 29733), plazos y gestión real de usuarios.
- Isolation Forest es exploratorio. Un puntaje alto indica que conviene mirar el caso, no que haya fraude.

## Principios de uso responsable

- Compartir un teléfono, dispositivo o dirección puede tener explicaciones legítimas (familias, negocios, cibercafés).
- La exposición económica es el monto asociado a casos bajo revisión, no una pérdida ni un fraude confirmado.
- El sistema no bloquea ni rechaza clientes y no debe usarse para decisiones crediticias automáticas.

## Roles y acceso

Al entrar, toda persona queda como **Jurado** (visitante, solo lectura y datos limitados). El personal ingresa desde la barra lateral → *Acceso del personal* (cuenta + clave).

| Rol | Paneles | Decide casos | Notas y registro | Descargas | Importar datos |
|---|---|---|---|---|---|
| Jurado | Todos menos Inicio | No | No | No | No |
| Analista | Todos menos Inicio | Sí | Sí | Sí | No |
| Supervisor | Todos (único con Inicio) | Sí | Sí | Sí | Sí |

Las claves se guardan solo como hash en el código. Para cambiarlas, define en los *Secrets* de Streamlit Cloud:

```toml
[claves]
supervisor = "tu-clave-supervisor"
analista = "tu-clave-analista"
```
