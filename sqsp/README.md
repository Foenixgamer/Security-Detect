# SQS - Sanitizador Quirúrgico de Software

Un sistema defensivo en capas para analizar y sanitizar software sospechoso
sin ejecutarlo de forma insegura. Cada capa es un módulo independiente que se
comunica con la siguiente mediante archivos JSON (auditabilidad y trazabilidad).

## Requisitos

- Python 3.11+ (sin dependencias externas; la GUI usa tkinter, incluido en el
  instalador oficial de Python)

Capacidades opcionales (con `pip install`):
- `pefile`: enriquece el análisis de PE (secciones, imports, características).
- `yara-python`: escaneo de firmas `rules/*.yara`.
- `PyYAML`: reglas de la Capa 4 en formato YAML.
- `pytest` + `pyinstaller`: tests y empaquetado standalone.

Entorno virtual recomendado:

```bash
python -m venv .venv
.venv\Scripts\activate       # Windows
pip install -r requirements-dev.txt
python -m pytest -q
```

## Arquitectura (7 capas)

| Capa | Módulo | Función |
|------|--------|---------|
| 1. Ingesta y Aislamiento | `ingestion_layer.py` + `layer1_extractor.py` | Hash SHA-256, cuarentena *read-only*, `manifest.json`, reputación por hash e inventario de componentes (`layer1_extracted_components.json`) |
| 2. Análisis Estático | `static_analysis_layer.py` | Tipo/arquitectura (PE/ELF/Mach-O), secciones, entropía, strings, imports, packers, PE embebidos (+ opcional `pefile`/`yara-python`) |
| 3. Análisis Dinámico | `dynamic_analysis_layer.py` | Ejecución controlada con timeout (sustituible por Docker opcional) |
| 4. Clasificación | `classification_layer.py` | Pesos configurables (`config/weights.json`), **motor de reglas** (`rules_engine.py` + `rules/`), zonas y `verdict_map.json` |
| 5. Cirugía | `surgery_layer.py` | Backup inmutable, parcheo binario (NOP) y `surgery_log.json` con diff |
| 6. Verificación | `integrity_verification_layer.py` | Re-ejecución del saneado, comparación y `final_report.json` |
| 7. Empaquetado | `packaging_layer.py` / `sqs_gui.py` | Paquete final + informe completo + GUI (tkinter) |

Componentes reutilizables (capa 1 original): `layers/layer1/` con detector de
tipo, analizador de encabezados, extractor de secciones, recolector de
metadatos, analizador de strings/entropía (`strings_analyzer.py`) y analizador
de imports PE (`imports_analyzer.py`). Adicionalmente, el spec de capas
aporta `layer1_extractor.py` (inventario de componentes),
`layer2_analyzer.py` (análisis dinámico de componentes con timeout),
`layer3_vuln_analyzer.py` (análisis de vulnerabilidades con verificación de
firma, funciones peligrosas y obsolescencia) y `layer4_report_generator.py`
(informe final en JSON/HTML/CSV combinando las capas), integrados sin
reemplazar las capas del pipeline.

Interfaces gráficas:
- `sqs_gui.py` -> GUI del pipeline completo de 7 capas (veredicto, pause en
  zona AMBIGUO, visor de reportes y exportación HTML).
- `gui_interface.py` -> GUI del spec de capas 1-4 (selección de paquete,
  análisis real con progreso, pestañas de componentes/vulnerabilidades/
  recomendaciones y exportación JSON/HTML/CSV).

## Uso rápido (pipeline completo)

```bash
python sqs.py <ruta_al_archivo_sospechoso> [--gui] [-o directorio_salida] [--app]
```

Ejemplo:
```bash
python sqs.py C:\sample\archivo.exe --gui
python sqs.py --app        # modo interactivo con barra de progreso
```

En zona `AMBIGUO` el pipeline se detiene y pregunta al usuario qué hacer
(continuar sin cirugía, forzar cirugía o abortar). En CLI el flujo se
orquesta con la opción `--app` (GUI) o el parámetro `decision_callback`.

## Reportes generados

`temp_YYYYMMDD_HHMMSS/` (entorno aislado):

- `manifest.json`: hash, tamaño, tipo MIME, reputación
- `layer1_extracted_components.json`: inventario de componentes (Capa 1,
  generado por `layer1_extractor.py`)
- `layer2_dynamic_analysis.json`: ejecución y comportamiento de componentes
  (Capa 2, generado por `layer2_analyzer.py`)
- `layer3_vulnerability_report.json`: vulnerabilidades y riesgo por
  componente (Capa 3, generado por `layer3_vuln_analyzer.py`)
- `final_report.json` / `final_report.html` / `final_report.csv`: informe
  final combinando Capa 1-3 y exportaciones (Capa 4, generado por
  `layer4_report_generator.py`)
- `static_analysis.json`: componentes, entropía, strings, imports, packers
- `dynamic_report.json` / `rerun_dynamic_report.json`: ejecución sandbox
- `classification.json`: veredicto + puntaje de riesgo
- `rules_report.json`: reglas evaluadas y disparadas por el motor de Capa 4
- `verdict_map.json`: acciones quirúrgicas por componente
- `surgery_report.json` + `surgery_log.json`: cirugía y diff de parcheos
- `integrity_verification.json` + `final_report.json`: verificación final
- `complete_report.json` (en `final_package_*`): consolidado + README

## Uso modular (cada capa por separado)

```bash
# Paso 1: Ingesta y aislamiento (crea temp_YYYYMMDD_HHMMSS/)
python ingestion_layer.py C:\sample\archivo.exe

# Paso 2: Análisis estático
set TEMP_DIR=temp_20240904_123456
python static_analysis_layer.py C:\sample\archivo.exe

# Paso 3: Análisis dinámico (sandbox)
python dynamic_analysis_layer.py C:\sample\archivo.exe

# Paso 4: Clasificación y veredicto
python classification_layer.py %TEMP_DIR%

# Paso 5: Saneamiento
python surgery_layer.py C:\sample\archivo.exe

# Paso 6: Verificación de integridad funcional
python integrity_verification_layer.py C:\sample\archivo.exe

# Paso 7: Empaquetado final
python packaging_layer.py C:\sample\archivo.exe
```

## Interfaz gráfica

```bash
# Ver los reportes de un directorio de trabajo
python sqs_gui.py temp_20240904_123456

# App interactiva (progreso + decisión en zona AMBIGUO + visor)
python sqs_gui.py --app
```

## Presión

```bash
python -m unittest discover -s tests -v   # o: python -m pytest -q
```

## Motor de reglas (Capa 4)

Las reglas viven en `rules/*.json` (activas) y `rules/*.yaml` (si PyYAML está
instalado); los archivos `example_*` son plantillas y no se cargan. Cada regla
define un `condition.field` (ruta punteada sobre el reporte), un operador
(`exists`, `equals`, `contains`, `greater`, `regex`) y puntos de riesgo por
`severity` (`low` +1, `medium` +2, `high` +3, `critical` +4) o `base_add`.

```json
{
  "name": "Process_Injection_API",
  "severity": "high",
  "condition": {
    "field": "static_analysis.suspicious_imports",
    "op": "contains",
    "value": "CreateRemoteThread"
  }
}
```

El resultado se audita en `rules_report.json` (`rules_evaluated`, `matched`,
`risk_added`) y los puntos se suman al riesgo de `classification.json`.

## Sandbox Docker (opcional)

Con `SQS_DOCKER=1` la Capa 3 ejecuta el archivo en un contenedor descartable
(`docker run --rm`, sin red, 1 CPU / 256 MB) usando `sandbox/docker_runner.py`.
Si Docker no está disponible, cae automáticamente al sandbox local:

```bash
set SQS_DOCKER=1
python sqs.py C:\sample\archivo.exe
```

## Empaquetado ejecutable (PyInstaller)

```bash
powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1
# genera dist\SQS-GUI.exe (usar SQS-GUI.exe --app)
```

## Integración continua

`pip install -r requirements-dev.txt`; CI en `.github/workflows/ci.yml`
(GitHub Actions, Python 3.11/3.12, pytest + unittest).

## Reglas de clasificación (heurísticas)

Pesos configurables en `config/weights.json`:

- Ejecutable detectado: +2
- Error en ejecución (sandbox): +5
- Actividad de red: +3
- Cambios en filesystem: +3
- String sospechoso: +1
- Import sospechoso (WinExec, ShellExecute, Internet*, ...): +2
- Alta entropía (>= 7.5, empaquetado/API): +3
- Instalador / empaquetador: +2
- Hash conocido malicioso: +10

- Veredicto: `malicioso` (>= 10), `sospechoso` (>= 5), `seguro` (< 5)
- Zonas: `malicioso` (cirugía automática), `ambiguo` (decisión humana),
  `limpio` (sin acciones). Reputación benigna conocida: riesgo acotado a < 5.