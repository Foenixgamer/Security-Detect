# Progreso - SQS

## Capa 1 - Análisis Estático de Paquetes (integrada)

- [x] `layer1_extractor.py`: inventario de componentes de paquetes/directorios
      (type por extensión: executable/script/installer/other; path relativo;
      size; sha256; type real por magic bytes con `layers/layer1`)
- [x] Generación de `layer1_extracted_components.json` (CLI + `save_components`)
- [x] Test nuevo `tests/test_layer1_extractor.py` (8 tests) sin tocar
      `tests/test_layer1.py` ni `layers/layer1` (no rompe nada existente)
- [x] Se integra con el manifiesto de ingesta: el hash de cada componente
      alimenta la reputación de la Capa 1 actual

## Capa 2 - Análisis Dinámico de Paquetes (integrada)

- [x] `layer2_analyzer.py`: ejecuta los componentes de Capa 1 con timeout y
      registra por componente: `execution_time`, `exit_code` (-1 timeout,
      -2 error), `output`/`error` truncados a 500 caracteres
- [x] Resuelve rutas relativas contra el paquete (directorio o archivo único)
      y filtra tipos (executable + script; `other`/`installer` no se ejecutan)
- [x] Generación de `layer2_dynamic_analysis.json` (CLI + `save_dynamic_analysis`)
- [x] Test nuevo `tests/test_layer2.py` (10 tests, con mocks portables
      Windows/Linux/CI) sin tocar `dynamic_analysis_layer.py`
- [x] Smoke test real: `hello.bat` -> exit=0 con salida capturada
- [x] Se relaciona con el sandbox de `dynamic_analysis_layer.py` (pipeline 7 capas)

## Capa 3 - Análisis de Vulnerabilidades (integrada)

- [x] `layer3_vuln_analyzer.py`: verifica cada componente del inventario y
      asigna `risk_level` (bajo/medio/alto según nº de vulnerabilidades)
- [x] Firma digital real en Windows (`Get-AuthenticodeSignature` vía
      PowerShell); `signed`/`unsigned`/`unknown` (desconocido en no-Windows)
- [x] Funciones peligrosas REUTILIZANDO `imports_analyzer` (imports PE
      sospechosos) y `strings_analyzer` (tokens textuales: system(, eval(,
      CreateProcess, URLDownloadToFile, ...) en scripts
- [x] Obsolescencia por antigüedad (mtime > 10 años por defecto)
- [x] Correlación con Capa 2: timeout (-1) / fallo de ejecución (-2) suman
      vulnerabilidades; `execution_status` en detalles
- [x] Generación de `layer3_vulnerability_report.json` (CLI + save)
- [x] Rutas relativas resueltas contra el paquete (`base_dir`) manteniendo
      el path relativo en el informe
- [x] Test nuevo `tests/test_layer3.py` (22 tests, mocks portables) sin tocar
      `classification_layer.py` (zona de riesgo del pipeline 7 capas)
- [x] Smoke test real: `run.py` con `os.system(` -> riesgo "alto"

## Capa 4 - Generación de Informe Final y Reporte Automático (integrada)

- [x] `layer4_report_generator.py`: `build_report(report)` con metadatos
      (`timestamp`, `report_version`), `summary` (totales y distribución de
      riesgo), unión por componente de Capa 2 y Capa 3 y lista de
      vulnerabilidades consolidadas
- [x] Tolera datos faltantes: capas 2/3 ausentes o componentes sin `type`
      (cuenta como `other`); informes parciales no rompen la generación
- [x] Exportación: `generate_final_report` -> JSON (UTF-8, `ensure_ascii=False`)
- [x] Exportación HTML con estilo por riesgo (alto/medio/bajo) y **escape de
      contenido** (anti XSS)
- [x] Exportación CSV (una fila por componente: type, risk, exit_code, issues)
- [x] CLI: `python layer4_report_generator.py <paquete>` ejecuta la cadena
      completa Capa 1 -> Capa 4 y genera los 3 formatos; sin argumento lee
      los JSON guardados de las capas
- [x] Test nuevo `tests/test_layer4.py` (11 tests) sin tocar
      `packaging_layer.py` (empaquetado del pipeline 7 capas)
- [x] Smoke real: 3 componentes (2 scripts + 1 txt) -> riesgo alto para
      `run.py` (función peligrosa + fallo de ejecución); JSON/HTML/CSV OK

## Interfaz gráfica del spec de capas (integrada)

- [x] `gui_interface.py`: GUI tkinter (stdlib) conectada a las capas REALES
      (sin simulaciones), a diferencia de los borradores del spec que usaban
      datos de ejemplo hardcodeados
- [x] `analyze_package()`: orquesta Capa 1 -> Capa 4 con callback de progreso
      (4 etapas) y `should_stop` (detener entre etapas); lógica pura testeable
- [x] Pestañas: Componentes (path, tipo, tamaño, riesgo, exit), Vulnerabilidades
      y Recomendaciones (autogeneradas del informe real: firmas, funciones
      peligrosas, fallos de ejecución)
- [x] Hilo + cola + polling `root.after` (patrón de sqs_gui.py); barra de
      progreso determinista; "Guardar informe..." exporta JSON/HTML/CSV
- [x] Test nuevo `tests/test_gui_interface.py` (12 tests): lógica pura con
      mocks de las 4 capas + smoke tests que instancian y destruyen la GUI
      real (se saltan en headless)
- [x] Demo real: `analyze_package(sqs_demo/test_package)` -> 3 componentes,
      riesgo bajo/medio, recomendaciones generadas del informe real
- [x] No reemplaza `sqs_gui.py` (pipeline 7 capas) ni abre ventanas en tests

## Arquitectura de 7 capas (COMPLETADA)

- [x] Capa 1: Ingesta y Aislamiento (`ingestion_layer.py`) - cuarentena
      *read-only*, `manifest.json`, reputación por hash (`data/known_hashes.json`)
- [x] Capa 2: Análisis Estático (`static_analysis_layer.py`, sin libmagic) -
      componentes, entropía, strings (`strings_analyzer.py`), imports PE
      (`imports_analyzer.py`), packers/instaladores, PE embebidos, con
      enriquecimiento opcional `pefile`/`yara-python` (`rules/*.yara`)
- [x] Capa 3: Análisis Dinámico / Sandbox (`dynamic_analysis_layer.py`) con
      sandbox Docker descartable opcional (`SQS_DOCKER=1`,
      `sandbox/docker_runner.py`)
- [x] Capa 4: Clasificación (`classification_layer.py`) - pesos configurables
      (`config/weights.json`), **motor de reglas** (`rules_engine.py` +
      `rules/signatures.json`, YAML opcional), zonas
      LIMPIO/AMBIGUO/MALICIOSO, `verdict_map.json` con acciones de parcheo
- [x] Capa 5: Cirugía (`surgery_layer.py`) - backup inmutable, parcheo binario
      NOP, `surgery_log.json` con diff hex
- [x] Capa 6: Verificación (`integrity_verification_layer.py`) - re-ejecución
      del saneado (`rerun_dynamic_report.json`), `final_report.json`
- [x] Capa 7: Empaquetado + GUI tkinter (`packaging_layer.py`, `sqs_gui.py`)
- [x] Orquestador `sqs.py`: 7 capas con `on_progress`, decisión humana en
      zona AMBIGUO (`continuar` / `fuerza_cirugia` / `abortar`) y modo `--app`
- [x] GUI interactiva (`sqs_gui.py --app`): selección de archivo, barra de
      progreso, diálogo de decisión AMBIGUO, visor de reportes y exportación HTML
- [x] Tests: `test_layer1.py` (11), `test_layer1_extractor.py` (8),
      `test_layer2.py` (10), `test_layer3.py` (22), `test_layer4.py` (11),
      `test_gui_interface.py` (12), `test_pipeline.py` (10),
      `test_advanced.py` (12) y `test_rules_engine.py` (14) -
      **110 tests OK** (unittest y pytest)
- [x] Stack de desarrollo: `requirements*.txt`, `pytest.ini`, `.venv`,
      CI GitHub Actions (`.github/workflows/ci.yml`), PyInstaller
      (`scripts/build_exe.ps1`), `.gitignore`
- [x] Documentación: `README.md` actualizado con reportes, pesos, zonas,
      motor de reglas, Docker y build

## Notas técnicas

- Comunicación entre capas por archivos JSON (sin memoria compartida).
- Sin dependencias externas: MIME estimado con magic bytes + extensión.
- `subprocess.run(..., timeout=...)` en lugar del comando `timeout` (Linux),
  portado a Windows.
- `static_analysis_layer` reutiliza los analizadores de `layers/layer1`.
- El análisis dinámico de Windows no ofrece un sandbox real de red/filesystem;
  el veredicto en el demo se apoya en la heurística de ejecución.

## Próximas mejoras (planificadas)

- Sandbox real con monitoreo de syscalls/red/filesystem.
- Sanitización granular de secciones (writable+ejecutables, imports) mediante
  el `verdict_map.json` ya generado.
- Ampliar `data/known_hashes.json` con firmas de malware y correlación.
- Empaquetado a ejecutable standalone (PyInstaller).
- Análisis de más tipos de archivo (instaladores MSI, scripts, documentos OLE).

## Prueba de humo (smoke test) - PASA

- [x] Guarda defensivo (pre-flight): muestras y scripts sin evasión ni ocultamiento
- [x] Generador de prueba sintética (`sqs_analysis_lab/test_generator.py`)
- [x] `security_guard.py` con `check_action`/`scan_artifact`
- [x] Pipeline real: malicioso (riesgo 19)
- [x] Cirugía completada, backup read-only, saneado utilizable en el paquete
- [x] `complete_report.json` + `README.md` generados
- [x] Verificaciones automáticas todas en OK (2026-09-04T19:01:10)

## Soporte de entrada múltiple: archivo / directorio / ISO (integrado)

- [x] `batch_processor.py`: orquestador de lotes que reutiliza el pipeline REAL
      de 7 capas (`run_pipeline`) por archivo — NO duplica Capas 5/6
- [x] Entradas soportadas: archivo único, directorio (recorrido con filtro de
      extensiones de interés) e ISO (extracción best-effort con 7z/bsdtar/tar)
- [x] `TARGET_EXTENSIONS`: exe/dll/sys/ocx/scr/com/cpl/bat/cmd/vbs/ps1/py/js
- [x] Errores por archivo no detienen el lote (`status: ok/error/aborted`);
      ruta inexistente se registra como error
- [x] `batch_report.json` agregado (total/ok/cleaned/suspicious/errors)
- [x] Decisión AMBIGUO por archivo: `interactive_decision` (CLI) o
      `decision_callback`; `--surgery` fuerza cirugía en todo el lote
- [x] CLI: `python sqs.py --input RUTA1 RUTA2... [-o DIR] [--surgery]`;
      un directorio o ISO como `archivo` también dispara modo lote
- [x] GUI `sqs_gui.py` (app): lista de selección ÚNICA (`selected_inputs`)
      con botones "Seleccionar archivos / directorios / ISO", prefijos
      FILE/DIR/ISO, "Limpiar selección" y "Analizar y procesar" (sin
      redundancias entre selector único y lote); checkbox "Modo avanzado:
      forzar cirugía en AMBIGUO" para el lote; archivo único mantiene el
      diálogo interactivo de decisión AMBIGUO
- [x] Test nuevo `tests/test_batch_processor.py` (11 tests) con pipeline real
      sobre PE sintéticos — **128 tests OK** (unittest y pytest)
- [x] Demo real: lote sobre `sqs_analysis_lab/muestras` (4/4 maliciosos
      saneados; el `.txt` queda filtrado por extensión)
- [x] **Análisis automático (detección)**: botón en la app que corre el
      pipeline REAL en modo `analyze_only` (capas 1-4: ingesta/estático/
      dinámico/veredicto) — SIN cirugía ni paquete. Etiqueta de estado
      (listo/analizando/completado), log por archivo con etiqueta
      MALICIOSO/SOSPECHOSO/LIMIO y resumen agregado. `process_batch`
      acepta `analyze_only=True` (no modifica archivos; evita sys.exit
      interno de `analyze_only` en el lote).
- [x] **Conector VirusTotal real** (`vt_connector.py`, solo stdlib urllib,
      sin dependencias): hash SHA256, informe por hash (`GET /files/<hash>`),
      subida multipart (`POST /files`) y polling del análisis (`GET
      /analyses/<id>`). API Key persistida en archivo local `.sqs_vt_key`
      (nunca en código/logs; borrado si se guarda vacía). Manejo de
      404→not_found, límites/error de red como VTError, sin clave→
      VTConfigError.
- [x] Sección "VirusTotal" en la app: campo API Key (oculto) + Guardar +
      "Consultar VirusTotal" (resuelve dirs/ISO vía `resolve_inputs`,
      analiza cada archivo y sube si no está en la base; log por archivo
      con maliciosos/sospechosos/sin-detectar y nombres de motor; botones
      desactivados durante la consulta).
- [x] **Contenedores (ZIP/TAR/7z/RAR/ISO)** en el lote: ZIP/TAR con stdlib
      (guardado anti-traversal: se descartan entradas con `..` o raíz), y
      los demás vía extractor externo (7z/bsdtar) como hasta ahora. La
      extracción es de UN nivel (no recursiva). Limpieza de temporales
      garantizada aunque un archivo falle.
- [x] **Exportar resultados**: botón en la app → `batch_report.json` +
      `resumen_batch.csv` (UTF-8-BOM para Excel) vía `write_csv_summary`;
      `_last_results` guardado también tras análisis de archivo único.
- [x] **VirusTotal por URL**: `vt_connector.scan_url()` (POST /urls, forma
      urlencoded con urllib) + campo URL en la app ("Consultar URL") que
      encola y hace polling del análisis; veredicto MALICIOSA/SOSPECHOSA/
      LIMIA en el log.
- [x] **Aviso de extensión peligrosa** al añadir archivos (`.exe/.bat/.scr/
      .com/.pif/.vbs/.js/.jse/.wsf/.ps1/.dll`). — **148 tests OK**
