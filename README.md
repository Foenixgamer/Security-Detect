# Security-Detect

Pipeline de analisis y saneamiento de software (SQS - Sanitizador Quirurgico de Software).

## Estructura

```
sqsp/               Pipeline principal (7 capas)
  sqs.py              Orquestador CLI + GUI
  batch_processor.py  Procesamiento por lotes (archivo/dir/ZIP/TAR/ISO)
  vt_connector.py     Conexion real con VirusTotal (hash + subida + URL)
  rules_engine.py     Motor de reglas heuristicas
  gui_interface.py    GUI basica (Capa 4)
  sqs_gui.py          GUI interactiva (seleccion + analisis + lote + VT)
  security_guard.py   Guardia de seguridad defensiva
  tests/              148 tests automatizados
sqs_analysis_lab/   Laboratorio aislado (muestras inertes)
```

## Uso

```bash
# Archivo unico
python sqsp/sqs.py <archivo> --gui

# Lote (directorio / ISO / ZIP)
python sqsp/sqs.py --input <carpeta> -o <salida>

# Deteccion sin modificar (capas 1-4)
python sqsp/sqs.py --input <carpeta> --analyze

# Cirugia forzada en zona ambigua
python sqsp/sqs.py <archivo> --surgery

# App grafica interactiva
python sqsp/sqs.py --app
```

## Tests

```bash
python -m pytest -q          # 148 tests
python -m unittest discover -s tests
```

## VirusTotal

La API Key se guarda en un archivo local `.sqs_vt_key` (nunca en el codigo).
Configurar desde la app o:

```python
from vt_connector import save_api_key
save_api_key("tu-api-key")
```

## Aviso

Este proyecto es educativo y debe usarse exclusivamente en entornos
autorizados. Las muestras inertes del laboratorio son archivos falsos
con extensiones PE y datos sinteticos.
