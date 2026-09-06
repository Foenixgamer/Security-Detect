# SQS Security Pipeline — Laboratorio aislado

Laboratorio de demostración (100% educativo) del **Sanitizador Quirúrgico de
Software** (`C:\AI-Security\sqsp`). Todo el trabajo ocurre en este directorio:
**las muestras y resultados nunca salen de aquí ni se propagan por la PC.**

Las muestras son archivos **inertes**: PE32 de juguete con imports literales y
cadenas de texto con indicadores de malware. No contienen código ejecutable.

## Estructura de resultados

```
sqs_analysis_lab/
├── muestras/ (samples originales, inertes)
│   ├── game_crack.exe      -> malicioso (riesgo alto)
│   ├── game_loader.dll     -> malicioso
│   ├── miner.exe           -> malicioso
│   ├── game_helper.dll     -> sospechoso (decisión manual/manual)
│   └── activador.txt       -> sospechoso
├── salidas/
│   ├── temp_*/             -> entorno aislado por muestra
│   │   ├── quarantine/     -> ORIGINAL bloqueado (solo lectura)
│   │   ├── backup/         -> copia de seguridad del original
│   │   ├── sanitized_*.exe -> archivo limpio (parcheado)
│   │   └── *.json          -> reportes de las 7 capas
│   ├── final_package_*/    -> paquete final (limpiado y utilizable)
│   │   ├── complete_report.json
│   │   ├── README.md
│   │   └── sanitized_*.exe/.dll
│   └── summary_report.json -> resumen agregado de todo el laboratorio
├── generar_muestras.py     -> generador de muestras educativas
├── ejecutar_prueba.ps1     -> pipeline completo + verificación
├── auto_verify.py          -> verifica que todo se generó correctamente
└── sqs_run.cmd             -> lanzador de doble clic
```

## Uso rápido

```powershell
# Ejecución completa en un clic
sqs_run.cmd

# Ejecución completa desde PowerShell
powershell -ExecutionPolicy Bypass -File ejecutar_prueba.ps1

# Solo análisis (capas 1-4: veredicto, sin cirugía)
python C:\AI-Security\sqsp\sqs.py muestras\miner.exe --analyze

# Pipeline completo + forzar cirugía en sospechosos (sin preguntar)
python C:\AI-Security\sqsp\sqs.py muestras\game_helper.dll --surgery

# App gráfica interactiva (permite decidir bloqueo en zona ambiguo)
python C:\AI-Security\sqsp\sqs.py --app
```

## Análisis de riesgo (umbrales reales del pipeline)

| Riesgo | Zona | Acción |
|--------|------|--------|
| 0-4    | seguro     | Continúa sin cirugía |
| 5-9    | ambiguo    | CLI pregunta (riesgo >= 8) o `--surgery` fuerza |
| 10-14  | malicioso  | Cuarentena + cirugía automática (backup + NOP) |
| 15+    | malicioso  | Cirugía automática completa |

## Verificación automática

`auto_verify.py` comprueba que existan todos los artefactos (saneado, backup
de solo lectura, cuarentena, reportes de las 7 capas y `complete_report.json`)
y genera `salidas/summary_report.json`:

```json
{
  "pipeline": {
    "version": "1.0",
    "timestamp": "2026-09-04_182845",
    "total_samples": 5,
    "malicious_count": 3,
    "suspicious_count": 2,
    "clean_count": 0
  },
  "samples": [
    {
      "filename": "miner.exe",
      "status": "cleaned",
      "risk_level": 12,
      "actions_taken": ["backup", "NOP_patch"],
      "final_file": "sanitized_miner.exe"
    }
  ]
}
```

## Nota honesta

Las muestras son bytes inertes (no son aplicaciones Win32 reales), por eso el
sandbox reporta `WinError 193` y la "re-ejecución funcional" queda marcada
como `failed`: no pueden ejecutarse, lo cual es intencional. El flujo de
cuarentena, cirugía y empaquetado es idéntico al que se aplicaría a un
binario real.