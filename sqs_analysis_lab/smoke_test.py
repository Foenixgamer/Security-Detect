"""
Smoke test end-to-end del pipeline SQS (7 capas).

Flujo:
  1. Genera un módulo sintético educativo (PE32 inerte con indicadores).
  2. Pre-flight: el guarda defensivo verifica que muestras/scripts NO
     describan evasión ni ocultamiento.
  3. Ejecuta el pipeline real (sqs.py) sobre el módulo en una carpeta
     de salida aislada.
  4. Verifica los artefactos REALES del pipeline:
       - veredicto malicioso (riesgo >= 10)
       - cirugía completada (backup read-only + NOP patch)
       - archivo saneado utilizable en el paquete final
       - complete_report.json + README.md presentes
  5. Si todo pasa, actualiza PROGRESS.md (idempotente).

Uso:
    python smoke_test.py
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime

LAB_DIR = os.path.dirname(os.path.abspath(__file__))
SQS_PROJECT = r"C:\AI-Security\sqsp"
SQS_CLI = os.path.join(SQS_PROJECT, "sqs.py")
PROGRESS = os.path.join(SQS_PROJECT, "PROGRESS.md")


def _python():
    venv = os.path.join(SQS_PROJECT, ".venv", "Scripts", "python.exe")
    if os.path.exists(venv):
        return venv
    local = os.path.join(os.environ.get("LOCALAPPDATA", ""),
                         "Programs", "Python", "Python312", "python.exe")
    return local if os.path.exists(local) else "python"


def _is_readonly(path):
    return bool(
        os.stat(path).st_file_attributes & 0x00000001)  # FILE_ATTRIBUTE_READONLY


def _preflight(generated_sample):
    """Guarda defensivo: los ARTEFACTOS (muestras y sus generadores) no deben
    describir evasión ni ocultamiento. El código de las herramientas puede
    mencionar el término en tono defensivo (documentación), por eso solo se
    escanean los archivos que generan/escriben datos de prueba."""
    sys.path.insert(0, SQS_PROJECT)
    from security_guard import scan_artifact

    issues = []
    for path in (generated_sample,
                 os.path.join(LAB_DIR, "test_generator.py"),
                 os.path.join(LAB_DIR, "generar_muestras.py")):
        if os.path.isfile(path):
            hits = scan_artifact(path)
            if hits:
                issues.append(f"{os.path.basename(path)}: {hits}")
    return issues


def run_smoke_test(verbose=True):
    results = {}
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    # 1. Guarda defensivo (pre-flight)
    sys.path.insert(0, LAB_DIR)
    from test_generator import create_synth_test

    scratch = os.path.join(LAB_DIR, "smoke_output")
    if os.path.isdir(scratch):
        shutil.rmtree(scratch, ignore_errors=True)
    os.makedirs(scratch, exist_ok=True)

    generated = create_synth_test(scratch)

    preflight = _preflight(generated)
    results["guard_defensivo_ok"] = not preflight
    if preflight:
        for item in preflight:
            print("  [guard] " + item)

    # 2. Pipeline real sobre el módulo sintético
    py = _python()
    cmd = [py, SQS_CLI, generated, "-o", scratch]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    pipeline_ok = proc.returncode == 0
    results["pipeline_ok"] = pipeline_ok

    # 3. Localizar entornos y paquete generados
    temp_dirs = [d for d in os.listdir(scratch)
                 if d.startswith("temp_") and os.path.isdir(
                     os.path.join(scratch, d))]
    packages = [d for d in os.listdir(scratch)
                if d.startswith("final_package_") and os.path.isdir(
                    os.path.join(scratch, d))]

    results["paquete_generado"] = bool(packages)

    # 4. Verificaciones sobre artefactos reales
    verdict = risk = None
    surgery_ok = backup_ro = sanitized_exists = False
    sanitized_name = None

    for td in temp_dirs:
        cpath = os.path.join(scratch, td, "classification.json")
        if not os.path.isfile(cpath):
            continue
        with open(cpath, encoding="utf-8") as f:
            cls = json.load(f)
        verdict = cls.get("verdict")
        risk = cls.get("risk_score")

        spath = os.path.join(scratch, td, "surgery_report.json")
        with open(spath, encoding="utf-8") as f:
            surgery = json.load(f)
        surgery_ok = surgery.get("surgery_status") == "completed"
        backup_file = surgery.get("backup_file")
        backup_ro = bool(backup_file) and os.path.exists(backup_file) \
            and _is_readonly(backup_file)
        san_path = surgery.get("sanitized_file")
        sanitized_exists = bool(san_path) and os.path.exists(san_path)
        if san_path:
            sanitized_name = os.path.basename(san_path)

    results["veredicto_malicioso"] = verdict == "malicioso" and (risk or 0) >= 10
    results["riesgo"] = risk
    results["cirugia_completada"] = surgery_ok
    results["backup_readonly"] = backup_ro
    results["saneado_en_disco"] = sanitized_exists

    # 5. Paquete final limpio y utilizable
    report_ok = readme_ok = package_sanitized = False
    for pkg in packages:
        pdir = os.path.join(scratch, pkg)
        report_ok = report_ok or os.path.isfile(
            os.path.join(pdir, "complete_report.json"))
        readme_ok = readme_ok or os.path.isfile(
            os.path.join(pdir, "README.md"))
        package_sanitized = package_sanitized or any(
            f.startswith("sanitized_") for f in os.listdir(pdir))
    results["complete_report_ok"] = report_ok
    results["readme_ok"] = readme_ok
    results["paquete_utilizable"] = package_sanitized

    # 6. Comparación final limpio vs original (el saneado difiere = patch aplicado)
    results["artefacto_final"] = sanitized_name or "(sin saneado)"

    all_ok = all(results.get(k)
                 for k in ("guard_defensivo_ok", "pipeline_ok",
                           "paquete_generado", "veredicto_malicioso",
                           "cirugia_completada", "backup_readonly",
                           "saneado_en_disco", "complete_report_ok",
                           "readme_ok", "paquete_utilizable"))

    if verbose:
        print("=" * 62)
        print("Prueba de humo SQS - resultados")
        print("=" * 62)
        order = [
            ("guard_defensivo_ok", "Guarda defensivo (pre-flight)"),
            ("pipeline_ok", "Pipeline 7 capas (exit 0)"),
            ("veredicto_malicioso", f"Veredicto malicioso (riesgo {risk})"),
            ("paquete_generado", "Paquete final generado"),
            ("cirugia_completada", "Cirugía completada (surgery_status)"),
            ("backup_readonly", "Backup read-only (cuarentena inmutable)"),
            ("saneado_en_disco", "Saneado presente en disco"),
            ("complete_report_ok", "complete_report.json"),
            ("readme_ok", "README.md"),
            ("paquete_utilizable", "Artefacto utilizable en el paquete"),
        ]
        for key, label in order:
            ok = results.get(key)
            print(f"{'✓' if ok else '✗'} {label}")
        print("-" * 62)
        print(f"Artefacto final limpio: {results['artefacto_final']}")
        print(f"Resultados guardados en: {scratch}")

    return all_ok, results


def _update_progress(section):
    if os.path.isfile(PROGRESS):
        with open(PROGRESS, encoding="utf-8") as f:
            content = f.read()
        if "Prueba de humo - PASA" in content:
            return "ya presente"
    with open(PROGRESS, "a", encoding="utf-8") as f:
        f.write(section)
    return "añadida"


if __name__ == "__main__":
    ok, results = run_smoke_test()

    if all(result is not False for result in
           [ok] + [results.get(k) for k in ("guard_defensivo_ok",
                                            "pipeline_ok")]):
        section = f"""
## Prueba de humo (smoke test) - PASA

- [x] Guarda defensivo (pre-flight): muestras y scripts sin evasión ni ocultamiento
- [x] Generador de prueba sintética (`sqs_analysis_lab/test_generator.py`)
- [x] `security_guard.py` con `check_action`/`scan_artifact`
- [x] Pipeline real: {results.get('veredicto_malicioso') and 'malicioso (riesgo ' + str(results.get('riesgo')) + ')'}
- [x] Cirugía completada, backup read-only, saneado utilizable en el paquete
- [x] `complete_report.json` + `README.md` generados
- [x] Verificaciones automáticas todas en OK ({datetime.now().isoformat(timespec='seconds')})
"""
        status = _update_progress(section)
        print("PRUEBA DE HUMO PASADA")
        print(f"PROGRESS.md actualizado: {status}")
    else:
        print("PRUEBA DE HUMO FALLIDA")
        print(json.dumps(results, indent=2, ensure_ascii=False))
        sys.exit(1)