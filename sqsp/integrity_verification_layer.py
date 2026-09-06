"""
SQS - Capa 6: Verificación de Integridad Funcional.

Confirma que el archivo saneado funciona correctamente:
  1. Re-ejecución en sandbox del archivo saneado (rerun_dynamic_report.json).
  2. Comparación de comportamiento contra el análisis dinámico original.
  3. Prueba de arranque básico y reporte final (final_report.json) con riesgo
     de pérdida funcional.
"""

import json
import hashlib
import os
import time
from datetime import datetime

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in __import__("sys").path:
    __import__("sys").path.insert(0, _THIS_DIR)

from dynamic_analysis_layer import run_in_sandbox


def _sha256(file_path):
    with open(file_path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def _load_json_safe(path):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def verify_integrity(file_path, temp_dir=".", timeout=10):
    """
    Verifica la integridad funcional del archivo saneado.

    Args:
        file_path (str): Ruta al archivo original.
        temp_dir (str): Directorio del entorno aislado.
        timeout (int): Límite de ejecución de la re-ejecución.

    Returns:
        dict: Reporte de verificación.
    """
    classification = _load_json_safe(os.path.join(temp_dir, "classification.json"))
    surgery = _load_json_safe(os.path.join(temp_dir, "surgery_report.json"))

    original_hash = ""
    try:
        original_hash = _sha256(file_path)
    except Exception as e:
        print(f"Error calculando hash del original: {e}")

    sanitized_path = surgery.get("sanitized_file")
    sanitized_hash = None
    if sanitized_path and os.path.exists(sanitized_path):
        try:
            sanitized_hash = _sha256(sanitized_path)
        except Exception as e:
            print(f"Error calculando hash del saneado: {e}")

    verification_results = {
        "timestamp": datetime.now().isoformat(),
        "original_file_hash": original_hash,
        "sanitized_file_path": sanitized_path,
        "sanitized_file_hash": sanitized_hash,
        "verification_status": "passed",
        "functional_tests": [],
        "rerun_dynamic_report": None,
        "differences_detected": sanitized_hash != original_hash,
        "compatibility_report": {},
    }

    start = time.monotonic()

    if not sanitized_path or not os.path.exists(sanitized_path):
        verification_results["verification_status"] = "skipped"
        verification_results["note"] = (
            "No hay archivo saneado que verificar (el veredicto no lo requirió "
            "o la cirugía no generó copia).")
    else:
        # Fase 6.1 - Re-ejecución del saneado en sandbox
        rerun = run_in_sandbox(sanitized_path, temp_dir, timeout=timeout,
                               report_name="rerun_dynamic_report.json")
        verification_results["rerun_dynamic_report"] = (
            os.path.join(temp_dir, "rerun_dynamic_report.json"))

        log = rerun.get("execution_log", []) or []
        last = log[-1] if log else None
        duration = last["duration_seconds"] if last else round(
            time.monotonic() - start, 3)
        output = ""
        if last:
            output = (last.get("stdout") or last.get("stderr") or "")
            if len(output) > 200:
                output = output[:200] + "..."

        if rerun.get("error"):
            status = "failed"
            reason = rerun["error"]
            return_code = None
        elif last and last.get("return_code") == 0:
            status = "passed"
            reason = "ejecución exitosa"
            return_code = 0
        else:
            status = "failed"
            reason = "código de retorno no nulo o sin ejecución"
            return_code = (last or {}).get("return_code")

        verification_results["functional_tests"].append({
            "test_name": "RerunInSandbox",
            "status": status,
            "return_code": return_code,
            "output": output or reason,
            "duration_seconds": round(duration, 3),
            "reason": reason,
        })

        # Fase 6.1b - Confirmar ausencia del comportamiento malicioso
        original_dynamic = _load_json_safe(os.path.join(temp_dir,
                                                        "dynamic_report.json"))
        original_error = bool(original_dynamic.get("error"))
        rerun_error = bool(rerun.get("error"))
        verification_results["malicious_behavior_removed"] = (
            original_error and not rerun_error)

        if any(t["status"] == "failed"
               for t in verification_results["functional_tests"]):
            verification_results["verification_status"] = "failed"

    # Fase 6.3 - Reporte final legible
    verdict = classification.get("verdict", "desconocido")
    zone = classification.get("zone", "desconocido")
    risk = classification.get("risk_score", 0)
    v_status = verification_results["verification_status"]

    if v_status == "passed":
        loss_risk = "baja"
    elif v_status == "skipped":
        loss_risk = "baja"
    else:
        loss_risk = "alta"

    summary = [
        f"Archivo original: {os.path.abspath(file_path)}",
        f"Veredicto: {verdict} (zona {zone}, riesgo {risk})",
        f"Estado de cirugía: {surgery.get('surgery_status', 'n/a')}",
        f"Verificación funcional: {v_status}",
        f"Riesgo de pérdida funcional: {loss_risk}",
    ]
    if verification_results.get("malicious_behavior_removed"):
        summary.append("Comportamiento malicioso confirmado como removido "
                       "en la re-ejecución.")

    final_report = {
        "timestamp": datetime.now().isoformat(),
        "input_file": os.path.abspath(file_path),
        "temp_directory": temp_dir,
        "verdict": verdict,
        "zone": zone,
        "risk_score": risk,
        "surgery_status": surgery.get("surgery_status"),
        "verification_status": v_status,
        "malicious_behavior_removed":
            verification_results.get("malicious_behavior_removed"),
        "functionality_loss_risk": loss_risk,
        "summary": summary,
    }

    with open(os.path.join(temp_dir, "integrity_verification.json"), "w",
              encoding="utf-8") as f:
        json.dump(verification_results, f, indent=2)

    with open(os.path.join(temp_dir, "final_report.json"), "w",
              encoding="utf-8") as f:
        json.dump(final_report, f, indent=2)

    return verification_results


def main():
    import sys
    if len(sys.argv) != 2:
        print("Uso: python integrity_verification_layer.py <ruta_archivo>")
        sys.exit(1)

    temp_dir = os.getenv("TEMP_DIR", ".")
    report = verify_integrity(sys.argv[1], temp_dir)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()