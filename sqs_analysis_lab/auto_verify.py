"""
Verificación automática del laboratorio SQS.

1. Comprueba que todos los artefactos esperados existan (saneado, backup,
   cuarentena, reportes, paquete final) y lo imprime con marcas ✓/✗.
2. Genera `summary_report.json` con el estado agregado de todas las muestras.

Uso:
    python auto_verify.py [directorio_de_salidas]
Por defecto usa ./salidas
"""

import json
import os
import sys
from datetime import datetime


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _readable_case(location):
    """True si el path o alguno de sus ancestros es de solo lectura."""
    current = location
    while current and os.path.dirname(current) != current:
        attr = os.stat(current).st_file_attributes
        if attr & 0x00000001:  # FILE_ATTRIBUTE_READONLY
            return True
        current = os.path.dirname(current)
    return False


def _actions_taken(surgery):
    raw = surgery.get("actions_taken") or []
    joined = "|".join(raw).lower()
    labels = []
    if "backup" in joined:
        labels.append("backup")
    if "nop" in joined:
        labels.append("NOP_patch")
    if surgery.get("surgery_status") == "not_needed":
        labels.append("no requerida")
    return labels or ["ninguna"]


def gather(salidas_dir):
    samples = []
    temp_dirs = sorted(
        d for d in os.listdir(salidas_dir)
        if d.startswith("temp_") and os.path.isdir(
            os.path.join(salidas_dir, d)))

    for name in temp_dirs:
        td = os.path.join(salidas_dir, name)
        manifest = _load(os.path.join(td, "manifest.json"))
        classification = _load(os.path.join(td, "classification.json"))
        surgery = _load(os.path.join(td, "surgery_report.json"))

        filename = os.path.basename(manifest.get("input_file") or name)
        verdict = classification.get("verdict", "desconocido")
        zone = classification.get("zone", "?")
        risk = classification.get("risk_score") or 0
        status = classification.get("verdict", "desconocido")
        final_file = None
        sanitized_exists = False
        if surgery.get("sanitized_file"):
            final_file = os.path.basename(surgery["sanitized_file"])
            sanitized_exists = (
                surgery["sanitized_file"] and
                os.path.exists(surgery["sanitized_file"]))
            if status == "malicioso" and sanitized_exists:
                status = "cleaned"
            elif status == "malicioso":
                status = "quarantined"

        quarantine = manifest.get("quarantine", {}).get("path")
        backup_file = surgery.get("backup_file")
        samples.append({
            "filename": filename,
            "status": status,
            "risk_level": risk,
            "zone": zone,
            "actions_taken": _actions_taken(surgery),
            "final_file": final_file,
            "checks": {
                "sanitized_exists": sanitized_exists,
                "backup_exists": bool(backup_file) and os.path.exists(backup_file),
                "quarantine_exists": bool(quarantine) and os.path.exists(quarantine),
                "backup_read_only": bool(backup_file)
                and os.path.exists(backup_file) and _readable_case(backup_file),
                "classification_json": os.path.exists(
                    os.path.join(td, "classification.json")),
                "final_report_json": os.path.exists(
                    os.path.join(td, "final_report.json")),
                "surgery_report_json": os.path.exists(
                    os.path.join(td, "surgery_report.json")),
                "integrity_verification_json": os.path.exists(
                    os.path.join(td, "integrity_verification.json")),
            },
        })

    return samples, temp_dirs


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    salidas_dir = sys.argv[1] if len(sys.argv) > 1 else "salidas"
    if not os.path.isdir(salidas_dir):
        print(f"Error: no existe {salidas_dir}")
        return 1

    samples, _ = gather(salidas_dir)
    if not samples:
        print("No hay resultados de análisis en esta carpeta.")
        print("Ejecuta primero:  generar_muestras.py + sqs.py (o el .cmd).")
        return 1

    malicious = [s for s in samples if s["status"] in ("cleaned",
                                                       "quarantined")]
    suspicious = [s for s in samples if s["status"] == "sospechoso"]
    clean = [s for s in samples if s["status"] == "seguro"]

    summary = {
        "pipeline": {
            "version": "1.0",
            "timestamp": datetime.now().strftime("%Y-%m-%d_%H%M%S"),
            "total_samples": len(samples),
            "malicious_count": len(malicious),
            "suspicious_count": len(suspicious),
            "clean_count": len(clean),
        },
        "samples": [{
            "filename": s["filename"],
            "status": s["status"],
            "risk_level": s["risk_level"],
            "actions_taken": s["actions_taken"],
            "final_file": s["final_file"],
            "checks": s["checks"],
        } for s in samples],
    }
    with open(os.path.join(salidas_dir, "summary_report.json"), "w",
              encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # Reporte legible
    print("=" * 62)
    print("Verificación automática del laboratorio SQS")
    print("=" * 62)
    all_ok = True
    for s in samples:
        ok = all(s["checks"].values()) if s["status"] == "cleaned" else True
        all_ok = all_ok and ok
        mark = "OK " if ok else "FALTA"
        print(f"{'✓' if ok else '✗'} [{mark}] {s['filename']:<20} "
              f"{s['status']:<12} riesgo={s['risk_level']:<3} "
              f"final={s['final_file'] or '-'}")
        if not ok:
            for check, passed in s["checks"].items():
                if not passed:
                    print(f"      falta: {check}")

    # Comprobación del paquete final
    packages = sorted(
        d for d in os.listdir(salidas_dir)
        if d.startswith("final_package_") and os.path.isdir(
            os.path.join(salidas_dir, d)))
    print("-" * 62)
    for pkg in packages:
        pkg_dir = os.path.join(salidas_dir, pkg)
        files = os.listdir(pkg_dir)
        for expected in ("complete_report.json", "README.md"):
            present = expected in files
            all_ok = all_ok and present
            print(f"{'✓' if present else '✗'} {pkg}/{expected}")
        for fname in files:
            if fname.startswith("sanitized_"):
                print(f"   utilizable -> {pkg}/{fname}")

    print("-" * 62)
    resumen = (f"{summary['pipeline']['total_samples']} muestras | "
               f"{summary['pipeline']['malicious_count']} maliciosas | "
               f"{summary['pipeline']['suspicious_count']} sospechosas | "
               f"{summary['pipeline']['clean_count']} limpias")
    print(resumen)
    if all_ok:
        print("✓ Todo verificado correctamente. "
              "Resultado en summary_report.json")
    else:
        print("✗ Faltan artefactos, revisa la lista anterior.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())