"""
SQS - Capa 5: Cirugía / Saneamiento.

Si el veredicto es "malicioso" (o la decisión del usuario fuerza la cirugía en
zona AMBIGUO):
  1. Crea un backup inmutable (solo lectura) del original.
  2. Aplica parches binarios (NOP) en los offsets marcados por verdict_map.
  3. Registra cada cambio con el diff exacto en surgery_log.json.
Si no se requiere, registra el estado "not_needed" para continuar el pipeline.
"""

import json
import os
import shutil
from datetime import datetime

PATCH_BYTE = 0x90  # NOP (x86)


def _set_readonly(path):
    # Quita los bits de escritura (Windows: activa FILE_ATTRIBUTE_READONLY;
    # POSIX: elimina w para owner/group/other).
    try:
        os.chmod(path, os.stat(path).st_mode & ~0o222)
    except Exception:
        pass


def _load_json_safe(path):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def sanitize_file(file_path, temp_dir="."):
    """
    Ejecuta el saneamiento del archivo malicioso.

    Args:
        file_path (str): Ruta al archivo original.
        temp_dir (str): Directorio del entorno aislado.

    Returns:
        dict: Reporte de cirugía.
    """
    classification = _load_json_safe(os.path.join(temp_dir, "classification.json"))
    verdict_map = _load_json_safe(os.path.join(temp_dir, "verdict_map.json"))

    verdict = verdict_map.get("verdict") or classification.get("verdict")
    zone = verdict_map.get("zone")
    decision = verdict_map.get("decision")  # "fuerza_cirugia" posible

    needs_surgery = (zone == "malicioso" or decision == "fuerza_cirugia")

    if not needs_surgery:
        report = {
            "timestamp": datetime.now().isoformat(),
            "original_file": os.path.abspath(file_path),
            "sanitized_file": None,
            "backup_file": None,
            "actions_taken": [],
            "surgery_status": "not_needed",
            "classification": classification,
        }

        with open(os.path.join(temp_dir, "surgery_report.json"), "w",
                  encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        return report

    # Fase 5.1 - Backup inmutable del original
    backup_dir = os.path.join(temp_dir, "backup")
    os.makedirs(backup_dir, exist_ok=True)
    backup_file = os.path.join(backup_dir, os.path.basename(file_path))
    shutil.copy2(file_path, backup_file)
    _set_readonly(backup_file)

    # Fase 5.3 - Parcheo binario (NOP) de los offsets marcados
    with open(file_path, 'rb') as f:
        original = bytearray(f.read())

    sanitized = bytearray(original)
    patches = []

    for action in verdict_map.get("actions", []) or []:
        if action.get("type") != "patch":
            continue
        offset = action.get("offset")
        size = action.get("size", 0) or 0
        if offset is None or offset < 0 or offset >= len(original):
            continue
        size = max(size, 1)
        end = min(offset + size, len(original))
        original_hex = bytes(original[offset:end]).hex()
        for i in range(offset, end):
            sanitized[i] = PATCH_BYTE
        patches.append({
            "offset": offset,
            "size": end - offset,
            "original_hex": original_hex,
            "new_hex": bytes(sanitized[offset:end]).hex(),
            "type": "nop_patch",
            "note": action.get("note", ""),
            "string": action.get("string", ""),
        })

    # Fase 5.4 - Archivo saneado (reempaquetado a nivel de bytes)
    sanitized_path = os.path.join(temp_dir,
                                  "sanitized_" + os.path.basename(file_path))
    with open(sanitized_path, 'wb') as f:
        f.write(bytes(sanitized))

    actions_taken = []
    if os.path.exists(backup_file):
        actions_taken.append(f"Backup inmutable creado: {backup_file}")
    if patches:
        actions_taken.append(
            f"NOP aplicado en {len(patches)} offset(s) (difusión en surgery_log)")
    else:
        actions_taken.append("Copia del archivo original para saneamiento")

    # Fase 5.4 - Registro de cirugía con diff exacto
    surgery_log = {
        "timestamp": datetime.now().isoformat(),
        "original_file": os.path.abspath(file_path),
        "backup_file": os.path.abspath(backup_file),
        "sanitized_file": os.path.abspath(sanitized_path),
        "patches": patches,
        "removed_components": [
            {"id": c.get("id"), "name": c.get("name"),
             "note": "componente independiente a excluir en el reempaquetado"}
            for c in (verdict_map.get("components", []) or [])
            if c.get("action") == "remove"
        ],
        "surgery_status": "completed",
    }

    with open(os.path.join(temp_dir, "surgery_log.json"), "w",
              encoding="utf-8") as f:
        json.dump(surgery_log, f, indent=2)

    report = {
        "timestamp": datetime.now().isoformat(),
        "original_file": os.path.abspath(file_path),
        "sanitized_file": os.path.abspath(sanitized_path),
        "backup_file": os.path.abspath(backup_file),
        "actions_taken": actions_taken,
        "surgery_status": "completed",
        "classification": classification,
    }

    with open(os.path.join(temp_dir, "surgery_report.json"), "w",
              encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return report


def main():
    import sys
    if len(sys.argv) != 2:
        print("Uso: python surgery_layer.py <ruta_archivo>")
        sys.exit(1)

    temp_dir = os.getenv("TEMP_DIR", ".")
    report = sanitize_file(sys.argv[1], temp_dir)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()