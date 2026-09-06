"""
SQS - Capa 1: Ingesta y Aislamiento.

Recibe el archivo de entrada, calcula SHA-256 / tamaño / tipo real (magic
bytes), lo copia a una cuarentena de solo lectura, consulta su reputación
contra una base de hashes local (offline) y genera el manifest.json con el
inventario completo. No se opera sobre el original hasta el final del proceso.
"""

import json
import hashlib
import os
import shutil
import sys
from datetime import datetime

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(_THIS_DIR, "data")
KNOWN_HASHES_FILE = os.path.join(DATA_DIR, "known_hashes.json")


def load_known_hashes():
    """Carga la base local de hashes (benignos y maliciosos)."""
    try:
        with open(KNOWN_HASHES_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return {
            "known_benign": set(data.get("known_benign", [])),
            "known_malicious": set(data.get("known_malicious", [])),
        }
    except Exception:
        return {"known_benign": set(), "known_malicious": set()}


def check_hash_reputation(file_hash):
    """
    Consulta la reputación de un hash contra la base local.

    Returns:
        dict: {"status": "benign"|"malicious"|"unknown", "matched": ...}
    """
    known = load_known_hashes()
    if file_hash in known["known_benign"]:
        return {"status": "benign", "matched": "known_benign"}
    if file_hash in known["known_malicious"]:
        return {"status": "malicious", "matched": "known_malicious"}
    return {"status": "unknown", "matched": None}


def detect_magic_type(file_path):
    """Tipo real por magic bytes (reutiliza el detector de layer1)."""
    sys.path.insert(0, os.path.join(_THIS_DIR, "layers", "layer1"))
    try:
        from file_type_detector import detect_file_type
        return detect_file_type(file_path)
    except Exception:
        return "UNKNOWN"


def _set_readonly(path):
    """Marca un archivo como solo lectura (Windows y POSIX)."""
    try:
        os.chmod(path, os.stat(path).st_mode & ~0o222)
    except Exception:
        pass


def process_input_file(file_path, base_dir=None):
    """
    Procesa el archivo de entrada y crea el entorno aislado.

    Args:
        file_path (str): Ruta al archivo sospechoso.
        base_dir (str, opcional): Directorio base del entorno aislado.

    Returns:
        str: Ruta absoluta del directorio aislado.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Archivo no encontrado: {file_path}")

    # Fase 1.1 - Recepción: hash, tamaño y tipo real
    with open(file_path, 'rb') as f:
        raw = f.read()
    file_hash = hashlib.sha256(raw).hexdigest()
    size_bytes = len(raw)
    magic_type = detect_magic_type(file_path)

    reputation = check_hash_reputation(file_hash)

    # Fase 1.2 - Aislamiento: copia a cuarentena de solo lectura
    base_dir = base_dir or os.getcwd()
    temp_dir = os.path.join(
        base_dir, "temp_" + datetime.now().strftime("%Y%m%d_%H%M%S"))
    counter = 0
    while os.path.exists(temp_dir):
        counter += 1
        temp_dir = os.path.join(
            base_dir, f"temp_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{counter}")
    quarantine_dir = os.path.join(temp_dir, "quarantine")
    os.makedirs(quarantine_dir, exist_ok=True)

    quarantined_path = os.path.join(quarantine_dir, os.path.basename(file_path))
    shutil.copy2(file_path, quarantined_path)
    _set_readonly(quarantined_path)

    # Manifest: inventario completo con hashes, tamaños y tipos reales
    manifest = {
        "timestamp": datetime.now().isoformat(),
        "input_file": os.path.abspath(file_path),
        "size_bytes": size_bytes,
        "file_hash": file_hash,
        "magic_type": magic_type,
        "reputation": reputation,
        "quarantine": {
            "path": os.path.abspath(quarantined_path),
            "read_only": True,
        },
        "temp_directory": os.path.abspath(temp_dir),
        "status": "ingested",
    }

    with open(os.path.join(temp_dir, "manifest.json"), "w",
              encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    # Reporte de auditoría inicial (compatible con versiones anteriores)
    report = {
        "timestamp": datetime.now().isoformat(),
        "input_file": os.path.abspath(file_path),
        "file_hash": file_hash,
        "temp_directory": os.path.abspath(temp_dir),
        "status": "ingested",
    }

    with open(os.path.join(temp_dir, "report.json"), "w",
              encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return os.path.abspath(temp_dir)


def main():
    if len(sys.argv) < 2:
        print("Uso: python ingestion_layer.py <ruta_archivo> [directorio_base]")
        sys.exit(1)

    base_dir = sys.argv[2] if len(sys.argv) > 2 else None
    temp_dir = process_input_file(sys.argv[1], base_dir)
    print(f"[+] Ingesta completada. Entorno aislado creado: {temp_dir}")


if __name__ == "__main__":
    main()