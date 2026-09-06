"""
SQS - Capa 1: Análisis Estático de Paquetes (Estructura y Componentes).

Inventaría el contenido de un paquete o instalador y genera
`layer1_extracted_components.json` con los componentes detectados
(ejecutables, scripts, DLLs...). Cada componente incluye:
    - type:      'executable' | 'script' | 'installer' | 'other'
    - path:      ruta relativa al paquete
    - size:      tamaño en bytes
    - sha256:    hash SHA-256 del archivo (auditabilidad)
    - magic_type: tipo real por magic bytes (reutiliza layers/layer1)

Este módulo NO reemplaza ingestion_layer.py ni layers/layer1; es el sustrato
estático de inventario que consume el resto del pipeline.
"""

import hashlib
import json
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_THIS_DIR, "layers", "layer1"))

try:
    from file_type_detector import detect_file_type
except Exception:
    detect_file_type = None

_EXEC_EXTS = {".exe", ".dll", ".com", ".elf", ".so", ".bin", ".dylib"}
_SCRIPT_EXTS = {".py", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".sh"}
_INSTALLER_EXTS = {".msi", ".msix", ".appx", ".deb", ".rpm", ".apk", ".pkg"}


def sha256_file(path):
    """SHA-256 de un archivo (lectura por bloques para archivos grandes)."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def get_file_type(filename):
    """Clasifica por extensión: executable, script, installer u other."""
    ext = os.path.splitext(filename)[1].lower()
    if ext in _EXEC_EXTS:
        return "executable"
    if ext in _SCRIPT_EXTS:
        return "script"
    if ext in _INSTALLER_EXTS:
        return "installer"
    return "other"


def _magic_type(file_path):
    """Tipo real por magic bytes (PE/ELF/Mach-O/UNKNOWN) o None si no hay capa1."""
    if detect_file_type is None:
        return None
    try:
        return detect_file_type(file_path)
    except Exception:
        return None


def extract_components(package_path):
    """
    Inventaria los componentes del paquete y retorna una lista de dicts.

    Args:
        package_path (str): ruta a un directorio (recorre todo el árbol) o a
            un archivo único (instalador/ejecutable tratado como el paquete).

    Returns:
        list[dict]: cada componente con type, path, size, sha256 y magic_type.
    """
    components = []

    if os.path.isdir(package_path):
        for root, _, files in os.walk(package_path):
            for file in sorted(files):
                full = os.path.join(root, file)
                components.append({
                    "type": get_file_type(file),
                    "path": os.path.relpath(full, package_path)
                              .replace("\\", "/"),
                    "size": os.path.getsize(full),
                    "sha256": sha256_file(full),
                    "magic_type": _magic_type(full),
                })
    else:
        # Archivo único: el paquete ES ese archivo (msi, exe, etc.)
        components.append({
            "type": "installer",
            "path": os.path.basename(package_path),
            "size": os.path.getsize(package_path),
            "sha256": sha256_file(package_path),
            "magic_type": _magic_type(package_path),
        })

    return components


def save_components(components, output_file="layer1_extracted_components.json"):
    """Escribe el inventario en JSON (UTF-8, indentado)."""
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(components, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return output_file


def main():
    if len(sys.argv) != 2:
        print("Uso: python layer1_extractor.py <paquete|directorio>")
        sys.exit(1)

    components = extract_components(sys.argv[1])
    output = save_components(components)

    counts = {}
    for c in components:
        counts[c["type"]] = counts.get(c["type"], 0) + 1

    print(f"[+] {len(components)} componente(s) inventariados en {output}")
    for kind, n in sorted(counts.items()):
        print(f"    - {kind}: {n}")


if __name__ == "__main__":
    main()