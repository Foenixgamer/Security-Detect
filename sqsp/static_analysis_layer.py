"""
SQS - Capa 2: Análisis Estático.

Inspecciona el binario sin ejecutarlo: tipo real, arquitectura, secciones,
entropía (detección de empaquetado/cifrado), strings legibles, imports de PE,
instaladores/empaquetadores y candidatos a binarios embebidos. Genera un
puntaje de sospecha POR COMPONENTE (no por archivo completo).
"""

import glob
import json
import os
import struct
import sys
from datetime import datetime

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_THIS_DIR, 'layers', 'layer1'))

from file_type_detector import detect_file_type
from header_analyzer import analyze_pe_header, analyze_elf_header
from section_extractor import extract_sections
from strings_analyzer import (
    extract_strings, suspicious_strings, entropy,
    entropy_by_block, entropy_by_sections, file_entropy,
)
from imports_analyzer import extract_pe_imports, suspicious_imports

_MACHINE_NAMES = {
    0x14c: "x86 (i386)",
    0x8664: "x86-64 (AMD64)",
    0x1c0: "ARM",
    0x1c4: "ARMv7",
    0xaa64: "ARM64 (AArch64)",
    0x3e: "x86-64 (AMD64)",
    0x28: "ARM",
    0xb7: "AArch64 (ARM64)",
    0x02: "SPARC",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x16: "PowerPC64",
}

_MIME_BY_MAGIC = {
    "PE": "application/x-dosexec",
    "ELF": "application/x-executable",
    "Mach-O": "application/x-mach-binary",
}

_MIME_BY_EXT = {
    ".py": "text/x-python",
    ".sh": "text/x-shellscript",
    ".bat": "text/x-batch",
    ".cmd": "text/x-batch",
    ".ps1": "text/x-powershell",
    ".exe": "application/x-dosexec",
    ".dll": "application/x-msdownload",
    ".so": "application/x-sharedlib",
    ".dylib": "application/x-mach-binary",
    ".html": "text/html",
    ".json": "application/json",
    ".txt": "text/plain",
    ".md": "text/plain",
}

_INSTALLER_MARKERS = [
    (b"NullsoftInst", "NSIS (Nullsoft Installer)"),
    (b"Inno Setup", "Inno Setup"),
    (b"InnoCfg", "Inno Setup"),
    (b"UPX!", "UPX (empaquetado ejecutable)"),
]

# Entropía por encima de la cual se considera bloque empacado/cifrado
HIGH_ENTROPY_THRESHOLD = 7.5

_RULES_DIR = os.path.join(_THIS_DIR, "rules")


def _enrich_pefile(data):
    """Enriquecimiento opcional con pefile (si el paquete está instalado)."""
    try:
        import pefile
    except ImportError:
        return None, None

    try:
        pe = pefile.PE(data=data, fast_load=False)
        sections = []
        for s in pe.sections:
            name = (s.Name or b"").rstrip(b"\x00")
            try:
                name = name.decode("utf-8", errors="replace")
            except Exception:
                name = "?"
            sections.append({
                "name": name,
                "virtual_address": int(s.VirtualAddress),
                "virtual_size": int(s.Misc_VirtualSize),
                "entropy": round(s.get_entropy(), 3),
            })

        imports = set()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", None) or []:
            try:
                imports.add(entry.dll.decode("utf-8", errors="replace"))
            except Exception:
                continue

        data_dirs = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", None)
        has_security = False
        try:
            has_security = bool(data_dirs and data_dirs[4].VirtualAddress)
        except Exception:
            has_security = False

        return {
            "machine": hex(int(pe.FILE_HEADER.Machine)),
            "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
            "dll_characteristics": hex(
                int(getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0))),
            "sections": sections,
            "imports": sorted(imports),
            "has_security_directory": has_security,
        }, None
    except Exception as e:
        return None, str(e)


def _scan_yara(data):
    """Escaneo opcional con yara-python sobre rules/*.yara."""
    try:
        import yara
    except ImportError:
        return None, None

    files = sorted(glob.glob(os.path.join(_RULES_DIR, "*.yara")))
    if not files:
        return [], None

    try:
        compiled = yara.compile(filepaths={
            os.path.basename(p): p for p in files})
        matches = compiled.match(data=data)
        return [m.rule for m in matches], None
    except Exception as e:
        return None, str(e)


def _guess_mime(file_path):
    """Estima el MIME usando magic bytes (layer1) y, como respaldo, extensión."""
    ftype = "UNKNOWN"
    try:
        ftype = detect_file_type(file_path)
    except Exception:
        pass

    if ftype in _MIME_BY_MAGIC:
        return _MIME_BY_MAGIC[ftype], ftype

    ext = os.path.splitext(file_path)[1].lower()
    return _MIME_BY_EXT.get(ext, "application/octet-stream"), ftype


def _analyze_signature(file_path):
    """Firma, arquitectura y secciones usando layer1."""
    info = {
        "file_signature": "unknown",
        "architecture": "unknown",
        "compiled_with": "unknown",
        "sections": [],
    }
    try:
        ftype = detect_file_type(file_path)
        info["file_signature"] = ftype

        if ftype == "PE":
            pe = analyze_pe_header(file_path)
            info["architecture"] = _MACHINE_NAMES.get(
                int(pe["machine"], 16), pe["machine"])
            info["compiled_with"] = ("PE32+" if
                                     pe["size_of_optional_header"] == 240
                                     else "PE32")
            info["sections"] = extract_sections(file_path, "PE")

        elif ftype == "ELF":
            elf = analyze_elf_header(file_path)
            info["architecture"] = _MACHINE_NAMES.get(
                int(elf["machine"], 16), elf["machine"])
            info["compiled_with"] = "GNU toolchain (asumido)"
            info["sections"] = extract_sections(file_path, "ELF")
    except Exception:
        pass
    return info


def _find_embedded_pe(data, limit=20):
    """Busca binarios PE embebidos (MZ + e_lfanew válido dentro del archivo)."""
    candidates = []
    start = 0
    for _ in range(limit * 2):
        idx = data.find(b'MZ', start)
        if idx == -1 or idx + 0x40 + 4 >= len(data):
            break
        start = idx + 1

        if idx == 0:
            # El MZ en offset 0 es el encabezado principal del propio archivo,
            # no un PE embebido.
            continue

        pe_offset = struct.unpack_from('<I', data, idx + 0x3C)[0]
        if not (0x40 <= pe_offset < 0x2000):
            continue
        if idx + pe_offset + 4 <= len(data) and \
                data[idx + pe_offset:idx + pe_offset + 4] == b'PE\x00\x00':
            candidates.append({
                "offset": idx,
                "hint": pe_offset,
            })
            if len(candidates) >= limit:
                break
    return candidates


def _detect_packers(data):
    """Detecta instaladores/empaquetadores por marcadores."""
    found = []
    if data[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
        found.append("MSI / Archivo compuesto OLE (D0CF11E0)")
    for marker, label in _INSTALLER_MARKERS:
        if marker in data:
            found.append(label)
    return found


def _component_score(is_exec, entropy_value, suspicious_hits, bad_imports,
                     packer_hits, reasons):
    """Puntaje heurístico de sospecha del componente (0..10)."""
    score = 0
    if is_exec:
        score += 1
        reasons.append("es ejecutable")
    if entropy_value >= HIGH_ENTROPY_THRESHOLD:
        score += 3
        reasons.append("alta entropía (posible empaquetado/cifrado)")
    if suspicious_hits:
        score += 2
        reasons.append(f"{suspicious_hits} string(s) sospechosos")
    if bad_imports:
        score += 2
        reasons.append(f"{bad_imports} import(s) sospechosos")
    if packer_hits:
        score += 1
        reasons.append("empaquetador/instalador detectado")
    return min(score, 10)


def analyze_static(file_path, temp_dir="."):
    """
    Genera el reporte estático con análisis por componente.

    Args:
        file_path (str): Ruta al archivo.
        temp_dir (str): Directorio del entorno aislado.

    Returns:
        dict: Reporte estático.
    """
    file_stats = os.stat(file_path)
    mime_type, _ = _guess_mime(file_path)

    is_executable = bool(file_stats.st_mode & 0o111) or mime_type in (
        "application/x-executable", "application/x-dosexec") or \
        mime_type.startswith("application/x-")

    signature = _analyze_signature(file_path)

    with open(file_path, 'rb') as f:
        data = f.read()

    # Strings, entropías, imports y empaquetadores
    strings = extract_strings(file_path, max_count=500)
    suspicious = suspicious_strings(strings)
    whole_entropy = entropy(data)
    section_entropy = entropy_by_sections(file_path, signature["sections"])
    high_entropy_sections = [
        s["name"] for s in section_entropy
        if s["entropy"] >= HIGH_ENTROPY_THRESHOLD
    ]
    max_block_entropy = max(
        (b["entropy"] for b in entropy_by_block(file_path)),
        default=0.0,
    )

    imports = []
    bad_imports = []
    if signature["file_signature"] == "PE":
        imports = extract_pe_imports(file_path)
        bad_imports = suspicious_imports(imports)

    packers = _detect_packers(data)
    embedded = _find_embedded_pe(data)

    pefile_info, pefile_error = _enrich_pefile(data)
    yara_matches, yara_error = _scan_yara(data)

    extra = {
        "entropy": whole_entropy,
        "max_block_entropy": max_block_entropy,
        "entropy_by_section": section_entropy,
        "high_entropy_sections": high_entropy_sections,
        "strings_count": len(strings),
        "top_strings": [s["string"] for s in strings[:50]],
        "suspicious_strings_found": suspicious,
        "imports": imports,
        "suspicious_imports": bad_imports,
        "packer_detected": packers,
        "embedded_pe_candidates": embedded,
        "pefile": pefile_info,
        "pefile_error": pefile_error,
        "yara_matches": yara_matches or [],
        "yara_error": yara_error,
    }
    signature.update(extra)

    # Inventario de componentes con puntaje de sospecha individual
    main_reasons = []
    main_score = _component_score(
        is_executable, whole_entropy,
        len(suspicious), len(bad_imports), len(packers), main_reasons)

    components = [{
        "id": "main",
        "name": os.path.basename(file_path),
        "kind": signature["file_signature"] or "UNKNOWN",
        "offset": 0,
        "size": file_stats.st_size,
        "entropy": whole_entropy,
        "suspicion_score": main_score,
        "reasons": main_reasons,
    }]

    for i, cand in enumerate(embedded):
        off = cand["offset"]
        chunk = data[off:off + 0x400]
        comp_reasons = ["binario PE embebido"]
        comp_score = _component_score(True, entropy(chunk), 0, 0, 0,
                                      comp_reasons)
        components.append({
            "id": f"embedded_{i}",
            "name": f"[PE embebido @ offset {off}]",
            "kind": "embedded_pe",
            "offset": off,
            "size": min(len(chunk), 0x400),
            "entropy": entropy(chunk),
            "suspicion_score": comp_score,
            "reasons": comp_reasons,
        })

    report = {
        "timestamp": datetime.now().isoformat(),
        "file_path": os.path.abspath(file_path),
        "mime_type": mime_type,
        "size_bytes": file_stats.st_size,
        "is_executable": is_executable,
        "permissions": oct(file_stats.st_mode)[-3:],
        "static_analysis": signature,
        "components": components,
    }

    os.makedirs(temp_dir, exist_ok=True)
    with open(os.path.join(temp_dir, "static_analysis.json"), "w",
              encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    return report


def main():
    if len(sys.argv) != 2:
        print("Uso: python static_analysis_layer.py <ruta_archivo>")
        sys.exit(1)

    temp_dir = os.getenv("TEMP_DIR", ".")
    report = analyze_static(sys.argv[1], temp_dir)
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()