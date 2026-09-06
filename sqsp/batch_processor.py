"""
SQS - Procesamiento por lotes (archivo único, directorio o ISO).

Extiende la entrada del pipeline de 7 capas (sqs.run_pipeline) para aceptar:
    - archivo único          -> se analiza igual que antes
    - directorio             -> se recorren los archivos de interés
    - archivo ISO            -> se extrae (best-effort con 7z/bsdtar) y se
                                analiza su contenido

No duplica las Capas 5/6: cada archivo pasa por el pipeline REAL existente
(surgery_layer + integrity_verification_layer). La ISO necesita 7-Zip o
bsdtar; si no hay extractor disponible, la entrada se marca como error y el
lote continúa.

Uso:
    python batch_processor.py ENT1 [ENT2 ...] [-o DIR] [--surgery]
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

TARGET_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".ocx", ".scr", ".com", ".cpl",
    ".bat", ".cmd", ".vbs", ".ps1", ".py", ".js",
}

# Archivos contenedores: se expanden y se analiza su contenido.
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".7z", ".rar", ".iso"}

_EXTRACTOR_EXE = None


def is_archive(path):
    """True si la extensión corresponde a un contenedor a expandir."""
    return os.path.splitext(str(path))[1].lower() in ARCHIVE_EXTENSIONS


def _find_extractor():
    """Localiza un extractor de ISO (7z/7za o bsdtar/tar) una sola vez."""
    global _EXTRACTOR_EXE
    if _EXTRACTOR_EXE is not None:
        return _EXTRACTOR_EXE
    for name in ("7z", "7za", "bsdtar", "tar"):
        exe = shutil.which(name)
        if exe:
            _EXTRACTOR_EXE = exe
            return exe
    _EXTRACTOR_EXE = ""
    return ""


def is_target_file(path):
    """True si la extensión del archivo es de interés para el lote."""
    return os.path.splitext(str(path))[1].lower() in TARGET_EXTENSIONS


def extract_iso(iso_path, dest_dir):
    """
    Extrae un ISO a dest_dir (best-effort con 7-Zip o bsdtar).

    Returns:
        bool: True si se extrajo contenido.

    Raises:
        RuntimeError: si no hay extractor disponible.
    """
    os.makedirs(dest_dir, exist_ok=True)
    exe = _find_extractor()
    if not exe:
        raise RuntimeError(
            "No hay extractor de ISO (instala 7-Zip o usa 'tar'). "
            "Lista: 7z/7za/bsdtar/tar")
    base = os.path.basename(exe).lower()
    if "7z" in base or "7za" in base:
        cmd = [exe, "x", str(iso_path), f"-o{dest_dir}", "-y"]
    else:
        cmd = [exe, "-xf", str(iso_path), "-C", dest_dir]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(f"No se pudo extraer ISO: {e}")
    if proc.returncode != 0 or not os.listdir(dest_dir):
        raise RuntimeError(
            f"No se pudo extraer ISO con {exe}: "
            f"{proc.stderr.decode(errors='replace').strip()[:200]}")
    return True


def resolve_inputs(input_paths):
    """
    Convierte entradas (archivos/dirs/ISO/archivos) en la lista concreta de
    archivos a analizar. Los contenedores (ISO, ZIP, 7z, RAR, TAR) se extraen
    a un temporal que se elimina al terminar el lote (NO se devuelven; se
    analizan inline por process_batch vía un generador interno).

    Returns:
        list: rutas de archivos concretos (incluye los contenedores, que
        process_batch reconoce y expande).
    """
    files = []
    for item in input_paths:
        path = os.path.abspath(item)
        if os.path.isdir(path):
            for root, _dirs, names in os.walk(path):
                for name in sorted(names):
                    full = os.path.join(root, name)
                    if is_target_file(full) or is_archive(full):
                        files.append(full)
        elif os.path.isfile(path):
            # contenedores y archivos normales se conservan; el lote expande
            # los contenedores y analiza los archivos de interés
            files.append(path)
        else:
            # ruta inexistente -> se conserva para registrar el error en lote
            files.append(path)
    return files


def _safe_extract_zip(zip_path, dest_dir):
    """Descomprime un ZIP evitando escrituras fuera del destino."""
    import zipfile
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or ".." in name.split("/"):
                continue
            target = os.path.join(dest_dir, name)
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with z.open(info) as src, open(target, "wb") as dst:
                for chunk in iter(lambda: src.read(1 << 16), b""):
                    dst.write(chunk)
    return True


def _safe_extract_tar(tar_path, dest_dir):
    """Desempaqueta un TAR evitando rutas peligrosas."""
    import tarfile
    with tarfile.open(tar_path) as t:
        for member in t.getmembers():
            if member.name.startswith("/") or ".." in member.name.split("/"):
                continue
            t.extract(member, dest_dir)
    return True


def _iter_archive_targets(archive, scratch_parent):
    """
    Extrae un contenedor (ISO/ZIP/TAR/7z/RAR) y recorre sus blancos.

    Nivel único (no recursivo): los archivos de destino que a su vez sean
    contenedores no se vuelven a expandir.

    Returns:
        tuple: (dest_dir, targets)

    Raises:
        RuntimeError: extracción fallida o sin archivos de interés.
    """
    ext = os.path.splitext(str(archive))[1].lower()
    dest = os.path.join(scratch_parent, "arch_" + datetime.now().strftime(
        "%Y%m%d_%H%M%S"))
    if ext == ".zip":
        _safe_extract_zip(archive, dest)
    elif ext == ".tar":
        _safe_extract_tar(archive, dest)
    else:
        extract_iso(archive, dest)
    targets = []
    for root, _dirs, names in os.walk(dest):
        for name in sorted(names):
            full = os.path.join(root, name)
            if is_target_file(full):
                targets.append(full)
    if not targets:
        raise RuntimeError("El contenedor no tiene archivos de interés")
    return dest, targets


def process_batch(input_paths, base_dir=None, decision_callback=None,
                  on_file_done=None, should_stop=None, analyze_only=False):
    """
    Ejecuta el pipeline de 7 capas sobre cada archivo de las entradas.

    Args:
        input_paths (list): Archivos, directorios o ISOs.
        base_dir (str, opcional): Base para entornos/packages (todos los
            archivos de un lote comparten esta base).
        decision_callback (callable, opcional): Mismo contrato que
            sqs.run_pipeline (zona AMBIGUO).
        on_file_done (callable, opcional): f(result_dict) al terminar cada
            archivo (útil para progreso en GUI).
        should_stop (callable, opcional): f() -> True detiene el lote.
        analyze_only (bool): Solo capas 1-4 (detección, sin cirugía ni
            paquete). No modifica el archivo ni crea paquetes.

    Returns:
        list: resultados por archivo (status ok/error, reportes, saneado).
    """
    from sqs import DECISION_FUERZA, run_pipeline

    base_dir = base_dir or os.getcwd()
    os.makedirs(base_dir, exist_ok=True)
    results = []
    scratch_parent = os.path.abspath(
        os.path.join(base_dir, "batch_scratch"))
    os.makedirs(scratch_parent, exist_ok=True)
    inputs = resolve_inputs(input_paths)
    archives = []
    for item in inputs:
        if should_stop and should_stop():
            return results

        if is_archive(item):
            try:
                dest, targets = _iter_archive_targets(item, scratch_parent)
            except Exception as e:
                entry = _error_entry(item, e)
                results.append(entry)
                if on_file_done:
                    on_file_done(entry)
                continue
            archives.append((dest, targets))

    # Archivos normales primero; luego los blancos extraídos de contenedores
    def _feed():
        for item in inputs:
            if is_archive(item):
                continue
            yield item, item
        for dest, targets in archives:
            for t in targets:
                yield t, t

    for target, label in _feed():
        if should_stop and should_stop():
            break
        entry = _process_one(target, label, base_dir, decision_callback,
                             analyze_only)
        results.append(entry)
        if on_file_done:
            on_file_done(entry)

    for dest, _targets in archives:
        shutil.rmtree(dest, ignore_errors=True)

    _write_batch_report(results, base_dir)
    return results


def _error_entry(source, exc):
    return {
        "input": os.path.abspath(source),
        "status": "error",
        "error": str(exc),
        "package_dir": None,
        "classification": None,
        "temp_dir": None,
        "surgery_status": None,
        "verification_status": None,
        "sanitized_file": None,
    }


def _process_one(target, label, base_dir, decision_callback, analyze_only=False):
    from sqs import run_pipeline, analyze_only as _analyze_only
    entry = {
        "input": os.path.abspath(label),
        "status": "ok",
        "error": None,
    }
    try:
        if analyze_only:
            try:
                classification, temp_dir = _analyze_only(
                    target, base_dir=base_dir)
            except SystemExit as e:
                raise RuntimeError(
                    f"No se pudo clasificar el archivo: {e}") from e
            entry.update(
                package_dir=None,
                classification=classification,
                temp_dir=temp_dir,
                surgery_status=None,
                verification_status=None,
                sanitized_file=None,
            )
            return entry
        package_dir, classification, temp_dir = run_pipeline(
            target, base_dir=base_dir, decision_callback=decision_callback)
        if package_dir is None:
            entry.update(status="aborted", temp_dir=temp_dir,
                         classification=classification)
            return entry
        surgery_status = None
        sanitized_file = None
        surgery_path = os.path.join(temp_dir, "surgery_report.json")
        if os.path.isfile(surgery_path):
            with open(surgery_path, encoding="utf-8") as f:
                surgery = json.load(f)
            surgery_status = surgery.get("surgery_status")
            if surgery.get("sanitized_file"):
                sanitized_file = os.path.basename(
                    surgery["sanitized_file"])
        verification_status = None
        vpath = os.path.join(temp_dir, "integrity_verification.json")
        if os.path.isfile(vpath):
            with open(vpath, encoding="utf-8") as f:
                verification_status = json.load(f).get(
                    "verification_status")
        entry.update(
            package_dir=package_dir,
            classification=classification,
            temp_dir=temp_dir,
            surgery_status=surgery_status,
            verification_status=verification_status,
            sanitized_file=sanitized_file,
        )
    except Exception as e:
        entry.update(
            status="error",
            error=str(e),
            package_dir=None,
            classification=None,
            temp_dir=None,
            surgery_status=None,
            verification_status=None,
            sanitized_file=None,
        )
    return entry


def _write_batch_report(results, base_dir):
    ok = [r for r in results if r.get("status") == "ok"]
    cleaned = [r for r in ok
               if (r.get("classification") or {}).get("zone") == "malicioso"
               and r.get("surgery_status") == "completed"]
    suspicious = [r for r in ok
                  if (r.get("classification") or {}).get("zone") == "ambiguo"]
    report = {
        "pipeline_version": "1.0",
        "timestamp": datetime.now().isoformat(),
        "total": len(results),
        "ok": len(ok),
        "cleaned": len(cleaned),
        "suspicious": len(suspicious),
        "errors": len(results) - len(ok),
        "results": results,
    }
    path = os.path.join(base_dir, "batch_report.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def write_csv_summary(results, csv_path):
    """
    Exporta un resumen legible del lote a CSV (UTF-8 BOM para Excel).
    """
    import csv
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["archivo", "estado", "veredicto", "riesgo",
                         "zona", "cirugia", "verificacion", "sanitizado",
                         "error"])
        for r in results:
            c = r.get("classification") or {}
            writer.writerow([
                os.path.basename(r["input"]),
                r["status"],
                c.get("verdict", ""),
                c.get("risk_score", ""),
                c.get("zone", ""),
                r.get("surgery_status") or "",
                r.get("verification_status") or "",
                r.get("sanitized_file") or "",
                r.get("error") or "",
            ])


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="SQS - Procesamiento por lotes (archivo/dir/ISO)")
    parser.add_argument("entradas", nargs="+",
                        help="Archivos, directorios o ISOs")
    parser.add_argument("-o", "--output-dir", default=None)
    parser.add_argument("--surgery", action="store_true",
                        help="Forzar cirugía en zona ambiguo")
    args = parser.parse_args()

    from sqs import DECISION_FUERZA, interactive_decision
    cb = interactive_decision
    if args.surgery:
        cb = lambda c, v=None: DECISION_FUERZA

    results = process_batch(args.entradas, base_dir=args.output_dir,
                            decision_callback=cb)
    _print_summary(results, args.output_dir or os.getcwd())


def _print_summary(results, base_dir):
    print("-" * 62)
    for r in results:
        state = "OK " if r["status"] == "ok" else r["status"].upper()
        verdict = (r["classification"] or {}).get("verdict", "-")
        risk = (r["classification"] or {}).get("risk_score", "-")
        print(f"{state}  {os.path.basename(r['input']):<28} "
              f"veredicto={verdict} riesgo={risk} "
              f"sanitized={r['sanitized_file'] or '-'}")
        if r.get("error"):
            print(f"     error: {r['error']}")
    print("-" * 62)
    print(f"Lote: {len(results)} archivos | resumen: "
          f"{os.path.join(base_dir, 'batch_report.json')}")


if __name__ == "__main__":
    main()