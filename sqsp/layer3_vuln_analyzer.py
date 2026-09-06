"""
SQS - Capa 3: Análisis de Vulnerabilidades (Identificación de Amenazas).

Verifica seguridad de los componentes de Capa 1 usando su análisis dinámico
de Capa 2:
    - Firma digital (Get-AuthenticodeSignature en Windows; 'unknown' en
      otras plataformas o si no hay binario).
    - Funciones peligrosas: reutiliza `imports_analyzer` (imports de PE
      conocido-maliciosos) y `strings_analyzer` (tokens textuales en scripts).
    - Obsolescencia por antigüedad del archivo (mtime > 10 años por defecto).
    - Correlación con el registro dinámico (timeouts / fallos de ejecución).

Genera `layer3_vulnerability_report.json` con, por componente:
    component, vulnerabilities (lista), risk_level (bajo/medio/alto) y
    detalles (signature_status, dangerous_functions, age_days,
    execution_status).

No reemplaza classification_layer.py (zona de riesgo del pipeline 7 capas);
es la capa de vulnerabilidades del spec de capas.
"""

import json
import os
import subprocess
import sys
import time

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_THIS_DIR, "layers", "layer1"))

try:
    from imports_analyzer import extract_pe_imports, suspicious_imports
    from strings_analyzer import extract_strings
except Exception:
    extract_pe_imports = suspicious_imports = extract_strings = None

_DANGEROUS_TOKENS = [
    "CreateProcess", "ShellExecute", "WinExec", "URLDownloadToFile",
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "GetProcAddress", "LoadLibrary", "system(", "eval(", "exec(",
    "Popen", "base64",
]

_SIGNATURE_STATUS = ["signed", "unsigned", "unknown"]


def _parse_signature_status(text):
    """Traduce la salida de Get-AuthenticodeSignature a un estado SQS."""
    lower = (text or "").lower()
    if "valid" in lower:
        return "signed"
    if "notsigned" in lower or "hash mismatch" in lower:
        return "unsigned"
    return "unknown"


def is_signed(filepath):
    """Firma digital real (Windows). 'unknown' si no verificable."""
    if os.name != "nt" or not os.path.isfile(filepath):
        return "unknown"
    try:
        target = filepath.replace("'", "''")
        script = (
            "Get-AuthenticodeSignature -FilePath '%s' | "
            "Format-List Subject,Status,StatusMessage" % target)
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             script],
            capture_output=True, text=True, timeout=30)
        return _parse_signature_status((result.stdout or "") +
                                       (result.stderr or ""))
    except Exception:
        return "unknown"


def has_dangerous_functions(filepath):
    """Usa imports PE reales (imports_analyzer) + tokens textuales en scripts.

    Returns:
        tuple: (bool, list[str]) presencia de funciones peligrosas y nombres.
    """
    names = set()

    if extract_pe_imports and extract_strings:
        try:
            if os.path.isfile(filepath):
                imports = extract_pe_imports(filepath)
                if imports and suspicious_imports:
                    for flagged in suspicious_imports(imports):
                        names.add(flagged.get("function") or "?")
        except Exception:
            pass

        try:
            if os.path.isfile(filepath):
                strings = extract_strings(filepath, max_count=1000)
                text = " ".join(s["string"] for s in strings)
                low = text.lower()
                for token in _DANGEROUS_TOKENS:
                    if token.lower() in low:
                        names.add(token)
        except Exception:
            pass

    return bool(names), sorted(names)


def is_outdated(filepath, max_age_days=3650):
    """Antigüedad excesiva del componente (mtime vs. hoy)."""
    try:
        age_days = (time.time() - os.path.getmtime(filepath)) / 86400.0
    except Exception:
        return False
    return age_days > max_age_days


def _component_age_days(filepath):
    try:
        return round((time.time() - os.path.getmtime(filepath)) / 86400.0, 1)
    except Exception:
        return None


def _dynamic_entry(dynamic_analysis, component_path, rel_path=None):
    for entry in dynamic_analysis or []:
        if entry.get("component") in (component_path, rel_path):
            return entry
    return None


def check_component_security(component, dynamic_analysis, rel_path=None):
    """
    Verifica un componente y asigna nivel de riesgo.

    Args:
        component (dict): inventario de Capa 1 (type, path, size, ...).
        dynamic_analysis (list): registro de Capa 2.
        rel_path (str, opcional): ruta relativa original usada en Capa 2.

    Returns:
        dict: component, vulnerabilities, risk_level y detalles.
    """
    vulnerabilities = []
    ctype = component.get("type")
    path = component.get("path", "")
    full_path = path if os.path.isabs(path) else path

    details = {"signature_status": None, "dangerous_functions": [],
               "age_days": _component_age_days(path),
               "execution_status": None}

    signature_status = "unknown"
    if ctype == "executable":
        signature_status = is_signed(path)
        if signature_status == "unsigned":
            vulnerabilities.append("No firmado digitalmente")
    details["signature_status"] = signature_status

    if ctype in ("executable", "script", "installer"):
        has_danger, names = has_dangerous_functions(path)
        if has_danger:
            vulnerabilities.append(
                "Uso de funciones peligrosas: " + ", ".join(names[:6]))
        details["dangerous_functions"] = names

    if is_outdated(path):
        vulnerabilities.append("Componente desactualizado")

    entry = _dynamic_entry(dynamic_analysis, path, rel_path)
    if entry is not None:
        code = entry.get("exit_code")
        if code == -1:
            vulnerabilities.append(
                "Timeout en ejecución (posible bloqueo/anti-sandbox)")
            details["execution_status"] = "timeout"
        elif code == -2:
            vulnerabilities.append(
                "No se pudo ejecutar el componente (entorno/bloqueo)")
            details["execution_status"] = "execution_error"
        else:
            details["execution_status"] = "ok"

    if len(vulnerabilities) >= 2:
        risk_level = "alto"
    elif len(vulnerabilities) == 1:
        risk_level = "medio"
    else:
        risk_level = "bajo"

    return {
        "component": rel_path if rel_path else path,
        "vulnerabilities": vulnerabilities,
        "risk_level": risk_level,
        "details": details,
    }


def analyze_vulnerabilities(components, dynamic_results, base_dir=None):
    """Analiza todos los componentes del inventario.

    Args:
        components (list): inventario de Capa 1.
        dynamic_results (list): registro de Capa 2.
        base_dir (str, opcional): resuelve rutas relativas contra el paquete.
    """
    report = []
    for comp in components or []:
        rel = comp.get("path", "")
        work = comp
        if base_dir is not None and not os.path.isabs(rel):
            if isinstance(comp, dict):
                work = dict(comp)
                work["path"] = os.path.normpath(os.path.join(base_dir, rel))
        else:
            rel = None
        report.append(check_component_security(work, dynamic_results, rel))
    return report


def save_vulnerability_report(report, output_file="layer3_vulnerability_report.json"):
    """Guarda el informe de vulnerabilidades en JSON (UTF-8, indentado)."""
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return output_file


def main():
    from layer1_extractor import extract_components
    from layer2_analyzer import analyze_package_dynamically

    if len(sys.argv) != 2:
        print("Uso: python layer3_vuln_analyzer.py <paquete|directorio>")
        sys.exit(1)

    components = extract_components(sys.argv[1])
    dynamic_results = analyze_package_dynamically(sys.argv[1], components)
    report = analyze_vulnerabilities(components, dynamic_results,
                                     base_dir=sys.argv[1])
    output = save_vulnerability_report(report)

    counts = {}
    for r in report:
        counts[r["risk_level"]] = counts.get(r["risk_level"], 0) + 1

    print(f"[+] {len(report)} componente(s) verificados en {output}")
    for level in ("bajo", "medio", "alto"):
        if level in counts:
            print(f"    - riesgo {level}: {counts[level]}")


if __name__ == "__main__":
    main()