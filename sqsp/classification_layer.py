"""
SQS - Capa 4: Clasificación y Veredicto.

Combina los hallazgos estáticos y dinámicos con pesos configurables
(config/weights.json), asigna un puntaje de riesgo y genera el veredicto por
zonas:
    LIMPIO      (auto-aprobado)
    AMBIGUO     (pausa para decisión del usuario)
    MALICIOSO   (auto-remover)
Además produce verdict_map.json con el mapa de cirugía (qué limpio/parchear/
remover y en qué offsets).
"""

import json
import os
from datetime import datetime

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
WEIGHTS_FILE = os.path.join(_THIS_DIR, "config", "weights.json")

_DEFAULT_WEIGHTS = {
    "weights": {
        "executable": 2,
        "sandbox_error": 5,
        "network_activity": 3,
        "filesystem_change": 3,
        "suspicious_string": 1,
        "suspicious_import": 2,
        "packed_high_entropy": 3,
        "installer_packed": 2,
        "known_malicious": 10,
    },
    "thresholds": {
        "malicious": 10,
        "suspicious": 5,
    },
}

HIGH_ENTROPY = 7.5


def load_weights():
    """Carga pesos y umbrales configurables (con respaldo a valores por defecto)."""
    try:
        with open(WEIGHTS_FILE, encoding="utf-8") as f:
            config = json.load(f)
        weights = dict(_DEFAULT_WEIGHTS["weights"])
        weights.update(config.get("weights", {}))
        thresholds = dict(_DEFAULT_WEIGHTS["thresholds"])
        thresholds.update(config.get("thresholds", {}))
        return weights, thresholds
    except Exception:
        return (dict(_DEFAULT_WEIGHTS["weights"]),
                dict(_DEFAULT_WEIGHTS["thresholds"]))


def _load_json(temp_dir, name):
    path = os.path.join(temp_dir, name)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def classify_file(temp_dir="."):
    """
    Clasifica el archivo y escribe classification.json y verdict_map.json.

    Args:
        temp_dir (str): Directorio del entorno aislado.

    Returns:
        dict: Reporte de clasificación, o None si faltan reportes.
    """
    static_report = _load_json(temp_dir, "static_analysis.json")
    dynamic_report = _load_json(temp_dir, "dynamic_report.json")
    manifest = _load_json(temp_dir, "manifest.json")

    if not static_report and not dynamic_report:
        print("No se encontraron los reportes necesarios en "
              f"{temp_dir} (static_analysis.json / dynamic_report.json)")
        return None

    weights, thresholds = load_weights()

    risk_score = 0
    threats_found = []
    notes = []

    # --- Señales estáticas ---
    if static_report.get("is_executable", False):
        risk_score += weights["executable"]

    s = static_report.get("static_analysis", {}) or {}

    if s.get("suspicious_strings_found"):
        risk_score += weights["suspicious_string"]
        threats_found.append(
            f"{len(s['suspicious_strings_found'])} string(s) sospechoso(s)")

    if s.get("suspicious_imports"):
        risk_score += weights["suspicious_import"]
        threats_found.append(
            f"{len(s['suspicious_imports'])} import(s) sospechoso(s)")

    if s.get("high_entropy_sections") or s.get("entropy", 0) >= HIGH_ENTROPY:
        risk_score += weights["packed_high_entropy"]
        threats_found.append("Alta entropía (posible empaquetado/cifrado)")

    if s.get("packer_detected"):
        risk_score += weights["installer_packed"]
        threats_found.append(
            f"Empaquetador/instalador: {', '.join(s['packer_detected'])}")

    # --- Señales dinámicas ---
    if dynamic_report.get("error"):
        risk_score += weights["sandbox_error"]
        threats_found.append(dynamic_report["error"])

    if dynamic_report.get("network_activity"):
        risk_score += weights["network_activity"]
        threats_found.append(
            f"Actividad de red: {len(dynamic_report['network_activity'])} evento(s)")

    if dynamic_report.get("filesystem_changes"):
        risk_score += weights["filesystem_change"]
        threats_found.append(
            f"Cambios en filesystem: "
            f"{len(dynamic_report['filesystem_changes'])} archivo(s)")

    # --- Motor de reglas (rules/signatures.json y YAML opcional) ---
    try:
        from rules_engine import evaluate as evaluate_rules, load_rules
        rules_signals = {
            "static_analysis": s,
            "dynamic_report": dynamic_report,
            "manifest": manifest,
        }
        rules_result = evaluate_rules(rules_signals)
        if rules_result.get("error"):
            notes.append(f"Motor de reglas: {rules_result['error']}")
    except Exception as e:
        rules_result = {"matched": [], "risk_added": 0, "error": str(e)}

    risk_score += rules_result["risk_added"]
    rules_matched = rules_result["matched"]
    for rule in rules_matched:
        threats_found.append(
            f"Regla '{rule['name']}' (severidad {rule.get('severity')})")

    # --- Reputación por hash (Capa 1) ---
    reputation = manifest.get("reputation", {}) or {}
    if reputation.get("status") == "malicious":
        risk_score += weights["known_malicious"]
        threats_found.append("Hash presente en base local de malware")
    elif reputation.get("status") == "benign":
        # LIMPIO auto-aprobado: señales benignas conocidas bajan el riesgo
        risk_score = min(risk_score, thresholds["suspicious"] - 1)
        notes.append("Hash conocido benigno: riesgo re-evaluado a la baja")

    # --- Umbrales ---
    if risk_score >= thresholds["malicious"]:
        verdict, zone = "malicioso", "malicioso"
    elif risk_score >= thresholds["suspicious"]:
        verdict, zone = "sospechoso", "ambiguo"
    else:
        verdict, zone = "seguro", "limpio"

    classification_report = {
        "timestamp": datetime.now().isoformat(),
        "temp_directory": temp_dir,
        "verdict": verdict,
        "zone": zone,
        "risk_score": risk_score,
        "threats_found": threats_found,
        "notes": notes,
        "weights": weights,
        "thresholds": thresholds,
        "rules_matched": [r["name"] for r in rules_matched],
        "rules_risk_added": rules_result["risk_added"],
        "static_analysis": static_report,
        "dynamic_analysis": dynamic_report,
        "manifest": manifest,
    }

    rules_report = {
        "timestamp": datetime.now().isoformat(),
        "rules_evaluated": len(load_rules()),
        "risk_added": rules_result["risk_added"],
        "matched": rules_matched,
        "error": rules_result.get("error"),
    }

    verdict_map = _build_verdict_map(classification_report, static_report)

    with open(os.path.join(temp_dir, "classification.json"), "w",
              encoding="utf-8") as f:
        json.dump(classification_report, f, indent=2, default=str)

    with open(os.path.join(temp_dir, "rules_report.json"), "w",
              encoding="utf-8") as f:
        json.dump(rules_report, f, indent=2, default=str)

    with open(os.path.join(temp_dir, "verdict_map.json"), "w",
              encoding="utf-8") as f:
        json.dump(verdict_map, f, indent=2, default=str)

    return classification_report


def _build_verdict_map(classification, static_report):
    """
    Mapa de cirugía: por cada componente decide acción y offsets a parchear.

    Returns:
        dict: verdict_map.json
    """
    components_out = []
    actions = []

    suspicious_offsets = []
    for hit in (static_report.get("static_analysis", {})
                .get("suspicious_strings_found", []) or []):
        suspicious_offsets.append({
            "offset": hit.get("offset"),
            "size": len(hit.get("string", "")),
            "note": hit.get("pattern", "string sospechoso"),
            "string": hit.get("string", "")[:40],
        })

    main_verdict = classification["verdict"]
    main_action = "keep"
    if main_verdict == "malicioso":
        main_action = "patch" if suspicious_offsets else "review"

    components_out.append({
        "id": "main",
        "name": os.path.basename(str(
            static_report.get("file_path", "desconocido"))),
        "kind": (static_report.get("static_analysis", {})
                 .get("file_signature", "unknown")),
        "offset": 0,
        "verdict": main_verdict,
        "action": main_action,
        "patch_offsets": suspicious_offsets,
    })

    for comp in static_report.get("components", []) or []:
        if comp.get("id") == "main":
            continue
        score = comp.get("suspicion_score", 0)
        if score >= 7:
            c_verdict, c_action = "malicioso", "remove"
        elif score >= 4:
            c_verdict, c_action = "sospechoso", "review"
        else:
            c_verdict, c_action = "seguro", "keep"
        components_out.append({
            "id": comp.get("id"),
            "name": comp.get("name"),
            "kind": comp.get("kind"),
            "offset": comp.get("offset"),
            "size": comp.get("size"),
            "entropy": comp.get("entropy"),
            "verdict": c_verdict,
            "action": c_action,
            "patch_offsets": [],
        })

    for off in suspicious_offsets:
        if off.get("offset") is not None:
            actions.append({
                "type": "patch",
                "offset": off["offset"],
                "size": off.get("size", 0) or 0,
                "note": off.get("note", ""),
                "string": off.get("string", ""),
            })

    return {
        "timestamp": datetime.now().isoformat(),
        "temp_directory": classification.get("temp_directory"),
        "verdict": classification["verdict"],
        "zone": classification["zone"],
        "risk_score": classification["risk_score"],
        "decision": None,
        "notes": classification.get("notes", []) or [],
        "components": components_out,
        "actions": actions,
    }


def main():
    import sys
    temp_dir = sys.argv[1] if len(sys.argv) > 1 else os.getenv("TEMP_DIR", ".")
    report = classify_file(temp_dir)
    if report is not None:
        print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()