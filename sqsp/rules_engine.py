"""
SQS - Motor de reglas (Capa 4).

Carga reglas desde `rules/*.json` (siempre) y `rules/*.yaml` (si PyYAML está
instalado) y las evalúa sobre el reporte consolidado (estático + dinámico +
manifest). Cada regla vencedora suma puntos de riesgo e identifica amenazas.

Formato de regla:
    {
      "name": "...",
      "description": "...",
      "severity": "low|medium|high|critical",   # define los puntos si no hay base_add
      "base_add": 2,                             # puntos de riesgo (opcional)
      "reference": "MITRE ATT&CK T1027",         # opcional
      "condition": {
        "field": "static_analysis.suspicious_imports",  # ruta punteada
        "op": "exists|equals|contains|greater|regex",
        "value": "..."
      }
    }

Operadores:
    exists  -> el campo existe y no está vacío
    equals  -> el campo (o algún elemento de una lista) es igual a value
    contains-> el campo (o algún elemento) contiene value como texto
    greater -> numérico
    regex   -> expresión regular sobre el texto del campo
"""

import glob
import json
import os
import re

_RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")

_DEFAULT_SEVERITY_POINTS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _get_path(obj, dotted):
    """Navega una ruta punteada sobre un dict anidado."""
    current = obj
    for part in dotted.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
        if current is None:
            return None
    return current


def _evaluate_condition(signals, condition):
    if not isinstance(condition, dict):
        return False

    field = condition.get("field")
    op = condition.get("op", "exists")
    expected = condition.get("value")

    value = _get_path(signals, field)

    if op == "exists":
        return value not in (None, "", [], {})

    if isinstance(value, list):
        if op == "contains":
            return any(expected in str(item) for item in value)
        if op == "equals":
            return any(str(item) == str(expected) for item in value)

    if op == "contains":
        return expected in str(value)
    if op == "equals":
        return str(value) == str(expected)
    if op == "greater":
        try:
            return float(value) > float(expected)
        except (TypeError, ValueError):
            return False
    if op == "regex":
        try:
            return re.search(str(expected), str(value)) is not None
        except Exception:
            return False
    return False


def _load_json_rules(path):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    return doc


def _load_yaml_rules(path):
    try:
        import yaml
    except ImportError:
        return None
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _normalize_doc(doc):
    """Extrae la lista de reglas de un documento (con/sin clave 'rules')."""
    if isinstance(doc, dict):
        items = doc.get("rules", [doc])
    elif isinstance(doc, list):
        items = doc
    else:
        items = []
    return items if isinstance(items, list) else [items]


def load_rules(rules_dir=_RULES_DIR):
    """
    Carga las reglas de `rules/`. JSON siempre; YAML solo con PyYAML.
    Los archivos `example_*` se ignoran (plantillas de referencia).
    """
    rules = []
    if not os.path.isdir(rules_dir):
        return rules

    for path in sorted(glob.glob(os.path.join(rules_dir, "*.json"))):
        if os.path.basename(path).startswith("example"):
            continue
        try:
            rules.extend(_normalize_doc(_load_json_rules(path)))
        except Exception:
            continue

    for path in sorted(glob.glob(os.path.join(rules_dir, "*.yaml"))):
        if os.path.basename(path).startswith("example"):
            continue
        doc = _load_yaml_rules(path)
        if doc is None:      # Sin PyYAML o YAML inválido
            continue
        rules.extend(_normalize_doc(doc))

    return rules


def evaluate(signals, rules=None):
    """
    Evalúa las reglas contra el reporte consolidado.

    Args:
        signals (dict): Reporte con claves estáticas/dinámicas/manifest.
        rules (list, opcional): Reglas a evaluar (por defecto load_rules()).

    Returns:
        dict: {"matched": [...], "risk_added": int, "error": str|None}
    """
    if rules is None:
        rules = load_rules()

    matched = []
    risk_added = 0

    for rule in rules:
        try:
            fired = _evaluate_condition(signals, rule.get("condition", {}))
        except Exception:
            fired = False
        if not fired:
            continue

        points = rule.get("base_add")
        if points is None:
            points = _DEFAULT_SEVERITY_POINTS.get(
                str(rule.get("severity", "")).lower(), 2)

        risk_added += points
        matched.append({
            "name": rule.get("name", "sin_nombre"),
            "severity": rule.get("severity"),
            "base_add": points,
            "description": rule.get("description"),
            "reference": rule.get("reference"),
        })

    return {
        "matched": matched,
        "risk_added": risk_added,
        "error": None,
    }