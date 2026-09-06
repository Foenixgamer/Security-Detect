"""
SQS - Capa 4: Generación de Informe Final y Reporte Automático.

Reúne los resultados de Capa 1 (inventario), Capa 2 (dinámico) y Capa 3
(vulnerabilidades) en `final_report.json` y exporta a HTML (visual) y CSV.

Tolerante a datos faltantes: los componentes sin análisis dinámico o sin
informe de vulnerabilidades se incluyen igualmente con `null`/resumen vacío;
los componentes sin clave `type` se cuentan como `other`.

No reemplaza packaging_layer.py (empaquetado del pipeline 7 capas); es la
capa de reportes del spec de capas.
"""

import csv
import html
import json
import sys
from datetime import datetime

_REPORT_VERSION = "1.0"
_LAYER1_CANDIDATES = [
    "layer1_extracted_components.json",
    "layer1_components.json",
    "components.json",
]
_LAYER2_CANDIDATES = ["layer2_dynamic_analysis.json"]
_LAYER3_CANDIDATES = ["layer3_vulnerability_report.json"]

_RISK_STYLE = {
    "alto": "#c62828",
    "medio": "#ef6c00",
    "bajo": "#2e7d32",
}


def _component_type(comp):
    if not isinstance(comp, dict):
        return "other"
    return comp.get("type", "other") or "other"


def _find_component_data(data_list, component_path):
    for item in data_list or []:
        try:
            if item.get("component") == component_path:
                return item
        except AttributeError:
            continue
    return None


def build_report(layer1_data, layer2_data, layer3_data):
    """Construye el diccionario del informe sin escribir archivo."""
    executables = scripts = others = 0
    for comp in layer1_data or []:
        ctype = _component_type(comp)
        if ctype == "executable":
            executables += 1
        elif ctype == "script":
            scripts += 1
        else:
            others += 1

    risk_counts = {"bajo": 0, "medio": 0, "alto": 0}
    components = []
    for comp in layer1_data or []:
        path = comp.get("path", "") if isinstance(comp, dict) else ""
        dynamic = _find_component_data(layer2_data, path)
        vuln = _find_component_data(layer3_data, path)
        if isinstance(vuln, dict) and vuln.get("risk_level") in risk_counts:
            risk_counts[vuln["risk_level"]] += 1

        component_data = {
            "component": comp,
            "dynamic_analysis": dynamic,
            "vulnerabilities": vuln,
        }
        components.append(component_data)

    report = {
        "report_version": _REPORT_VERSION,
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_components": len(layer1_data or []),
            "executables": executables,
            "scripts": scripts,
            "others": others,
            "risk_distribution": risk_counts,
        },
        "components": components,
        "vulnerabilities": [
            {"component": v.get("component"), "risk_level": v.get("risk_level"),
             "issues": v.get("vulnerabilities")}
            for v in (layer3_data or [])
            if v.get("vulnerabilities")
        ],
    }
    return report


def generate_final_report(layer1_data, layer2_data, layer3_data,
                          output_file="final_report.json"):
    """
    Genera un informe final combinando los resultados de las capas anteriores.

    Returns:
        dict: el informe construido (y guardado en `output_file`).
    """
    report = build_report(layer1_data, layer2_data, layer3_data)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return report


def export_to_html(report, output_file="final_report.html"):
    """
    Exporta el informe final a formato HTML (escapa todo el contenido).

    Returns:
        str: ruta del archivo generado.
    """
    summary = report.get("summary", {})
    risk_distribution = summary.get("risk_distribution", {})

    rows = []
    for vuln in report.get("vulnerabilities", []):
        style = _RISK_STYLE.get(vuln.get("risk_level"), "#37474f")
        rows.append(
            "<tr><td>{}</td><td style=\"color:{}\">{}</td><td>{}</td></tr>"
            .format(html.escape(str(vuln.get("component"))),
                    style,
                    html.escape(str(vuln.get("risk_level"))),
                    html.escape(", ".join(vuln.get("issues") or []))))

    component_rows = []
    for entry in report.get("components", []):
        comp = entry.get("component") or {}
        vuln = entry.get("vulnerabilities") or {}
        risk = vuln.get("risk_level", "desconocido")
        style = _RISK_STYLE.get(risk, "#37474f")
        dyn = entry.get("dynamic_analysis") or {}
        issues = ", ".join(comp.get("vulnerabilities") or [])
        if not issues:
            issues = "sin hallazgos"
        component_rows.append(
            "<tr><td>{}</td><td>{}</td><td style=\"color:{}\">{}</td>"
            "<td>{}</td><td>{}</td></tr>"
            .format(html.escape(str(comp.get("path"))),
                    html.escape(str(_component_type(comp))),
                    style,
                    html.escape(str(risk)),
                    html.escape(str(dyn.get("exit_code"))),
                    html.escape(issues)))

    html_content = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Informe de Seguridad</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; color: #212121; }}
h1 {{ border-bottom: 2px solid #1565c0; padding-bottom: 6px; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background-color: #f2f2f2; }}
.badge {{ padding: 2px 8px; border-radius: 4px; color: #fff; }}
</style>
</head>
<body>
<h1>Informe de Seguridad del Paquete</h1>
<p>Generado el: {timestamp}</p>
<p>Versión del informe: {version}</p>

<h2>Resumen</h2>
<p>Total de componentes: {total}</p>
<p>Ejecutables: {executables} | Scripts: {scripts} | Otros: {others}</p>
<p>Distribución de riesgo: alto {alto}, medio {medio}, bajo {bajo}</p>

<h2>Componentes</h2>
<table>
<tr><th>Componente</th><th>Tipo</th><th>Riesgo</th><th>Exit</th><th>Problemas</th></tr>
{component_rows}
</table>

<h2>Vulnerabilidades Detectadas</h2>
<table>
<tr><th>Componente</th><th>Nivel de Riesgo</th><th>Problemas</th></tr>
{vuln_rows}
</table>
</body>
</html>
""".format(
        timestamp=html.escape(str(report.get("timestamp"))),
        version=html.escape(str(report.get("report_version", ""))),
        total=summary.get("total_components"),
        executables=summary.get("executables"),
        scripts=summary.get("scripts"),
        others=summary.get("others"),
        alto=risk_distribution.get("alto", 0),
        medio=risk_distribution.get("medio", 0),
        bajo=risk_distribution.get("bajo", 0),
        component_rows="\n".join(component_rows) or
        "<tr><td colspan=\"5\">Sin componentes</td></tr>",
        vuln_rows="\n".join(rows) or
        "<tr><td colspan=\"3\">Sin vulnerabilidades</td></tr>",
    )

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_file


def export_to_csv(report, output_file="final_report.csv"):
    """
    Exporta el informe a CSV: una fila por componente con su riesgo y estado.

    Returns:
        str: ruta del archivo generado.
    """
    with open(output_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["component", "type", "risk_level", "exit_code",
                         "issues"])
        for entry in report.get("components", []):
            comp = entry.get("component") or {}
            vuln = entry.get("vulnerabilities") or {}
            dyn = entry.get("dynamic_analysis") or {}
            writer.writerow([
                comp.get("path", ""),
                _component_type(comp),
                vuln.get("risk_level", "desconocido") if vuln else "",
                dyn.get("exit_code", ""),
                ", ".join(comp.get("vulnerabilities") or []),
            ])
    return output_file


def _load_json_or_none(candidates):
    for candidate in candidates:
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
    return None


def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)

    package = argv[0] if argv else None
    layer1_data = layer2_data = layer3_data = None

    if package:
        from layer1_extractor import extract_components
        from layer2_analyzer import analyze_package_dynamically
        layer1_data = extract_components(package)
        layer2_data = analyze_package_dynamically(package, layer1_data)

        from layer3_vuln_analyzer import analyze_vulnerabilities
        layer3_data = analyze_vulnerabilities(layer1_data, layer2_data,
                                              base_dir=package)
    else:
        layer1_data = _load_json_or_none(_LAYER1_CANDIDATES)
        layer2_data = _load_json_or_none(_LAYER2_CANDIDATES)
        layer3_data = _load_json_or_none(_LAYER3_CANDIDATES)

    if layer1_data is None and not package:
        print("No se encontraron datos de Capa 1 para generar el informe.")
        print("Pasa una ruta de paquete o guarda primero "
              + " / ".join(_LAYER1_CANDIDATES))
        return None

    for data, name in ((layer1_data, "Capa 1"), (layer2_data, "Capa 2"),
                       (layer3_data, "Capa 3")):
        if data is None:
            print("Aviso: sin datos de %s (se usará vacío)." % name)
            data = []

    report = generate_final_report(
        layer1_data, layer2_data or [], layer3_data or [])
    html_path = export_to_html(report)
    csv_path = export_to_csv(report)
    print("Informe generado con éxito.")
    print("  - final_report.json")
    print("  - %s" % html_path)
    print("  - %s" % csv_path)
    return report


if __name__ == "__main__":
    main()