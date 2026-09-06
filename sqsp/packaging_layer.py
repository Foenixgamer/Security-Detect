"""
SQS - Capa 7: Empaquetado en App Ejecutable (GUI).

Genera la versión final empaquetada del análisis: copia el archivo saneado,
crea el informe completo (complete_report.json) y un README de resumen.
También permite lanzar la interfaz gráfica (sqs_gui.py) para visualizar todos
los resultados.
"""

import json
import os
import shutil
from datetime import datetime


def package_application(input_file, temp_dir=".", output_dir=None):
    """
    Empaqueta los resultados del procesamiento en un directorio final.

    Args:
        input_file (str): Ruta al archivo original.
        temp_dir (str): Directorio del entorno aislado.
        output_dir (str, opcional): Directorio base del paquete final.

    Returns:
        str: Ruta del directorio del paquete, o None si no hay reportes.
    """
    reports = {}

    try:
        with open(os.path.join(temp_dir, "classification.json"),
                  encoding="utf-8") as f:
            reports["classification"] = json.load(f)
        with open(os.path.join(temp_dir, "surgery_report.json"),
                  encoding="utf-8") as f:
            reports["surgery"] = json.load(f)
        with open(os.path.join(temp_dir, "integrity_verification.json"),
                  encoding="utf-8") as f:
            reports["verification"] = json.load(f)
        for key, name in (("verdict_map", "verdict_map.json"),
                          ("surgery_log", "surgery_log.json"),
                          ("manifest", "manifest.json"),
                          ("final_report", "final_report.json"),
                          ("rules_report", "rules_report.json")):
            path = os.path.join(temp_dir, name)
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    reports[key] = json.load(f)
    except Exception as e:
        print(f"Error cargando reportes: {e}")
        return None

    base_dir = output_dir or os.getcwd()
    os.makedirs(base_dir, exist_ok=True)

    # Crear directorio final para empaquetado
    output = os.path.join(
        base_dir, f"final_package_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    os.makedirs(output, exist_ok=True)

    # Copiar archivo saneado si existe
    sanitized_file = reports.get("surgery", {}).get("sanitized_file")
    if sanitized_file and os.path.exists(sanitized_file):
        shutil.copy2(sanitized_file, output)

    # Crear informe completo
    final_report = {
        "timestamp": datetime.now().isoformat(),
        "input_file": os.path.abspath(input_file),
        "output_directory": os.path.abspath(output),
        "processing_reports": reports,
        "final_status": "completed"
    }

    with open(os.path.join(output, "complete_report.json"), "w",
              encoding="utf-8") as f:
        json.dump(final_report, f, indent=2)

    # Crear archivo README con resumen
    classification = reports.get("classification", {})
    final_report = reports.get("final_report", {})
    verdict = classification.get("verdict", "sin datos")
    risk = classification.get("risk_score", 0)

    readme_content = f"""# Informe de Procesamiento

Archivo procesado: {os.path.abspath(input_file)}
Fecha de procesamiento: {final_report.get('timestamp', 'n/d')}
Estado final: {final_report.get('final_status', 'completed')}

## Resumen del análisis:
- Veredicto final: {verdict}
- Puntaje de riesgo: {risk}

## Amenazas detectadas:
{json.dumps(classification.get('threats_found', []), indent=2, ensure_ascii=False)}

## Resumen de verificación:
{json.dumps(final_report.get('summary', []), indent=2, ensure_ascii=False)}

## Acciones realizadas:
{json.dumps(reports.get('surgery', {}), indent=2, ensure_ascii=False, default=str)}
"""

    with open(os.path.join(output, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme_content)

    return os.path.abspath(output)


def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python packaging_layer.py <ruta_archivo> [--gui]")
        sys.exit(1)

    temp_dir = os.getenv("TEMP_DIR", ".")
    output = package_application(sys.argv[1], temp_dir)

    if output:
        print(f"[+] Paquete final generado en: {output}")

    if "--gui" in sys.argv and output:
        from sqs_gui import launch_gui
        launch_gui(temp_dir)


if __name__ == "__main__":
    main()