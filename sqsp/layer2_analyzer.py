"""
SQS - Capa 2: Análisis Dinámico de Paquetes (Ejecución y Comportamiento).

Ejecuta los componentes detectados por la Capa 1 (`layer1_extractor.py`) con
límite de tiempo, captura salida estándar/errores y genera
`layer2_dynamic_analysis.json`.

Registro por componente:
    - component:       ruta del componente analizado
    - execution_time:  tiempo de ejecución en segundos
    - exit_code:       código de salida (-1 = timeout, -2 = error de ejecución)
    - output:          salida estándar (limitada a 500 caracteres)
    - error:           errores si los hubo

Este módulo NO reemplaza `dynamic_analysis_layer.py` (Capa 3 del pipeline de
7 capas, con sandbox/normalización); es el análisis dinámico autónomo de
paquetes del spec de capas y consume el inventario de Capa 1.
"""

import json
import os
import subprocess
import time

_OUTPUT_LIMIT = 500
_DEFAULT_TIMEOUT = 15
_RUN_TYPES = {"executable", "script"}


def _resolve_path(package_path, rel_path):
    """Resuelve la ruta relativa de un componente contra el paquete."""
    if os.path.isabs(rel_path):
        return rel_path
    base = package_path
    if os.path.isfile(package_path):
        base = os.path.dirname(package_path) or "."
    return os.path.join(base, rel_path)


def analyze_package_dynamically(package_path, components, timeout=_DEFAULT_TIMEOUT,
                                run_scripts=True):
    """
    Analiza dinámicamente los componentes del paquete.

    Args:
        package_path (str): ruta del paquete (directorio o archivo único).
        components (list): inventario de layer1_extractor.extract_components.
        timeout (int): límite de ejecución por componente, en segundos.
        run_scripts (bool): si True (por defecto) también ejecuta componentes
            de tipo 'script' además de los 'executable'.

    Returns:
        list[dict]: resultados por componente ejecutado. Los componentes de
        tipo 'other'/'installer' no se ejecutan y no aparecen en el registro.
    """
    results = []

    for comp in components:
        ctype = comp.get("type")
        if ctype not in _RUN_TYPES or (ctype == "script" and not run_scripts):
            continue

        target = _resolve_path(package_path, comp.get("path", ""))
        start = time.time()
        log = {
            "component": comp.get("path"),
            "execution_time": 0.0,
            "exit_code": None,
            "output": "",
            "error": "",
        }

        try:
            result = subprocess.run(
                [target], capture_output=True, text=True, shell=False,
                timeout=timeout)

            log.update({
                "execution_time": round(time.time() - start, 3),
                "exit_code": result.returncode,
                "output": (result.stdout or "")[:_OUTPUT_LIMIT],
                "error": (result.stderr or "")[:_OUTPUT_LIMIT],
            })

        except subprocess.TimeoutExpired:
            log.update({
                "execution_time": float(timeout),
                "exit_code": -1,
                "error": f"Timeout: excedió el límite de {timeout} segundos",
            })

        except Exception as e:
            log.update({
                "exit_code": -2,
                "error": str(e)[:_OUTPUT_LIMIT],
            })

        results.append(log)

    return results


def save_dynamic_analysis(results, output_file="layer2_dynamic_analysis.json"):
    """Guarda el registro de ejecución en JSON (UTF-8, indentado)."""
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return output_file


def main():
    import sys
    if len(sys.argv) != 2:
        print("Uso: python layer2_analyzer.py <paquete|directorio>")
        sys.exit(1)

    from layer1_extractor import extract_components

    components = extract_components(sys.argv[1])
    results = analyze_package_dynamically(sys.argv[1], components)
    output = save_dynamic_analysis(results)

    print(f"[+] {len(results)} componente(s) analizado(s) en {output}")
    for r in results:
        print(f"    - {r['component']}: exit={r['exit_code']} "
              f"({r['execution_time']}s)")


if __name__ == "__main__":
    main()