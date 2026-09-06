#!/usr/bin/env python3
"""
SQS - Sanitizador Quirúrgico de Software
Orquestador del pipeline de 7 capas:

  1. Ingesta y Aislamiento      (cuarentena + manifest.json)
  2. Análisis Estático          (componentes, strings, entropía, imports)
  3. Análisis Dinámico (Sandbox)
  4. Clasificación y Veredicto  (zonas LIMPIO/AMBIGUO/MALICIOSO)
  5. Cirugía / Saneamiento      (backup + parcheo binario + diff)
  6. Verificación de Integridad (re-ejecución del saneado)
  7. Empaquetado + GUI

Uso:
    python sqs.py <archivo> [--gui] [-o DIR]   # pipeline completo (7 capas)
    python sqs.py <archivo> --analyze          # solo capas 1-4 (veredicto)
    python sqs.py <archivo> --surgery          # fuerza cirugía en zona ambiguo
    python sqs.py --app                        # app gráfica interactiva
"""

import argparse
import json
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from ingestion_layer import process_input_file
from static_analysis_layer import analyze_static
from dynamic_analysis_layer import run_in_sandbox
from classification_layer import classify_file
from surgery_layer import sanitize_file
from integrity_verification_layer import verify_integrity
from packaging_layer import package_application

STEPS = [
    "Ingesta y aislamiento",
    "Análisis estático",
    "Análisis dinámico (sandbox)",
    "Clasificación y veredicto",
    "Cirugía / saneamiento",
    "Verificación de integridad funcional",
    "Empaquetado final",
]

# Decisiones del usuario en zona AMBIGUO
DECISION_CONTINUAR = "continuar"       # sin cirugía
DECISION_FUERZA = "fuerza_cirugia"     # forzar la cirugía
DECISION_ABORTAR = "abortar"           # detener el proceso


def interactive_decision(classification, verdict_map_path=None):
    """
    Decisión humana en zona AMBIGUO desde la terminal:
      - riesgo >= 15: fuerza la cirugía automáticamente.
      - riesgo >= 8:  pregunta al usuario (y=forzar, n=continuar, a=abortar).
      - resto:        continúa sin cirugía.
    Sin terminal interactiva (automatización) se continúa sin cirugía.
    """
    risk = classification.get("risk_score") or 0
    if risk >= 15:
        print("      Riesgo alto: se fuerza la cirugía automáticamente.")
        return DECISION_FUERZA
    if risk >= 8:
        print(f"      Muestra sospechosa (riesgo {risk}).")
        try:
            answer = input("      ¿Forzar cirugía? [y=forzar / n=continuar "
                           "/ a=abortar]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("      (Sin entrada interactiva: se continúa sin cirugía.)")
            return DECISION_CONTINUAR
        if answer in ("y", "s"):
            return DECISION_FUERZA
        if answer in ("a", "q"):
            return DECISION_ABORTAR
        return DECISION_CONTINUAR
    return DECISION_CONTINUAR


def analyze_only(input_file, base_dir=None, on_progress=None):
    """
    Ejecuta solo las capas 1-4: ingesta, estático, dinámico y veredicto.

    Returns:
        tuple: (classification, temp_dir)
    """
    def progress(i, label):
        if on_progress:
            on_progress(i, label)

    temp_dir = process_input_file(input_file, base_dir)
    progress(1, "Ingesta y aislamiento")
    print(f"      Entorno aislado: {temp_dir}")

    analyze_static(input_file, temp_dir)
    progress(2, "Análisis estático")

    run_in_sandbox(input_file, temp_dir)
    progress(3, "Análisis dinámico")

    classification = classify_file(temp_dir)
    if classification is None:
        print("[!] No se pudieron cargar los reportes para clasificar.")
        sys.exit(1)
    progress(4, "Clasificación y veredicto")

    return classification, temp_dir


def run_pipeline(input_file, base_dir=None, on_progress=None,
                 decision_callback=None):
    """
    Ejecuta las 7 capas del pipeline sobre el archivo.

    Args:
        input_file (str): Ruta al archivo sospechoso.
        base_dir (str, opcional): Directorio base de los entornos.
        on_progress (callable, opcional): f(index, label) al finalizar cada
            capa.
        decision_callback (callable, opcional): f(classification, verdict_map)
            en zona AMBIGUO; debe devolver una decisión SQS_DECISION_*.

    Returns:
        tuple: (package_dir, classification, temp_dir). package_dir es None si
        el usuario abortó.
    """
    def progress(i, label):
        if on_progress:
            on_progress(i, label)

    temp_dir = process_input_file(input_file, base_dir)
    progress(1, "Ingesta y aislamiento")
    print(f"      Entorno aislado: {temp_dir}")

    analyze_static(input_file, temp_dir)
    progress(2, "Análisis estático")

    run_in_sandbox(input_file, temp_dir)
    progress(3, "Análisis dinámico")

    classification = classify_file(temp_dir)
    if classification is None:
        print("[!] No se pudieron cargar los reportes para clasificar.")
        sys.exit(1)
    progress(4, "Clasificación y veredicto")
    print(f"      Veredicto: {classification['verdict']} "
          f"(zona {classification.get('zone', '?')}, "
          f"riesgo {classification['risk_score']})")

    # Pausa en zona AMBIGUO para decisión humana
    if classification.get("zone") == "ambiguo" and decision_callback:
        verdict_map_path = os.path.join(temp_dir, "verdict_map.json")
        decision = decision_callback(classification, verdict_map_path)
        print(f"      Decisión del usuario: {decision}")

        if decision == DECISION_ABORTAR:
            return None, classification, temp_dir

        if decision == DECISION_FUERZA:
            verdict_map_path = os.path.join(temp_dir, "verdict_map.json")
            if os.path.exists(verdict_map_path):
                with open(verdict_map_path, encoding="utf-8") as f:
                    verdict_map = json.load(f)
                verdict_map["decision"] = DECISION_FUERZA
                with open(verdict_map_path, "w", encoding="utf-8") as f:
                    json.dump(verdict_map, f, indent=2)

    surgery = sanitize_file(input_file, temp_dir)
    progress(5, "Cirugía / saneamiento")
    print(f"      Estado cirugía: {surgery['surgery_status']}")

    verification = verify_integrity(input_file, temp_dir)
    progress(6, "Verificación de integridad")
    print(f"      Estado verificación: {verification['verification_status']}")

    package_dir = package_application(input_file, temp_dir, base_dir)
    progress(7, "Empaquetado final")
    print(f"      Paquete final: {package_dir}")

    return package_dir, classification, temp_dir


def main():
    parser = argparse.ArgumentParser(
        description="SQS - Sanitizador Quirúrgico de Software (pipeline 7 capas)")
    parser.add_argument("archivo", nargs="?", help="Ruta al archivo sospechoso")
    parser.add_argument("--gui", action="store_true",
                        help="Abrir la interfaz gráfica con los resultados")
    parser.add_argument("-o", "--output-dir", default=None,
                        help="Directorio base para los entornos y el paquete")
    parser.add_argument("--app", action="store_true",
                        help="Abrir la app gráfica con análisis interactivo")
    parser.add_argument("--analyze", action="store_true",
                        help="Solo capas 1-4 (veredicto, sin cirugía)")
    parser.add_argument("--surgery", action="store_true",
                        help="Forzar cirugía en zona ambiguo (sin preguntar)")
    parser.add_argument("--input", nargs="+", default=None,
                        help="Lote: archivos, directorios o ISOs")
    parser.add_argument("--batch", action="store_true",
                        help="Procesar por lotes (implica --input o dir/ISO)")
    args = parser.parse_args()

    if args.app:
        from sqs_gui import launch_app
        launch_app()
        return

    if not args.archivo and not args.input:
        parser.print_help()
        sys.exit(1)

    if not args.input and args.archivo and not os.path.exists(args.archivo):
        print(f"Error: El archivo {args.archivo} no existe.")
        sys.exit(1)

    batch_mode = (args.input is not None or args.batch or
                  (args.archivo is not None and
                   (os.path.isdir(args.archivo) or
                    args.archivo.lower().endswith(".iso"))))

    if batch_mode:
        from batch_processor import process_batch, _print_summary
        inputs = args.input if args.input is not None else [args.archivo]
        if args.surgery:
            cb = (lambda classification, verdict_map_path=None:
                  DECISION_FUERZA)
        else:
            cb = interactive_decision
        results = process_batch(inputs, base_dir=args.output_dir,
                                decision_callback=cb)
        _print_summary(results, args.output_dir or os.getcwd())
        if args.gui:
            from sqs_gui import launch_gui
            first = next((r for r in results if r.get("temp_dir")), None)
            if first:
                launch_gui(first["temp_dir"])
        return

    if args.analyze:
        classification, temp_dir = analyze_only(args.archivo,
                                                args.output_dir)
        print(f"\n[+] Análisis solo (capas 1-4).")
        print(f"    Veredicto: {classification['verdict']} "
              f"(zona {classification.get('zone', '?')}, "
              f"riesgo {classification['risk_score']})")
        print(f"    Datos:     {temp_dir}")
        if args.gui:
            from sqs_gui import launch_gui
            launch_gui(temp_dir)
        return

    decision_callback = interactive_decision
    if args.surgery:
        decision_callback = (
            lambda classification, verdict_map_path=None: DECISION_FUERZA)

    package_dir, classification, temp_dir = run_pipeline(
        args.archivo, args.output_dir, decision_callback=decision_callback)

    if package_dir is None:
        print("\n[!] Proceso abortado por decisión del usuario.")
        return

    print("\n[+] Proceso completado.")
    print(f"    Veredicto: {classification['verdict']} "
          f"(riesgo {classification['risk_score']})")
    print(f"    Paquete:   {package_dir}")
    print(f"    Datos:     {temp_dir}")

    if args.gui:
        from sqs_gui import launch_gui
        launch_gui(temp_dir)


if __name__ == "__main__":
    main()