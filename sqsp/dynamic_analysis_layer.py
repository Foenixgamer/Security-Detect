"""
SQS - Capa 3: Análisis Dinámico (Sandbox).

Ejecuta el software en un entorno controlado registrando el comportamiento:
código de retorno, salida, duración y (en una implementación real) monitoreo de
syscalls, red y filesystem. Usa subprocess con timeout (multiplataforma) en
lugar del comando "timeout" de Linux.
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _THIS_DIR)
sys.path.insert(0, os.path.join(_THIS_DIR, 'layers', 'layer1'))

try:
    from file_type_detector import detect_file_type
except ImportError:
    detect_file_type = None

_EXEC_EXTENSIONS = {".exe", ".dll", ".com", ".bat", ".cmd", ".sh",
                    ".ps1", ".elf", ".bin", ".out", ".so", ".dylib"}


def _looks_executable(file_path):
    """Determina si el archivo es ejecutable (magic bytes o extensión)."""
    if detect_file_type is not None:
        try:
            if detect_file_type(file_path) in ("PE", "ELF", "Mach-O"):
                return True
        except Exception:
            pass
    return os.path.splitext(file_path)[1].lower() in _EXEC_EXTENSIONS


def _docker_sandbox_enabled():
    """Sandbox Docker activado con la variable de entorno SQS_DOCKER."""
    return os.getenv("SQS_DOCKER", "").strip().lower() in ("1", "true", "yes")


def run_in_sandbox(file_path, temp_dir=".", timeout=30, report_name="dynamic_report.json"):
    """
    Ejecuta el archivo en el entorno controlado (simulado) y guarda el
    reporte en <temp_dir>/<report_name>.

    Con SQS_DOCKER=1 y Docker disponible usa un contenedor descartable
    (sandbox/docker_runner.py); si no hay Docker, vuelve al sandbox local.

    Args:
        file_path (str): Ruta al archivo a ejecutar.
        temp_dir (str): Directorio del entorno aislado.
        timeout (int): Límite de ejecución en segundos.
        report_name (str): Nombre del archivo de reporte a generar.

    Returns:
        dict: Reporte dinámico.
    """
    sandbox_config = {
        "timestamp": datetime.now().isoformat(),
        "file_to_execute": os.path.abspath(file_path),
        "sandbox_id": f"sandbox_{int(time.monotonic() * 1000)}",
        "execution_log": [],
        "network_activity": [],
        "filesystem_changes": []
    }

    if not _looks_executable(file_path):
        sandbox_config["note"] = (
            "El archivo no parece ejecutable; se omitió la ejecución en sandbox. "
            "En una implementación con sandbox real (hooking de syscalls, red y "
            "filesystem) aquí se registraría el comportamiento.")

    docker_ran = False
    if _looks_executable(file_path):
        # Sandbox Docker opcional (SQS_DOCKER=1)
        if _docker_sandbox_enabled():
            try:
                from sandbox.docker_runner import run_in_docker
                docker_report = run_in_docker(file_path, temp_dir,
                                              timeout=timeout)
                if not docker_report.get("docker_unavailable"):
                    docker_ran = True
                    docker_report["sandbox_id"] = docker_report.get(
                        "sandbox_id") or sandbox_config["sandbox_id"]
                    sandbox_config = docker_report
                else:
                    sandbox_config["note"] = (
                        "Docker no disponible; usando sandbox local.")
            except Exception as e:
                sandbox_config["note"] = (
                    f"Sandbox Docker con error; usando sandbox local: {e}")

        if not docker_ran:
            start = time.monotonic()
            try:
                result = subprocess.run(
                    [file_path], capture_output=True, text=True, shell=False,
                    timeout=timeout)

                sandbox_config["execution_log"].append({
                    "command": [file_path],
                    "return_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "duration_seconds": round(time.monotonic() - start, 3)
                })

            except subprocess.TimeoutExpired:
                err = f"Timeout: el proceso excedió el límite de {timeout} segundos"
                sandbox_config["error"] = err
                sandbox_config["execution_log"].append({
                    "command": [file_path],
                    "return_code": None,
                    "stdout": "",
                    "stderr": err,
                    "duration_seconds": round(time.monotonic() - start, 3)
                })

            except Exception as e:
                sandbox_config["error"] = \
                    f"No se pudo ejecutar en sandbox: {e}"

    os.makedirs(temp_dir, exist_ok=True)
    with open(os.path.join(temp_dir, report_name), "w",
              encoding="utf-8") as f:
        json.dump(sandbox_config, f, indent=2)

    return sandbox_config


def main():
    if len(sys.argv) != 2:
        print("Uso: python dynamic_analysis_layer.py <ruta_archivo>")
        sys.exit(1)

    temp_dir = os.getenv("TEMP_DIR", ".")
    report = run_in_sandbox(sys.argv[1], temp_dir)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()