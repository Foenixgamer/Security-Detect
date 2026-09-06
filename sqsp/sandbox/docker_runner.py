"""
SQS - Sandbox Docker opcional (Capa 3).

Ejecuta el archivo en un contenedor descartable (`docker run --rm`) con límites
de memoria/CPU, sin red y con el directorio del entorno montado de solo lectura.

Se activa con la variable de entorno SQS_DOCKER=1 en `dynamic_analysis_layer`.
Si Docker no está disponible, la capa 3 cae al sandbox local (subprocess).

El reporte sigue la misma estructura que dynamic_report.json.
"""

import json
import os
import subprocess
import time
from datetime import datetime

_RUNNER_SCRIPT = r"""
import json, subprocess, sys, time
target = sys.argv[1]
timeout = int(sys.argv[2])
t0 = time.monotonic()
try:
    r = subprocess.run([target], capture_output=True, text=True,
                       timeout=timeout)
    print(json.dumps({
        "return_code": r.returncode,
        "stdout": (r.stdout or "")[:4000],
        "stderr": (r.stderr or "")[:4000],
        "duration_seconds": round(time.monotonic() - t0, 3),
        "error": None,
    }))
except subprocess.TimeoutExpired:
    print(json.dumps({
        "return_code": None, "stdout": "", "stderr": "",
        "duration_seconds": round(time.monotonic() - t0, 3),
        "error": "timeout %ds" % timeout,
    }))
except Exception as e:
    print(json.dumps({
        "return_code": None, "stdout": "", "stderr": str(e),
        "duration_seconds": round(time.monotonic() - t0, 3),
        "error": str(e),
    }))
"""

_DEFAULT_IMAGE = "python:3.12-slim"


def docker_available():
    """Comprueba si el daemon de Docker responde."""
    try:
        result = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True, text=True, timeout=10)
        return result.returncode == 0 and bool(result.stdout.strip())
    except Exception:
        return False


def run_in_docker(file_path, temp_dir=".", timeout=30, image=_DEFAULT_IMAGE):
    """
    Ejecuta `file_path` en un contenedor descartable y registra el resultado.

    Returns:
        dict: Reporte dinámico (estructura de dynamic_report.json) o
        {"docker_unavailable": True, "error": ...} si Docker no está disponible.
    """
    report = {
        "timestamp": datetime.now().isoformat(),
        "backend": "docker",
        "image": image,
        "file_to_execute": os.path.abspath(file_path),
        "sandbox_id": f"docker_{int(time.monotonic() * 1000)}",
        "execution_log": [],
        "network_activity": [],
        "filesystem_changes": [],
    }

    if not docker_available():
        report["docker_unavailable"] = True
        report["error"] = "Docker no disponible; use el sandbox local."
        return report

    target_basename = os.path.basename(file_path)
    in_container = f"/work/{target_basename}"

    os.makedirs(temp_dir, exist_ok=True)
    runner_host = os.path.join(temp_dir, "_docker_runner.py")
    with open(runner_host, "w", encoding="utf-8") as f:
        f.write(_RUNNER_SCRIPT.lstrip())

    docker_cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "--cpus", "1",
        "--memory", "256m",
        "--name", f"sqs_{int(time.monotonic() * 1000)}",
        "-v", f"{os.path.abspath(temp_dir)}:/work:ro",
        image,
        "python", "/work/_docker_runner.py", in_container, str(timeout),
    ]

    start = time.monotonic()
    try:
        result = subprocess.run(docker_cmd, capture_output=True, text=True,
                                timeout=timeout + 60)
        stdout = (result.stdout or "").strip()
        entry = None

        # El runner imprime JSON en la última línea de stdout
        for line in reversed(stdout.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except Exception:
                entry = None
            break

        if entry is None:
            report["error"] = (result.stderr or "").strip()[:500] or (
                f"Código de retorno {result.returncode}")
        else:
            if entry.get("error"):
                report["error"] = entry["error"]
            else:
                report["note"] = ("El archivo se ejecutó en contenedor Linux "
                                  "descartable sin red.")
            report["execution_log"].append({
                "command": [in_container],
                "return_code": entry.get("return_code"),
                "stdout": entry.get("stdout", ""),
                "stderr": entry.get("stderr", ""),
                "duration_seconds": entry.get("duration_seconds"),
            })
    except subprocess.TimeoutExpired:
        report["error"] = f"Timeout: el contenedor excedió {timeout} segundos"
    except Exception as e:
        report["error"] = f"No se pudo ejecutar en Docker: {e}"

    return report