"""
SQS - Conector VirusTotal (verificación externa por hash / subida).

Usa exclusivamente la stdlib (urllib) para evitar dependencias.
El hash SHA256 se consulta en https://www.virustotal.com/api/v3/files/<hash>
y, si no existe en la base de datos, se sube el archivo y se consulta el
informe generado (modo bajo demanda).

El API Key se guarda fuera del código (archivo local `.sqs_vt_key`), nunca en
el repositorio ni en logs. Sin clave configurada, las funciones de red lanzan
VTConfigError; el resto (hash, utilidades) siempre funcionan sin red.

Las funciones de red son mockeables: en los tests se sustituye `urlopen`
para no tocar Internet.
"""

import hashlib
import json
import mimetypes
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_KEY_FILE = os.path.join(_THIS_DIR, ".sqs_vt_key")

_API = "https://www.virustotal.com/api/v3"
TIMEOUT = 20


class VTError(Exception):
    """Error general de la conexión a VirusTotal."""


class VTConfigError(VTError):
    """API Key no configurada."""


class VTNotFound(VTError):
    """El hash aún no aparece en la base de datos de VirusTotal.

    Se usa para decidir si conviene subir el archivo.
    """


def key_file_path():
    """Ruta del archivo local de API Key (sobrescribible por entorno)."""
    return os.environ.get("SQS_VT_KEY_FILE", DEFAULT_KEY_FILE)


def save_api_key(api_key):
    """Persiste la API Key en un archivo local con permisos restringidos."""
    api_key = (api_key or "").strip()
    path = key_file_path()
    if not api_key:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        return False
    with open(path, "w", encoding="ascii") as f:
        f.write(api_key + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return True


def load_api_key():
    """Devuelve la API Key guardada (o "")."""
    try:
        with open(key_file_path(), encoding="ascii") as f:
            return f.read().strip()
    except OSError:
        return ""


def file_sha256(path):
    """Hash SHA256 de un archivo (None si no se puede leer)."""
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, IOError):
        return None


def _http_json(url, api_key, data=None, headers=None):
    """GET/POST JSON contra la API de VT usando urllib (stdlib)."""
    req_headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": "SQS-pipeline/1.0",
    }
    if headers:
        req_headers.update(headers)
    body = None
    if data is not None:
        body = data.encode("utf-8")
        req_headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(url, data=body, headers=req_headers)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise VTNotFound(
                f"Hash no encontrado en VirusTotal (HTTP 404)") from e
        try:
            detail = e.read().decode("utf-8", errors="replace")[:300]
        except Exception:
            detail = ""
        raise VTError(f"HTTP {e.code}: {detail}") from e
    except urllib.error.URLError as e:
        raise VTError(f"Error de red: {e.reason}") from e


def _post_multipart(url, api_key, file_path):
    """Sube un archivo como multipart/form-data (sin requests)."""
    boundary = "----SQS" + datetime.now().strftime("%Y%m%d%H%M%S%f")
    filename = os.path.basename(file_path)
    ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    with open(file_path, "rb") as f:
        content = f.read()
    parts = []
    parts.append(f"--{boundary}\r\n".encode("ascii"))
    parts.append(
        (f'Content-Disposition: form-data; name="file"; '
         f'filename="{filename}"\r\n').encode("utf-8"))
    parts.append(f"Content-Type: {ctype}\r\n\r\n".encode("ascii"))
    parts.append(content)
    parts.append(f"\r\n--{boundary}--\r\n".encode("ascii"))
    body = b"".join(parts)
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }
    request = urllib.request.Request(url, data=body)
    request.add_header("x-apikey", api_key)
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", "SQS-pipeline/1.0")
    for k, v in headers.items():
        request.add_header(k, v)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", errors="replace")[:300]
        except Exception:
            detail = ""
        raise VTError(f"HTTP {e.code} al subir archivo: {detail}") from e
    except urllib.error.URLError as e:
        raise VTError(f"Error de red al subir archivo: {e.reason}") from e


def _check_key(api_key):
    key = (api_key or "").strip()
    if not key:
        raise VTConfigError(
            "API Key de VirusTotal no configurada (usa 'Guardar' en la app)")
    return key


def fetch_file_report(api_key, sha256):
    """
    Consulta el informe por hash SHA256.

    Returns:
        dict: atributos del informe (data.attributes) o {"status":
        "not_found"}.

    Raises:
        VTConfigError / VTError.
    """
    key = _check_key(api_key)
    try:
        payload = _http_json(f"{_API}/files/{sha256}", key)
    except VTNotFound:
        return {"status": "not_found"}
    data = payload.get("data") or {}
    return data.get("attributes") or {}


def submit_file(api_key, file_path):
    """Sube un archivo y devuelve el id del análisis a encolar."""
    key = _check_key(api_key)
    payload = _post_multipart(f"{_API}/files", key, file_path)
    data = payload.get("data") or {}
    return (data.get("id") or "").strip()


def fetch_analysis(api_key, analysis_id, retries=20, delay=3):
    """
    Espera (polling) al informe de un análisis y devuelve
    last_analysis_stats. El calling thread espera hasta retries*delay.
    """
    key = _check_key(api_key)
    import time
    stats = {}
    status = "unknown"
    for _ in range(retries):
        payload = _http_json(f"{_API}/analyses/{analysis_id}", key)
        data = payload.get("data") or {}
        attr = data.get("attributes") or {}
        status = attr.get("status") or "queued"
        if status == "completed":
            stats = (attr.get("stats") or
                     (attr.get("results") or {}).get("stats") or {})
            break
        time.sleep(delay)
    stats.setdefault("status", status)
    return stats


def scan_url(api_key, url):
    """
    Encola un escaneo de URL en VirusTotal (POST /urls).

    Returns:
        str: id del análisis (para fetch_analysis).

    Raises:
        VTConfigError / VTError.
    """
    import urllib.parse
    key = _check_key(api_key)
    payload = _http_json(
        f"{_API}/urls", key,
        data=urllib.parse.urlencode({"url": url}))
    data = payload.get("data") or {}
    return (data.get("id") or "").strip()


def analyze_file(api_key, file_path, submit_if_not_found=True,
                 retries=20, delay=2):
    """
    Flujo completo por archivo: hash -> informe -> (opcional) subida.

    Returns:
        dict: {hash, found, malicious, suspicious, undetected, status,
        error?, engines?}

    Raises:
        VTConfigError / VTError (red, límite de API, etc.) salvo
        not-found sin subida (devuelve status "not_found").
    """
    key = _check_key(api_key)
    sha = file_sha256(file_path)
    if not sha:
        raise VTError(f"No se pudo calcular el hash de {file_path}")
    report = fetch_file_report(key, sha)
    if report.get("status") == "not_found":
        if not submit_if_not_found:
            return {
                "hash": sha, "found": False, "malicious": 0,
                "suspicious": 0, "undetected": 0,
                "status": "not_found", "engines": [],
            }
        analysis_id = submit_file(key, file_path)
        if not analysis_id:
            raise VTError("VirusTotal no devolvió id de análisis")
        stats = fetch_analysis(key, analysis_id, retries=retries,
                               delay=delay)
    else:
        stats = report.get("last_analysis_stats") or {}

    engines = []
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    for rule in (report.get("last_analysis_results") or {}).values():
        if rule and rule.get("category") == "malicious":
            engines.append(rule.get("result", rule.get("engine_name", "?")))
    return {
        "hash": sha,
        "found": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "status": stats.get("status", "completed"),
        "engines": engines[:10],
    }