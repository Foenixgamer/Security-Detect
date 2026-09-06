"""
SQS - Guarda defensivo (control de evasión).

Garantiza que las herramientas del proyecto (generadores de muestras, scripts
de prueba, documentación de acciones) sean estrictamente DEFENSIVAS: ninguna
acción registrada puede describir técnicas de evasión, ofuscación o
anti-detección. Si algo lo intenta, se levanta una SecurityViolation y el
proceso se detiene.

Uso:
    from security_guard import check_action, scan_artifact

    check_action("Parcheo NOP de funciones maliciosas en binario")   # OK
    check_action("Evasion de antivirus mediante ofuscacion")          # SecurityViolation

    issues = scan_artifact(ruta_de_archivo)   # lista de coincidencias (vacía = seguro)
"""

import os

# Términos que describen técnicas de evasión/ocultamiento de payload.
# Cualquiera de ellos en una acción o contenido invalida la operación.
_EVASIVE_TERMS = (
    "evasion",
    "evasión",
    "bypass antivirus",
    "anti-detection",
    "anti low",
    "antidetect",
    "payload_hiding",
    "malware_obfuscation",
    "ofuscación de malware",
    "rootkit",
    "credential theft",
    "c2 beacon",
    "command and control",
)

# Términos inocuos que el propio proyecto usa en contexto defensivo
# (etiquetas del análisis) y que no deben disparar alarma.
_WHITELIST = (
    "ofuscación (opcional)",
    "anti-depuración",
    "anti-análisis/timing",
    "dump de credenciales",
)


class SecurityViolation(Exception):
    """Acción o contenido prohibido (evasión/ocultamiento)."""


def check_action(action_description):
    """
    Verifica que una descripción de acción sea defensiva.

    Args:
        action_description (str): Descripción de la acción a ejecutar.

    Returns:
        bool: True si la acción es defensiva.

    Raises:
        SecurityViolation: si se detecta un término de evasión.
    """
    text = str(action_description or "").lower()
    if not text:
        raise SecurityViolation("Acción vacía no permitida.")
    for prohibited in _EVASIVE_TERMS:
        if prohibited in text:
            raise SecurityViolation(
                f"Acción prohibida detectada: {action_description}")
    return True


def _looks_whitelisted(line):
    lowered = line.lower()
    return any(w in lowered for w in _WHITELIST)


def scan_content(text):
    """
    Escanea contenido en busca de términos de evasión.

    Returns:
        list: Coincidencias detectadas (vacío = cuenta aprobada).
    """
    hits = []
    for line in (text or "").splitlines():
        lowered = line.lower()
        if _looks_whitelisted(line):
            continue
        for prohibited in _EVASIVE_TERMS:
            if prohibited in lowered:
                hits.append(f"{prohibited!r} en: {line.strip()[:80]}")
    return hits


def scan_artifact(path):
    """
    Escanea un archivo (muestra, script, reporte) en busca de evasión.

    Returns:
        list: Coincidencias (vacío = contenido defensivo/aseguro).
    """
    if not os.path.isfile(path):
        return ["archivo no encontrado"]
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        return [f"no se pudo leer: {e}"]
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = raw.decode("latin-1", errors="replace")
    return scan_content(text)