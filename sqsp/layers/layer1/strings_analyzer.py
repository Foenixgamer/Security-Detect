"""
Análisis de strings y entropía.

Extrae cadenas legibles, calcula entropía de Shannon (por sección o bloque) y
detecta patrones de texto sospechosos. Base para la Capa 2 (Análisis Estático).
"""

import math
import os


def extract_strings(file_path, min_length=4, max_count=2000):
    """
    Extrae cadenas ASCII legibles del archivo junto con su offset.

    Args:
        file_path (str): Ruta al archivo.
        min_length (int): Longitud mínima de la cadena.
        max_count (int): Límite de cadenas a devolver.

    Returns:
        list: Lista de dicts {"string", "offset"}.
    """
    with open(file_path, 'rb') as f:
        data = f.read()

    strings = []
    seen = set()
    run = bytearray()
    start = 0

    for i, byte in enumerate(data):
        if 0x20 <= byte <= 0x7E:
            if not run:
                start = i
            run.append(byte)
        else:
            if len(run) >= min_length:
                s = bytes(run).decode('ascii')
                if s not in seen:
                    seen.add(s)
                    strings.append({"string": s, "offset": start})
                    if len(strings) >= max_count:
                        return strings
            run = bytearray()

    if len(run) >= min_length and len(strings) < max_count:
        s = bytes(run).decode('ascii')
        if s not in seen:
            strings.append({"string": s, "offset": start})

    return strings


def entropy(data):
    """
    Entropía de Shannon (0..8) de un bloque de bytes.

    Args:
        data (bytes): Bloque a analizar.

    Returns:
        float: Entropía en bits por byte.
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    total = 0.0
    for c in counts:
        if c:
            p = c / length
            total -= p * math.log2(p)
    return round(total, 3)


def file_entropy(file_path):
    """Entropía de Shannon del archivo completo."""
    with open(file_path, 'rb') as f:
        return entropy(f.read())


def entropy_by_block(file_path, block_size=4096, max_blocks=256):
    """
    Entropía por bloque de bytes. Útil para detectar zonas empacadas/cifradas.

    Returns:
        list: Lista de dicts {"block", "offset", "size", "entropy"}.
    """
    with open(file_path, 'rb') as f:
        data = f.read()

    result = []
    for i in range(0, len(data), block_size):
        if len(result) >= max_blocks:
            break
        chunk = data[i:i + block_size]
        result.append({
            "block": i // block_size,
            "offset": i,
            "size": len(chunk),
            "entropy": entropy(chunk)
        })
    return result


def entropy_by_sections(file_path, sections):
    """
    Entropía de cada sección conocida (PE/ELF) a partir de offset/tamaño.

    Args:
        sections (list): Salida de section_extractor (offset, size).

    Returns:
        list: Lista de dicts {"name", "offset", "size", "entropy"}.
    """
    with open(file_path, 'rb') as f:
        data = f.read()

    result = []
    for sec in sections:
        off = sec.get("offset") or 0
        size = sec.get("size") or 0
        chunk = data[off:off + size]
        result.append({
            "name": sec.get("name", "?"),
            "offset": off,
            "size": len(chunk),
            "entropy": entropy(chunk)
        })
    return result


_SUSPICIOUS_PATTERNS = [
    (rb"http://", "URL (http/https)"),
    (rb"https://", "URL (http/https)"),
    (rb"ftp://", "URL (ftp)"),
    (b"powershell", "PowerShell"),
    (b"-enc", "PowerShell -enc (ofuscación)"),
    (b"cmd.exe", "cmd.exe"),
    (b"/c ", "cmd /c"),
    (b"WScript.Shell", "WScript.Shell (COM)"),
    (b".DownloadFile", "Descarga remota (.DownloadFile)"),
    (b"whoami", "whoami"),
    (b"netstat", "netstat"),
    (b"Invoke-", "Invoke-* (PowerShell)"),
    (b"schtasks", "Persistencia (schtasks)"),
    (b"reg add", "Modificación de registro"),
    (b"Mimikatz", "Herramienta de dump de credenciales"),
    (b"CreateRemoteThread", "Inyección de hilos"),
]


def _looks_base64(s):
    if len(s) < 40:
        return False
    return all(c.isalnum() or c in "+/=" for c in s)


def suspicious_strings(strings):
    """
    Filtra cadenas con patrones sospechosos.

    Args:
        strings (list): Salida de extract_strings.

    Returns:
        list: Lista de dicts {"string", "offset", "pattern"}.
    """
    found = []
    for item in strings:
        s = item["string"]
        b = s.encode('ascii', errors='ignore')
        for pattern, label in _SUSPICIOUS_PATTERNS:
            if pattern in b:
                found.append({
                    "string": s,
                    "offset": item["offset"],
                    "pattern": label
                })
                break
        else:
            if _looks_base64(s):
                found.append({
                    "string": s,
                    "offset": item["offset"],
                    "pattern": "Posible payload base64"
                })
    return found