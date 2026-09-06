"""
Análisis de la tabla de imports de binarios PE.

Parsea la tabla de imports (32/64 bits) para listar DLLs y funciones, y marca
combinaciones de APIs conocidamente abusadas por malware.
"""

import struct


# Diccionario de API sospechosas (nombres sin sufijo A/W): nombre -> motivo
_SUSPICIOUS_APIS = {
    "winexec": "ejecución de comandos",
    "shellexecute": "ejecución de comandos",
    "urldownloadtofile": "descarga remota",
    "createremotethread": "inyección de hilos",
    "createprocessasuser": "escalada de privilegios",
    "virtualallocex": "asignación de memoria remota",
    "writeprocessmemory": "escritura en memoria remota",
    "setwindowshookex": "hooking de sistema",
    "regsetvalueex": "persistencia en registro",
    "cryptencrypt": "ofuscación",
    "cryptdecrypt": "ofuscación",
    "internetopen": "actividad de red",
    "httpsendrequest": "actividad de red",
    "internetreadfile": "actividad de red",
    "loadlibrary": "carga dinámica de librerías",
    "getprocaddress": "resolución dinámica de APIs",
    "isdebuggerpresent": "anti-depuración",
    "checkremotedebuggerpresent": "anti-depuración",
    "outputdebugstring": "anti-depuración",
    "gettickcount": "anti-análisis/timing",
    "getsystemtimeasfiletime": "anti-análisis/timing",
}


def _read_pe_layout(file_path):
    """Lee el offset del PE header y la tabla de secciones."""
    with open(file_path, 'rb') as f:
        data = f.read()

    if len(data) < 0x40 or data[:2] != b'MZ':
        return None

    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
        return None

    n_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
    magic = struct.unpack_from('<H', data, pe_offset + 24)[0]

    if magic == 0x10b:      # PE32
        optional_header_size = 224
        data_dirs_offset = pe_offset + 24 + 96
    elif magic == 0x20b:    # PE32+
        optional_header_size = 240
        data_dirs_offset = pe_offset + 24 + 112
    else:
        return None

    section_table = pe_offset + 24 + optional_header_size
    sections = []
    for i in range(n_sections):
        off = section_table + i * 40
        if off + 40 > len(data):
            break
        sections.append({
            "name": data[off:off + 8].rstrip(b'\x00').decode('ascii',
                                                            errors='replace'),
            "virtual_address": struct.unpack_from('<I', data, off + 12)[0],
            "virtual_size": struct.unpack_from('<I', data, off + 8)[0],
            "raw_offset": struct.unpack_from('<I', data, off + 20)[0],
            "raw_size": struct.unpack_from('<I', data, off + 16)[0],
        })

    return {
        "data": data,
        "is_64": magic == 0x20b,
        "data_dirs_offset": data_dirs_offset,
        "sections": sections,
    }


def extract_pe_imports(file_path):
    """
    Extrae las DLLs y funciones importadas de un binario PE.

    Args:
        file_path (str): Ruta al archivo PE.

    Returns:
        list: Lista de dicts {"dll", "functions": [...], "ordinals": n}.
    """
    layout = _read_pe_layout(file_path)
    if layout is None:
        return []

    data = layout["data"]
    is_64 = layout["is_64"]
    sections = layout["sections"]

    def rva_to_offset(rva):
        for sec in sections:
            span = max(sec["virtual_size"], sec["raw_size"])
            if sec["virtual_address"] <= rva < sec["virtual_address"] + span:
                return sec["raw_offset"] + (rva - sec["virtual_address"])
        return None

    def read_cstring(offset, limit=256):
        if offset is None or offset < 0 or offset >= len(data):
            return ""
        end = data.find(b'\x00', offset, offset + limit)
        if end == -1:
            end = offset + limit
        try:
            return data[offset:end].decode('utf-8', errors='replace')
        except Exception:
            return ""

    # Directorio de imports: índice 1 de data directories
    import_rva = struct.unpack_from('<I', data, layout["data_dirs_offset"] + 8)[0]
    import_size = struct.unpack_from('<I', data, layout["data_dirs_offset"] + 12)[0]

    if import_rva == 0 or import_size == 0:
        return []

    desc_offset = rva_to_offset(import_rva)
    if desc_offset is None:
        return []

    thunk_size = 8 if is_64 else 4
    ordinal_flag = 0x8000000000000000 if is_64 else 0x80000000

    imports = []
    for _ in range(400):  # límite de DLLs
        if desc_offset + 20 > len(data):
            break

        name_rva = struct.unpack_from('<I', data, desc_offset + 12)[0]
        oft_rva = struct.unpack_from('<I', data, desc_offset + 0)[0]
        ft_rva = struct.unpack_from('<I', data, desc_offset + 16)[0]

        if name_rva == 0:
            break  # final de la tabla

        dll_name = read_cstring(rva_to_offset(name_rva))
        if not dll_name:
            dll_name = f"dll_{_}"

        functions = []
        ordinals = 0

        thunk_rva = oft_rva or ft_rva
        thunk_off = rva_to_offset(thunk_rva)
        if thunk_off is not None:
            for _ in range(2000):  # límite de thunks
                if thunk_off + thunk_size > len(data):
                    break
                value = struct.unpack_from('<Q' if is_64 else '<I',
                                           data, thunk_off)[0]
                if value == 0:
                    break

                if value & ordinal_flag:
                    ordinals += 1
                    functions.append(f"ordinal_{value & 0xFFFF}")
                else:
                    hint_rva = value & 0xFFFFFFFF
                    name = read_cstring(rva_to_offset(hint_rva + 2))
                    if name:
                        functions.append(name)
                thunk_off += thunk_size

        imports.append({
            "dll": dll_name,
            "functions": functions,
            "ordinals": ordinals,
        })
        desc_offset += 20

    return imports


def suspicious_imports(imports):
    """
    Marca funciones importadas con APIs abusadas por malware.

    Args:
        imports (list): Salida de extract_pe_imports.

    Returns:
        list: Lista de dicts {"dll", "function", "reason"}.
    """
    flagged = []
    for entry in imports:
        for fn in entry["functions"]:
            if fn.startswith("ordinal_"):
                continue
            normalized = fn.lower().rstrip("aw")
            if normalized in _SUSPICIOUS_APIS:
                flagged.append({
                    "dll": entry["dll"],
                    "function": fn,
                    "reason": _SUSPICIOUS_APIS[normalized],
                })
    return flagged