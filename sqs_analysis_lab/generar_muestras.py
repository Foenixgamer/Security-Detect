"""
Generador de muestras EDUCATIVAS para SQS.

Cada muestra es un archivo INERTE: un PE32 mínimo de juguete con una tabla de
imports literalmente en bytes + cadenas de texto ASCII con indicadores de
malware (http, schtasks, netstat, reg add, ...). NINGUNO de estos archivos
ejecuta código: no tienen entry point real, ni payload ejecutable, ni
libreto de propagación. Sirven únicamente para que el pipeline SQS (7 capas)
demuestre detección por firmas/imports/rules, cuarentena y saneamiento en un
entorno aislado.

Uso:
    python generar_muestras.py [directorio_de_salida]
"""

import os
import struct
import sys


def build_pe(import_names):
    """PE32 mínimo de una sección (.idata) que importa names de KERNEL32.

    La estructura copia el fixture ya validado por test_advanced.py
    (_build_pe_with_imports) y lo generaliza a N imports por nombre.
    """
    buf = bytearray(0x800)
    buf[0:2] = b'MZ'
    struct.pack_into('<I', buf, 0x3C, 0x80)          # e_lfanew
    pe = 0x80
    buf[pe:pe + 4] = b'PE\x00\x00'
    coff = pe + 4                                      # 0x84
    struct.pack_into('<H', buf, coff + 0, 0x14C)       # machine i386
    struct.pack_into('<H', buf, coff + 2, 1)           # 1 sección
    struct.pack_into('<H', buf, coff + 16, 224)        # size optional header
    struct.pack_into('<H', buf, coff + 18, 0x0102)     # characteristics

    opt = coff + 20                                    # 0x98
    struct.pack_into('<H', buf, opt, 0x10B)            # PE32
    struct.pack_into('<I', buf, opt + 96 + 8, 0x1000)  # import dir RVA
    struct.pack_into('<I', buf, opt + 96 + 12, 0x60)   # import dir size

    sect = opt + 224                                   # 0x178
    buf[sect:sect + 8] = b'.idata\x00\x00'
    struct.pack_into('<I', buf, sect + 8, 0x200)       # VirtualSize
    struct.pack_into('<I', buf, sect + 12, 0x1000)     # VirtualAddress
    struct.pack_into('<I', buf, sect + 16, 0x200)      # SizeOfRawData
    struct.pack_into('<I', buf, sect + 20, 0x200)      # PointerToRawData

    # Descriptor de imports en RVA 0x1000 (file 0x200)
    orig_thunk = 0x1040                                # file 0x240
    first_thunk = 0x1020                               # file 0x220
    dll_name_rva = 0x1060                              # file 0x260
    name_base = 0x1080                                 # file 0x280 (0x282+)
    step = 32                                          # hint+nombre por entrada
    struct.pack_into('<I', buf, 0x200, orig_thunk)
    struct.pack_into('<I', buf, 0x200 + 12, dll_name_rva)
    struct.pack_into('<I', buf, 0x200 + 16, first_thunk)
    buf[0x260:0x260 + 13] = b'KERNEL32.dll\x00'

    for i, fn in enumerate(import_names):
        struct.pack_into('<I', buf, 0x220 + i * 4, name_base + i * step)
        struct.pack_into('<I', buf, 0x240 + i * 4, name_base + i * step)
        struct.pack_into('<H', buf, 0x280 + i * step, 0)
        name = fn.encode('ascii').rstrip(b'\x00')
        buf[0x282 + i * step:0x282 + i * step + len(name)] = name
    # terminadores nulos de las thunk arrays
    struct.pack_into('<I', buf, 0x220 + len(import_names) * 4, 0)
    struct.pack_into('<I', buf, 0x240 + len(import_names) * 4, 0)

    return bytes(buf)


def write_sample(path, import_names, indicator_text):
    pe = build_pe(import_names)
    body = pe + b'\n[STRINGS]\n' + indicator_text + b'\n'
    with open(path, 'wb') as f:
        f.write(body)
    return path


INDICATORS = {
    "game_crack.exe": {
        "imports": ["CreateRemoteThread", "IsDebuggerPresent"],
        "text": (
            b"GameCrack payload\n"
            b"http://update.gamecrack.example/agent.exe\n"
            b"schtasks /create /tn GameUpdater /tr updater.exe /sc onlogon\n"
            b"netstat -ano\n"
            b"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
            b"/v GameCrack /d updater.exe\n"
            b"whoami /all\n"),
    },
    "game_loader.dll": {
        "imports": ["WinExec", "VirtualAllocEx"],
        "text": (
            b"GameLoader v3.2 (pirata)\n"
            b"https://dl.gamecrack.example/loader.bin\n"
            b"powershell -enc SQBFAFgA\n"),
    },
    "miner.exe": {
        "imports": ["CreateRemoteThread", "UrlDownloadToFile",
                    "LoadLibraryA"],
        "text": (
            b"XMRig 6.9 fork\n"
            b"stratum+tcp://pool.gamecrack.example:4444\n"
            b"http://update.gamecrack.example/xmrig.exe\n"
            b"netstat -an | findstr ESTABLISHED\n"),
    },
    "game_helper.dll": {
        "imports": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                    "GetTickCount"],
        "text": (
            b"GameHelper anti-cheat (crackeado)\n"
            b"reg add HKLM\\SOFTWARE\\Microsoft\\Shadow /v kb\ndump\n"),
    },
    "activador.txt": {
        "imports": [],
        "text": b"Tu activador con el parche ya esta dentro del paquete.\n",
    },
}


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "muestras"
    os.makedirs(out_dir, exist_ok=True)
    for name, spec in INDICATORS.items():
        path = os.path.join(out_dir, name)
        write_sample(path, spec["imports"], spec["text"])
        size = os.path.getsize(path)
        print(f"[+] {name} ({size} bytes, imports={spec['imports']})")


if __name__ == "__main__":
    main()