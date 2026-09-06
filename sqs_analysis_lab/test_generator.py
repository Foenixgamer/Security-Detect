"""
Generador de prueba sintética para el smoke test de SQS.

Crea UN módulo de prueba (test_synth_module.exe): un PE32 minimalista e INERTE
con imports literales y cadenas de texto que el pipeline detecta como
indicadores. No contiene código ejecutable (no hay entry point ni payload).

Este generador NO crea malware: es el artefacto que el pipeline SQS debe
detectar, poner en cuarentena, sanear (NOP) y empaquetar como artefacto
"limpio y utilizable" en la prueba de humo.
"""

import os
import struct


def build_pe(import_names):
    """PE32 mínimo de una sección que importa funciones de KERNEL32.

    Estructura validada por test_advanced.py (fixture), generalizada a
    varios imports con stride de 32 bytes entre hint+nombre.
    """
    buf = bytearray(0x800)
    buf[0:2] = b'MZ'
    struct.pack_into('<I', buf, 0x3C, 0x80)          # e_lfanew
    pe = 0x80
    buf[pe:pe + 4] = b'PE\x00\x00'
    coff = pe + 4                                     # 0x84
    struct.pack_into('<H', buf, coff + 0, 0x14C)      # i386
    struct.pack_into('<H', buf, coff + 2, 1)          # 1 sección
    struct.pack_into('<H', buf, coff + 16, 224)       # optional header size
    struct.pack_into('<H', buf, coff + 18, 0x0102)    # characteristics

    opt = coff + 20                                   # 0x98
    struct.pack_into('<H', buf, opt, 0x10B)           # PE32
    struct.pack_into('<I', buf, opt + 96 + 8, 0x1000)
    struct.pack_into('<I', buf, opt + 96 + 12, 0x60)

    sect = opt + 224                                  # 0x178
    buf[sect:sect + 8] = b'.idata\x00\x00'
    struct.pack_into('<I', buf, sect + 8, 0x200)
    struct.pack_into('<I', buf, sect + 12, 0x1000)
    struct.pack_into('<I', buf, sect + 16, 0x200)
    struct.pack_into('<I', buf, sect + 20, 0x200)

    step = 32
    struct.pack_into('<I', buf, 0x200, 0x1040)        # orig first thunk
    struct.pack_into('<I', buf, 0x200 + 12, 0x1060)   # KERNEL32.dll name
    struct.pack_into('<I', buf, 0x200 + 16, 0x1020)   # first thunk
    buf[0x260:0x260 + 13] = b'KERNEL32.dll\x00'

    for i, fn in enumerate(import_names):
        struct.pack_into('<I', buf, 0x220 + i * 4, 0x1080 + i * step)
        struct.pack_into('<I', buf, 0x240 + i * 4, 0x1080 + i * step)
        struct.pack_into('<H', buf, 0x280 + i * step, 0)
        name = fn.encode('ascii').rstrip(b'\x00')
        buf[0x282 + i * step:0x282 + i * step + len(name)] = name
    struct.pack_into('<I', buf, 0x220 + len(import_names) * 4, 0)
    struct.pack_into('<I', buf, 0x240 + len(import_names) * 4, 0)

    return bytes(buf)


def create_synth_test(out_dir="."):
    """Crea el módulo sintético y devuelve su ruta absoluta."""
    labels = (
        b"# SQS-SYNTHETIC-TEST (inert education payload - NOT REAL MALWARE)\n"
        b"test_synth_module - componente sospechoso de prueba\n"
        b"http://synthetic.test.example/agent.exe\n"
        b"schtasks /create /tn SynthUpdater /tr updater.exe /sc onlogon\n"
        b"netstat -ano\n"
        b"reg add HKCU\\Software\\Synthetic /v updater\n")

    payload = (build_pe(["CreateRemoteThread", "IsDebuggerPresent"]) +
               b'\n[STRINGS]\n' + labels + b'\n')

    path = os.path.join(out_dir, "test_synth_module.exe")
    with open(path, "wb") as f:
        f.write(payload)
    return os.path.abspath(path)


if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    path = create_synth_test(out)
    print(f"[+] Módulo sintético creado: {path} "
          f"({os.path.getsize(path)} bytes)")