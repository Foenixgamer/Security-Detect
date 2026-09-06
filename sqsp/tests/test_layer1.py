"""
Tests unitarios para Layer 1.
"""

import os
import struct
import sys
import tempfile
import unittest

# Añadir el directorio de las capas al path (ruta absoluta, independiente del cwd)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, 'layers', 'layer1'))

from file_type_detector import detect_file_type
from header_analyzer import analyze_pe_header, analyze_elf_header
from section_extractor import extract_sections
from metadata_collector import collect_metadata


def _build_pe_fixture():
    """Construye un archivo PE sintético minimalista."""
    buf = bytearray(512)
    buf[0:2] = b'MZ'
    struct.pack_into('<I', buf, 0x3C, 0x80)  # e_lfanew -> offset del PE header

    pe = 0x80
    buf[pe:pe + 4] = b'PE\x00\x00'
    coff = pe + 4
    struct.pack_into('<H', buf, coff + 0, 0x14c)   # machine (x86)
    struct.pack_into('<H', buf, coff + 2, 2)       # number_of_sections
    struct.pack_into('<I', buf, coff + 4, 0)       # time_date_stamp
    struct.pack_into('<I', buf, coff + 8, 0)       # pointer_to_symbol_table
    struct.pack_into('<I', buf, coff + 12, 0)      # number_of_symbols
    struct.pack_into('<H', buf, coff + 16, 224)    # size_of_optional_header
    struct.pack_into('<H', buf, coff + 18, 0x0102) # characteristics

    opt = coff + 20
    struct.pack_into('<H', buf, opt, 0x10b)        # magic PE32

    sect_start = opt + 224
    entries = [
        (b'.text\x00\x00\x00', 0x100, 0x1000, 0x200, 0x200),
        (b'.data\x00\x00\x00', 0x50,  0x2000, 0x100, 0x400),
    ]
    for i, (name, vsz, va, szraw, ptrraw) in enumerate(entries):
        off = sect_start + i * 40
        buf[off:off + 8] = name
        struct.pack_into('<I', buf, off + 8, vsz)
        struct.pack_into('<I', buf, off + 12, va)
        struct.pack_into('<I', buf, off + 16, szraw)
        struct.pack_into('<I', buf, off + 20, ptrraw)
    return bytes(buf)


def _build_elf_fixture():
    """Construye un archivo ELF64 sintético con .text y .shstrtab."""
    shoff = 64                     # tabla de secciones justo después del header
    shstr = b'\x00.text\x00.shstrtab\x00'   # ".text" en offset 1, ".shstrtab" en offset 7
    text_data = b'\x90\x90\xc3'
    shstr_off = shoff + 3 * 64
    text_off = shstr_off + len(shstr)

    e_ident = b'\x7fELF' + bytes([2, 1, 1, 0, 0]) + bytes(7)
    eh = struct.pack('<HHIQQQIHHHHHH',
                     2,           # e_type (ET_EXEC)
                     0x3e,        # e_machine (x86-64)
                     1,           # e_version
                     0x400000,    # e_entry
                     0,           # e_phoff
                     shoff,       # e_shoff
                     0,           # e_flags
                     64,          # e_ehsize
                     0, 0,        # e_phentsize, e_phnum
                     64,          # e_shentsize
                     3,           # e_shnum
                     2)           # e_shstrndx
    header = e_ident + eh
    assert len(header) == 64

    entries = [
        struct.pack('<IIQQQQIIQQ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        struct.pack('<IIQQQQIIQQ', 1, 1, 6, 0x400000, text_off, 3, 0, 0, 0, 0),
        struct.pack('<IIQQQQIIQQ', 7, 3, 0, 0, shstr_off, len(shstr), 0, 0, 0, 0),
    ]

    buf = bytearray(b'\x00' * (text_off + len(text_data)))
    buf[:len(header)] = header
    buf[shoff:shoff + 3 * 64] = b''.join(entries)
    buf[shstr_off:shstr_off + len(shstr)] = shstr
    buf[text_off:text_off + len(text_data)] = text_data
    return bytes(buf)


class TestLayer1(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.dir = self.tmpdir.name
        self.pe_file = self._write('sample.exe', _build_pe_fixture())
        self.elf_file = self._write('sample.elf', _build_elf_fixture())

    def _write(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, 'wb') as f:
            f.write(data)
        return path

    # --- file_type_detector ---

    def test_detect_file_type_pe(self):
        self.assertEqual(detect_file_type(self.pe_file), "PE")

    def test_detect_file_type_elf(self):
        self.assertEqual(detect_file_type(self.elf_file), "ELF")

    def test_detect_file_type_macho(self):
        macho_big = self._write('big.bin', b'\xcf\xfa\xed\xfe' + b'\x00' * 12)
        macho_little = self._write('little.bin', b'\xce\xfa\xed\xfe' + b'\x00' * 12)
        self.assertEqual(detect_file_type(macho_big), "Mach-O")
        self.assertEqual(detect_file_type(macho_little), "Mach-O")

    def test_detect_file_type_unknown(self):
        unknown = self._write('data.bin', b'\x00' * 8)
        self.assertEqual(detect_file_type(unknown), "UNKNOWN")

    def test_detect_file_type_missing(self):
        with self.assertRaises(FileNotFoundError):
            detect_file_type(os.path.join(self.dir, 'no_existe.bin'))

    # --- header_analyzer ---

    def test_analyze_pe_header(self):
        info = analyze_pe_header(self.pe_file)
        self.assertEqual(info['signature'], 'PE')
        self.assertEqual(info['machine'], hex(0x14c))
        self.assertEqual(info['number_of_sections'], 2)

    def test_analyze_elf_header(self):
        info = analyze_elf_header(self.elf_file)
        self.assertEqual(info['class'], 2)
        self.assertEqual(info['data'], 1)
        self.assertEqual(info['type'], 2)
        self.assertEqual(info['entry_point'], hex(0x400000))
        self.assertEqual(info['shnum'], 3)
        self.assertEqual(info['shstrndx'], 2)

    # --- section_extractor ---

    def test_extract_pe_sections(self):
        sections = extract_sections(self.pe_file, "PE")
        self.assertEqual(len(sections), 2)
        self.assertEqual(sections[0]['name'], '.text')
        self.assertEqual(sections[0]['offset'], 0x200)
        self.assertEqual(sections[0]['size'], 0x200)
        self.assertEqual(sections[1]['name'], '.data')

    def test_extract_elf_sections(self):
        sections = extract_sections(self.elf_file, "ELF")
        self.assertEqual(len(sections), 3)
        self.assertEqual(sections[1]['name'], '.text')
        self.assertEqual(sections[2]['name'], '.shstrtab')
        self.assertEqual(sections[1]['size'], 3)
        self.assertGreater(sections[1]['offset'], 0)

    def test_extract_sections_unsupported(self):
        with self.assertRaises(ValueError):
            extract_sections(self.pe_file, "MACHO")

    # --- metadata_collector ---

    def test_collect_metadata(self):
        meta = collect_metadata(self.pe_file)
        self.assertIsInstance(meta, dict)
        self.assertEqual(meta['file_path'], self.pe_file)
        self.assertGreater(meta['size_bytes'], 0)
        self.assertIn('created_time', meta)
        self.assertIn('modified_time', meta)


if __name__ == "__main__":
    unittest.main()