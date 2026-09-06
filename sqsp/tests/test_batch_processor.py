"""
Tests del procesamiento por lotes (batch_processor.py):
archivo único, directorio, ISO y verificación batch sobre el pipeline real.
"""

import json
import os
import struct
import sys
import tempfile
import unittest
from unittest import mock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import batch_processor
import sqs


def _build_pe(import_names):
    """PE32 mínimo (validado en test_advanced) con imports nombrados."""
    buf = bytearray(0x800)
    buf[0:2] = b'MZ'
    struct.pack_into('<I', buf, 0x3C, 0x80)
    pe = 0x80
    buf[pe:pe + 4] = b'PE\x00\x00'
    coff = pe + 4
    struct.pack_into('<H', buf, coff + 0, 0x14C)
    struct.pack_into('<H', buf, coff + 2, 1)
    struct.pack_into('<H', buf, coff + 16, 224)
    struct.pack_into('<H', buf, coff + 18, 0x0102)
    opt = coff + 20
    struct.pack_into('<H', buf, opt, 0x10B)
    struct.pack_into('<I', buf, opt + 96 + 8, 0x1000)
    struct.pack_into('<I', buf, opt + 96 + 12, 0x60)
    sect = opt + 224
    buf[sect:sect + 8] = b'.idata\x00\x00'
    struct.pack_into('<I', buf, sect + 8, 0x200)
    struct.pack_into('<I', buf, sect + 12, 0x1000)
    struct.pack_into('<I', buf, sect + 16, 0x200)
    struct.pack_into('<I', buf, sect + 20, 0x200)
    struct.pack_into('<I', buf, 0x200, 0x1040)
    struct.pack_into('<I', buf, 0x200 + 12, 0x1060)
    struct.pack_into('<I', buf, 0x200 + 16, 0x1020)
    buf[0x260:0x260 + 13] = b'KERNEL32.dll\x00'
    step = 32
    for i, fn in enumerate(import_names):
        struct.pack_into('<I', buf, 0x220 + i * 4, 0x1080 + i * step)
        struct.pack_into('<I', buf, 0x240 + i * 4, 0x1080 + i * step)
        struct.pack_into('<H', buf, 0x280 + i * step, 0)
        name = fn.encode('ascii').rstrip(b'\x00')
        buf[0x282 + i * step:0x282 + i * step + len(name)] = name
    struct.pack_into('<I', buf, 0x220 + len(import_names) * 4, 0)
    struct.pack_into('<I', buf, 0x240 + len(import_names) * 4, 0)
    return bytes(buf)


def _write_pe(dir_path, name, imports):
    path = os.path.join(dir_path, name)
    with open(path, "wb") as f:
        f.write(_build_pe(imports))
    return path


class TestTargets(unittest.TestCase):

    def test_is_target_file_extensions(self):
        self.assertTrue(batch_processor.is_target_file("x.exe"))
        self.assertTrue(batch_processor.is_target_file("y.DLL"))
        self.assertTrue(batch_processor.is_target_file("z.vbs"))
        self.assertFalse(batch_processor.is_target_file("readme.txt"))
        self.assertFalse(batch_processor.is_target_file("A.PNG"))

    def test_resolve_single_file(self):
        with tempfile.TemporaryDirectory() as base:
            f = _write_pe(base, "a.exe", ["WinExec"])
            resolved = batch_processor.resolve_inputs([f])
            self.assertEqual([os.path.abspath(f)], resolved)

    def test_resolve_directory_filters(self):
        with tempfile.TemporaryDirectory() as base:
            _write_pe(base, "a.exe", ["WinExec"])
            _write_pe(base, "b.dll", ["WinExec"])
            with open(os.path.join(base, "leeme.txt"), "w") as f:
                f.write("no")
            resolved = batch_processor.resolve_inputs([base])
            self.assertEqual(2, len(resolved))
            self.assertTrue(any(r.endswith(".exe") for r in resolved))
            self.assertTrue(any(r.endswith(".dll") for r in resolved))

    def test_resolve_iso_stays_as_input(self):
        with tempfile.TemporaryDirectory() as base:
            iso = os.path.join(base, "instalador.iso")
            with open(iso, "wb") as f:
                f.write(b"\x00" * 64)
            self.assertEqual([os.path.abspath(iso)],
                             batch_processor.resolve_inputs([iso]))


class TestISO(unittest.TestCase):

    def test_extract_iso_no_extractor_raises(self):
        with tempfile.TemporaryDirectory() as base:
            iso = os.path.join(base, "a.iso")
            with open(iso, "wb") as f:
                f.write(b"x" * 64)
            with mock.patch.object(batch_processor, "_find_extractor",
                                   return_value=""):
                with self.assertRaises(RuntimeError):
                    batch_processor.extract_iso(iso, os.path.join(base, "d"))

    def test_extract_iso_success_with(self):
        with tempfile.TemporaryDirectory() as base:
            dest = os.path.join(base, "d")
            os.makedirs(dest, exist_ok=True)
            with open(os.path.join(dest, "in.txt"), "w") as f:
                f.write("x")
            fake = mock.Mock()
            fake.returncode = 0
            fake.stderr = b""
            with mock.patch.object(batch_processor, "_find_extractor",
                                   return_value="tools/7z.exe"):
                with mock.patch.object(batch_processor.subprocess, "run",
                                       return_value=fake):
                    self.assertTrue(
                        batch_processor.extract_iso("a.iso", dest))


class TestArchives(unittest.TestCase):

    def _make_zip(self, zip_path, entries):
        import zipfile
        with zipfile.ZipFile(zip_path, "w",
                             zipfile.ZIP_DEFLATED) as z:
            for name, data in entries.items():
                z.writestr(name, data)

    def test_zip_end_to_end_and_cleanup(self):
        with tempfile.TemporaryDirectory() as base:
            pe = _build_pe(["CreateRemoteThread", "IsDebuggerPresent"])
            zip_path = os.path.join(base, "paquete.zip")
            self._make_zip(zip_path, {"sub/virus.exe": pe,
                                      "leeme.txt": b"no"})
            out = os.path.join(base, "out")
            results = batch_processor.process_batch([zip_path],
                                                    base_dir=out)
            self.assertEqual(1, len(results))
            r = results[0]
            self.assertEqual(r["status"], "ok")
            self.assertEqual(r["classification"]["verdict"], "malicioso")
            self.assertEqual(r["surgery_status"], "completed")
            self.assertTrue(r["sanitized_file"])
            scratch = os.path.join(out, "batch_scratch")
            self.assertTrue(os.path.isdir(scratch))
            rest = [n for n in os.listdir(scratch)
                    if n.startswith("arch_")]
            self.assertEqual([], rest,
                             "temporales de extracción no limpiados")

    def test_tar_end_to_end(self):
        import tarfile
        import io
        with tempfile.TemporaryDirectory() as base:
            pe = _build_pe(["CreateRemoteThread", "IsDebuggerPresent"])
            tar_path = os.path.join(base, "pkg.tar")
            with tarfile.open(tar_path, "w") as t:
                info = tarfile.TarInfo("payload.exe")
                info.size = len(pe)
                t.addfile(info, io.BytesIO(pe))
            results = batch_processor.process_batch(
                [tar_path], base_dir=os.path.join(base, "out"))
            self.assertEqual(1, len(results))
            self.assertEqual(results[0]["status"], "ok")
            self.assertEqual(results[0]["classification"]["verdict"],
                             "malicioso")

    def test_resolve_keeps_archives_inside_dir(self):
        with tempfile.TemporaryDirectory() as base:
            d = os.path.join(base, "d")
            os.makedirs(d, exist_ok=True)
            zip_path = os.path.join(d, "a.zip")
            self._make_zip(zip_path, {"x.exe": _build_pe(["WinExec"])})
            resolved = batch_processor.resolve_inputs([d])
            self.assertIn(os.path.abspath(zip_path), resolved)


class TestExport(unittest.TestCase):

    def test_write_csv_summary(self):
        with tempfile.TemporaryDirectory() as base:
            _write_pe(base, "a.exe", ["WinExec"])
            out = os.path.join(base, "out")
            results = batch_processor.process_batch(
                [base], base_dir=out, analyze_only=True)
            csv_path = os.path.join(base, "resumen.csv")
            batch_processor.write_csv_summary(results, csv_path)
            with open(csv_path, encoding="utf-8-sig") as f:
                content = f.read()
            self.assertIn("archivo,estado,veredicto", content)
            self.assertIn("a.exe", content)


class TestBatch(unittest.TestCase):

    def test_process_batch_end_to_end_malicioso(self):
        with tempfile.TemporaryDirectory() as base:
            src = os.path.join(base, "src")
            os.makedirs(src, exist_ok=True)
            _write_pe(src, "virus.exe", ["CreateRemoteThread",
                                         "IsDebuggerPresent"])
            with open(os.path.join(src, "leeme.txt"), "w") as f:
                f.write("ignorado")

            out = os.path.join(base, "out")
            results = batch_processor.process_batch([src], base_dir=out)

            self.assertEqual(1, len(results))
            r = results[0]
            self.assertEqual(r["status"], "ok")
            self.assertEqual(r["classification"]["verdict"], "malicioso")
            self.assertGreaterEqual(r["classification"]["risk_score"], 10)
            self.assertEqual(r["surgery_status"], "completed")
            self.assertTrue(r["sanitized_file"])
            self.assertTrue(os.path.isdir(r["package_dir"]))

            report_path = os.path.join(out, "batch_report.json")
            self.assertTrue(os.path.isfile(report_path))
            with open(report_path, encoding="utf-8") as f:
                report = json.load(f)
            self.assertEqual(report["total"], 1)
            self.assertEqual(report["cleaned"], 1)

    def test_process_batch_continues_on_error(self):
        with tempfile.TemporaryDirectory() as base:
            missing = os.path.join(base, "no_existe.exe")
            good = _write_pe(base, "bien.exe", ["WinExec"])
            results = batch_processor.process_batch(
                [missing, good], base_dir=os.path.join(base, "out"))
            self.assertEqual(2, len(results))
            statuses = {r["status"] for r in results}
            self.assertEqual({"ok", "error"}, statuses)
            errored = next(r for r in results if r["status"] == "error")
            self.assertIn("no_existe", os.path.basename(errored["input"]))

    def test_analyze_only_detects_without_modifying(self):
        with tempfile.TemporaryDirectory() as base:
            sample = _write_pe(base, "virus.exe",
                               ["CreateRemoteThread", "IsDebuggerPresent"])
            out = os.path.join(base, "out")
            results = batch_processor.process_batch(
                [sample], base_dir=out, analyze_only=True)
            r = results[0]
            self.assertEqual(r["status"], "ok")
            self.assertEqual(r["classification"]["verdict"], "malicioso")
            self.assertIsNone(r["package_dir"])
            self.assertIsNone(r["sanitized_file"])
            self.assertIsNone(r["surgery_status"])
            self.assertTrue(r["temp_dir"])
            self.assertFalse(
                any(n.startswith("final_package") for n in os.listdir(out)))

    def test_decision_callback_forces_surgery(self):
        with tempfile.TemporaryDirectory() as base:
            sample = _write_pe(base, "sospechoso.exe", ["WinExec"])
            results = batch_processor.process_batch(
                [sample], base_dir=os.path.join(base, "out"),
                decision_callback=lambda c, v=None: sqs.DECISION_FUERZA)
            r = results[0]
            self.assertEqual(r["status"], "ok")
            self.assertEqual(r["classification"]["verdict"], "sospechoso")
            self.assertEqual(r["surgery_status"], "completed")
            self.assertTrue(r["sanitized_file"])

    def test_on_file_done_callback(self):
        with tempfile.TemporaryDirectory() as base:
            _write_pe(base, "virus.exe", ["WinExec"])
            seen = []
            batch_processor.process_batch(
                [base], base_dir=os.path.join(base, "out"),
                on_file_done=lambda entry: seen.append(entry["input"]))
            self.assertEqual(1, len(seen))

    def test_should_stop(self):
        with tempfile.TemporaryDirectory() as base:
            _write_pe(base, "a.exe", ["WinExec"])
            _write_pe(base, "b.exe", ["WinExec"])
            calls = {"n": 0}

            def stop():
                calls["n"] += 1
                return calls["n"] > 1

            results = batch_processor.process_batch(
                [base], base_dir=os.path.join(base, "out"),
                should_stop=stop)
            self.assertEqual(0, len(results))


if __name__ == "__main__":
    unittest.main()