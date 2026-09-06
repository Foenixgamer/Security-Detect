"""
Tests de las capacidades avanzadas del modelo expandido:

L2: strings / entropía / imports PE
L4: pesos configurables, zonas y verdict_map
L5: backup inmutable + parcheo binario + surgery_log con diff
L6: re-ejecución del saneado + final_report
L7: orquestador con decisión en zona AMBIGUO
"""

import json
import os
import struct
import sys
import tempfile
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "layers", "layer1"))

from strings_analyzer import extract_strings, suspicious_strings, entropy
from imports_analyzer import extract_pe_imports, suspicious_imports
import classification_layer
import surgery_layer
import integrity_verification_layer
import sqs
from sqs import run_pipeline


def _build_pe_with_imports():
    """PE32 de una sección con la importación de KERNEL32.WinExec."""
    buf = bytearray(0x500)
    buf[0:2] = b'MZ'
    struct.pack_into('<I', buf, 0x3C, 0x80)
    pe = 0x80
    buf[pe:pe + 4] = b'PE\x00\x00'
    coff = pe + 4
    struct.pack_into('<H', buf, coff + 0, 0x14c)
    struct.pack_into('<H', buf, coff + 2, 1)
    struct.pack_into('<I', buf, coff + 4, 0)
    struct.pack_into('<I', buf, coff + 8, 0)
    struct.pack_into('<I', buf, coff + 12, 0)
    struct.pack_into('<H', buf, coff + 16, 224)
    struct.pack_into('<H', buf, coff + 18, 0x0102)

    opt = coff + 20                      # 0x98
    struct.pack_into('<H', buf, opt, 0x10b)   # PE32
    # Directorio de imports: índice 1 en data directories (opt+96)
    struct.pack_into('<I', buf, opt + 96 + 8, 0x1000)   # import RVA
    struct.pack_into('<I', buf, opt + 96 + 12, 0x60)    # import size

    sect = opt + 224                     # tabla de secciones 0x178
    buf[sect:sect + 8] = b'.idata\x00\x00'
    struct.pack_into('<I', buf, sect + 8, 0x200)    # VirtualSize
    struct.pack_into('<I', buf, sect + 12, 0x1000)  # VirtualAddress
    struct.pack_into('<I', buf, sect + 16, 0x200)   # SizeOfRawData
    struct.pack_into('<I', buf, sect + 20, 0x200)   # PointerToRawData

    # Descriptores en RVA 0x1000 (file 0x200)
    struct.pack_into('<I', buf, 0x200, 0x1040)   # OriginalFirstThunk
    struct.pack_into('<I', buf, 0x200 + 12, 0x1060)   # Name -> KERNEL32.dll
    struct.pack_into('<I', buf, 0x200 + 16, 0x1020)   # FirstThunk
    # FirstThunk en RVA 0x1020 (file 0x220)
    struct.pack_into('<I', buf, 0x220, 0x1080)
    struct.pack_into('<I', buf, 0x224, 0)
    # OriginalFirstThunk en RVA 0x1040 (file 0x240)
    struct.pack_into('<I', buf, 0x240, 0x1080)
    struct.pack_into('<I', buf, 0x244, 0)
    # Nombre de DLL en RVA 0x1060 (file 0x260)
    buf[0x260:0x260 + 13] = b'KERNEL32.dll\x00'
    # Hint/Nombre en RVA 0x1080 (file 0x280)
    struct.pack_into('<H', buf, 0x280, 0)
    buf[0x282:0x282 + 8] = b'WinExec\x00'

    return bytes(buf)


class TestStringsAndEntropy(unittest.TestCase):

    def test_extract_strings(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.txt")
            with open(path, "w", encoding="ascii") as f:
                f.write("hello world")
            strings = extract_strings(path)
            self.assertTrue(any(s["string"] == "hello world"
                                for s in strings))

    def test_suspicious_strings(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.txt")
            with open(path, "w", encoding="ascii") as f:
                f.write("http://evil.example.com\npowershell\n-enc\nXQ==\n")
            found = suspicious_strings(extract_strings(path))
            patterns = {h["pattern"] for h in found}
            self.assertIn("URL (http/https)", patterns)
            self.assertTrue(any("PowerShell" in p for p in patterns))

    def test_entropy(self):
        self.assertEqual(entropy(b"\x41" * 4096), 0.0)
        self.assertAlmostEqual(entropy(bytes(range(256)) * 16), 8.0, delta=0.2)


class TestImportsAnalyzer(unittest.TestCase):

    def test_extract_imports(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "imports.exe")
            with open(path, "wb") as f:
                f.write(_build_pe_with_imports())

            imports = extract_pe_imports(path)
            self.assertTrue(imports)
            self.assertEqual(imports[0]["dll"], "KERNEL32.dll")
            self.assertIn("WinExec", imports[0]["functions"])

            flagged = suspicious_imports(imports)
            self.assertTrue(any(f["function"] == "WinExec" for f in flagged))


class TestClassificationSignals(unittest.TestCase):

    def _write_reports(self, base, static, dynamic, manifest=None):
        with open(os.path.join(base, "static_analysis.json"), "w",
                  encoding="utf-8") as f:
            json.dump(static, f)
        with open(os.path.join(base, "dynamic_report.json"), "w",
                  encoding="utf-8") as f:
            json.dump(dynamic, f)
        if manifest is not None:
            with open(os.path.join(base, "manifest.json"), "w",
                      encoding="utf-8") as f:
                json.dump(manifest, f)

    def test_static_signals(self):
        with tempfile.TemporaryDirectory() as base:
            static = {
                "is_executable": False,
                "static_analysis": {
                    "suspicious_strings_found": [{"string": "http://", "offset": 1}],
                    "suspicious_imports": [{"function": "WinExec"}],
                    "high_entropy_sections": [".text"],
                    "entropy": 7.9,
                    "packer_detected": ["UPX"],
                },
            }
            self._write_reports(base, static, {})
            classification = classification_layer.classify_file(base)
            self.assertEqual(classification["verdict"], "sospechoso")
            self.assertEqual(classification["zone"], "ambiguo")
            # 1 + 2 + 3 + 2 = 8
            self.assertEqual(classification["risk_score"], 8)

    def test_manifest_malicious(self):
        with tempfile.TemporaryDirectory() as base:
            static = {"is_executable": False, "static_analysis": {}}
            self._write_reports(
                base, static, {},
                manifest={"reputation": {"status": "malicious"}})
            classification = classification_layer.classify_file(base)
            self.assertEqual(classification["verdict"], "malicioso")
            self.assertEqual(classification["risk_score"], 10)

    def test_manifest_benign_caps_risk(self):
        with tempfile.TemporaryDirectory() as base:
            static = {"is_executable": True, "static_analysis": {}}
            dynamic = {"error": "fallo en sandbox"}
            # riesgo "puro": 2 + 5 = 7 -> sospechoso; benigno lo baja a < 5
            self._write_reports(
                base, static, dynamic,
                manifest={"reputation": {"status": "benign"}})
            classification = classification_layer.classify_file(base)
            self.assertEqual(classification["verdict"], "seguro")
            self.assertEqual(classification["zone"], "limpio")
            self.assertLess(classification["risk_score"], 5)

    def test_verdict_map_actions(self):
        with tempfile.TemporaryDirectory() as base:
            static = {
                "file_path": os.path.join(base, "payload"),
                "static_analysis": {
                    "suspicious_strings_found": [
                        {"string": "http://evil.com", "offset": 10,
                         "pattern": "URL (http/https)"}],
                },
            }
            self._write_reports(base, static, {})
            classification_layer.classify_file(base)

            with open(os.path.join(base, "verdict_map.json"),
                      encoding="utf-8") as f:
                verdict_map = json.load(f)
            patches = [a for a in verdict_map["actions"]
                       if a["type"] == "patch"]
            self.assertTrue(patches)
            self.assertEqual(patches[0]["offset"], 10)


class TestSurgeryPatching(unittest.TestCase):

    def test_nop_patch_with_diff_log(self):
        with tempfile.TemporaryDirectory() as base:
            payload = b"prefix http://evil.com suffix"
            offset = payload.index(b"http://evil.com")
            size = len(b"http://evil.com")

            input_file = os.path.join(base, "payload.bin")
            with open(input_file, "wb") as f:
                f.write(payload)

            with open(os.path.join(base, "classification.json"), "w",
                      encoding="utf-8") as f:
                json.dump({"verdict": "malicioso"}, f)
            with open(os.path.join(base, "verdict_map.json"), "w",
                      encoding="utf-8") as f:
                json.dump({
                    "verdict": "malicioso",
                    "zone": "malicioso",
                    "decision": None,
                    "components": [],
                    "actions": [{
                        "type": "patch", "offset": offset, "size": size,
                        "note": "URL (http/https)", "string": "http://evil.com",
                    }],
                }, f)

            report = surgery_layer.sanitize_file(input_file, base)

            self.assertEqual(report["surgery_status"], "completed")
            sanitized = os.path.join(base, "sanitized_payload.bin")
            self.assertTrue(os.path.isfile(sanitized))
            with open(sanitized, "rb") as f:
                out = f.read()
            self.assertEqual(out[offset:offset + size], b"\x90" * size)

            # El original no se toca
            with open(input_file, "rb") as f:
                self.assertEqual(f.read(), payload)

            # Backup inmutable
            backup = os.path.join(base, "backup", "payload.bin")
            self.assertTrue(os.path.isfile(backup))

            # Log de cirugía con diff exacto
            with open(os.path.join(base, "surgery_log.json"),
                      encoding="utf-8") as f:
                log = json.load(f)
            self.assertEqual(len(log["patches"]), 1)
            self.assertEqual(log["patches"][0]["offset"], offset)
            self.assertEqual(log["patches"][0]["original_hex"],
                             payload[offset:offset + size].hex())
            self.assertEqual(log["patches"][0]["new_hex"], "90" * size)


class TestVerificationRerun(unittest.TestCase):

    def test_rerun_and_final_report(self):
        with tempfile.TemporaryDirectory() as base:
            input_file = os.path.join(base, "payload.exe")
            with open(input_file, "wb") as f:
                f.write(b"MZ" + b"\x00" * 64)

            sanitized = os.path.join(base, "sanitized_payload.exe")
            with open(sanitized, "wb") as f:
                f.write(b"MZ" + b"\x00" * 64)

            with open(os.path.join(base, "classification.json"), "w",
                      encoding="utf-8") as f:
                json.dump({"verdict": "malicioso", "zone": "malicioso",
                           "risk_score": 13}, f)
            with open(os.path.join(base, "surgery_report.json"), "w",
                      encoding="utf-8") as f:
                json.dump({"sanitized_file": sanitized,
                           "surgery_status": "completed"}, f)
            with open(os.path.join(base, "dynamic_report.json"), "w",
                      encoding="utf-8") as f:
                json.dump({"error": "error original"}, f)

            verification = integrity_verification_layer.verify_integrity(
                input_file, base, timeout=5)

            self.assertTrue(
                os.path.isfile(os.path.join(base,
                                            "rerun_dynamic_report.json")))
            self.assertTrue(os.path.isfile(os.path.join(base,
                                                        "final_report.json")))
            self.assertIsNotNone(
                verification.get("malicious_behavior_removed"))

            with open(os.path.join(base, "final_report.json"),
                      encoding="utf-8") as f:
                final = json.load(f)
            self.assertIn("verification_status", final)
            self.assertIn("summary", final)


class TestOrchestratorDecisions(unittest.TestCase):

    def _fake_exe(self, base):
        path = os.path.join(base, "sospechoso.exe")
        with open(path, "wb") as f:
            f.write(b"MZ" + b"\x00" * 126)
        return path

    def test_abort_on_ambiguous(self):
        with tempfile.TemporaryDirectory() as base:
            input_file = self._fake_exe(base)
            package, classification, temp_dir = run_pipeline(
                input_file, base_dir=base,
                decision_callback=lambda c, v: sqs.DECISION_ABORTAR)
            self.assertEqual(classification["zone"], "ambiguo")
            self.assertIsNone(package)
            self.assertTrue(os.path.isdir(temp_dir))

    def test_force_surgery_on_ambiguous(self):
        with tempfile.TemporaryDirectory() as base:
            input_file = self._fake_exe(base)
            package, classification, temp_dir = run_pipeline(
                input_file, base_dir=base,
                decision_callback=lambda c, v: sqs.DECISION_FUERZA)
            self.assertEqual(classification["zone"], "ambiguo")
            self.assertIsNotNone(package)
            self.assertTrue(
                os.path.exists(os.path.join(temp_dir, "surgery_report.json")))
            with open(os.path.join(temp_dir, "surgery_report.json"),
                      encoding="utf-8") as f:
                surgery = json.load(f)
            self.assertEqual(surgery["surgery_status"], "completed")


if __name__ == "__main__":
    unittest.main()