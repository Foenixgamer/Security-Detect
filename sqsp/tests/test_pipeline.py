"""
Tests del pipeline SQS (7 capas) y de los módulos de capas 1-7.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import ingestion_layer
import static_analysis_layer
import classification_layer
import surgery_layer
import integrity_verification_layer
import packaging_layer
import sqs_gui
from sqs import run_pipeline


class TestIngestion(unittest.TestCase):

    def test_ingestion_hash_and_report(self):
        with tempfile.TemporaryDirectory() as base:
            input_file = os.path.join(base, "scan_me.txt")
            with open(input_file, "wb") as f:
                f.write(b"hello world")

            temp_dir = ingestion_layer.process_input_file(input_file, base)

            self.assertTrue(os.path.isdir(temp_dir))
            report_path = os.path.join(temp_dir, "report.json")
            self.assertTrue(os.path.isfile(report_path))

            with open(report_path, encoding="utf-8") as f:
                report = json.load(f)

            expected_hash = hashlib.sha256(b"hello world").hexdigest()
            self.assertEqual(report["file_hash"], expected_hash)
            self.assertEqual(report["status"], "ingested")
            self.assertEqual(report["input_file"],
                             os.path.abspath(input_file))

    def test_ingestion_missing_file(self):
        with tempfile.TemporaryDirectory() as base:
            with self.assertRaises(FileNotFoundError):
                ingestion_layer.process_input_file(
                    os.path.join(base, "no_existe.bin"), base)


class TestClassification(unittest.TestCase):

    def _seed(self, base_dir, static, dynamic):
        input_file = os.path.join(base_dir, "payload.exe")
        with open(input_file, "wb") as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 60)

        with open(os.path.join(base_dir, "static_analysis.json"), "w",
                  encoding="utf-8") as f:
            json.dump(static, f)
        with open(os.path.join(base_dir, "dynamic_report.json"), "w",
                  encoding="utf-8") as f:
            json.dump(dynamic, f)
        return input_file

    def _static_executable(self):
        return {
            "timestamp": "2024-01-01T00:00:00",
            "file_path": "payload.exe",
            "mime_type": "application/x-dosexec",
            "size_bytes": 64,
            "is_executable": True,
            "permissions": "755",
            "static_analysis": {
                "file_signature": "PE",
                "architecture": "x86-64 (AMD64)",
                "compiled_with": "PE32",
                "sections": []},
        }

    def test_classify_malicioso(self):
        with tempfile.TemporaryDirectory() as base:
            dynamic = {
                "timestamp": "2024-01-01T00:00:00",
                "file_to_execute": "payload.exe",
                "sandbox_id": "sandbox_1",
                "execution_log": [],
                "network_activity": ["conn: 10.0.0.5:4444"],
                "filesystem_changes": ["C:/suspicious/payload.dll"],
                "error": "No se pudo ejecutar en sandbox: WinError 193",
            }
            input_file = self._seed(base, self._static_executable(), dynamic)

            classification = classification_layer.classify_file(base)

            self.assertIsNotNone(classification)
            # riesgo: ejecutable(2) + error(5) + red(3) + fs(3) = 13
            self.assertEqual(classification["verdict"], "malicioso")
            self.assertEqual(classification["risk_score"], 13)
            self.assertTrue(classification["threats_found"])
            self.assertTrue(os.path.isfile(os.path.join(base, "classification.json")))

            surgery = surgery_layer.sanitize_file(input_file, base)
            self.assertEqual(surgery["surgery_status"], "completed")
            self.assertTrue(os.path.isfile(surgery["sanitized_file"]))

            verification = integrity_verification_layer.verify_integrity(
                input_file, base)
            self.assertIn("original_file_hash", verification)
            # El saneado es una copia idéntica => hashes coinciden
            self.assertFalse(verification["differences_detected"])
            self.assertTrue(os.path.isfile(
                os.path.join(base, "integrity_verification.json")))

            package = packaging_layer.package_application(input_file, base, base)
            self.assertIsNotNone(package)
            self.assertTrue(os.path.isfile(os.path.join(package, "complete_report.json")))
            with open(os.path.join(package, "README.md"), encoding="utf-8") as f:
                self.assertIn("malicioso", f.read())

    def test_classify_sospechoso(self):
        with tempfile.TemporaryDirectory() as base:
            dynamic = {
                "timestamp": "2024-01-01T00:00:00",
                "file_to_execute": "payload.exe",
                "sandbox_id": "sandbox_2",
                "execution_log": [],
                "network_activity": [],
                "filesystem_changes": [],
                "error": "Timeout: el proceso excedió el límite",
            }
            self._seed(base, self._static_executable(), dynamic)

            classification = classification_layer.classify_file(base)

            # riesgo: ejecutable(2) + error(5) = 7
            self.assertEqual(classification["verdict"], "sospechoso")
            self.assertEqual(classification["risk_score"], 7)

    def test_classify_seguro(self):
        with tempfile.TemporaryDirectory() as base:
            static = self._static_executable()
            static["is_executable"] = False
            dynamic = {
                "timestamp": "2024-01-01T00:00:00",
                "file_to_execute": "payload.exe",
                "sandbox_id": "sandbox_3",
                "execution_log": [],
                "network_activity": [],
                "filesystem_changes": [],
            }
            self._seed(base, static, dynamic)

            classification = classification_layer.classify_file(base)

            self.assertEqual(classification["verdict"], "seguro")
            self.assertEqual(classification["risk_score"], 0)

    def test_surgery_not_needed(self):
        with tempfile.TemporaryDirectory() as base:
            static = self._static_executable()
            static["is_executable"] = False
            self._seed(base, static, {
                "timestamp": "2024-01-01T00:00:00",
                "file_to_execute": "x",
                "sandbox_id": "s",
                "execution_log": [],
                "network_activity": [],
                "filesystem_changes": [],
            })
            input_file = os.path.join(base, "payload.exe")

            classification_layer.classify_file(base)
            surgery = surgery_layer.sanitize_file(input_file, base)

            self.assertEqual(surgery["surgery_status"], "not_needed")
            self.assertIsNone(surgery["sanitized_file"])
            # reporte también se escribe para que el pipeline continúe
            self.assertTrue(os.path.isfile(
                os.path.join(base, "surgery_report.json")))

    def test_classify_missing_reports(self):
        with tempfile.TemporaryDirectory() as base:
            self.assertIsNone(classification_layer.classify_file(base))


class TestStaticAnalysis(unittest.TestCase):

    def test_guess_mime_no_executable(self):
        with tempfile.TemporaryDirectory() as base:
            input_file = os.path.join(base, "note.txt")
            with open(input_file, "w", encoding="utf-8") as f:
                f.write("texto plano")

            report = static_analysis_layer.analyze_static(input_file, base)

            self.assertEqual(report["mime_type"], "text/plain")
            self.assertFalse(report["is_executable"])
            report_path = os.path.join(base, "static_analysis.json")
            self.assertTrue(os.path.isfile(report_path))


class TestPipeline(unittest.TestCase):

    def test_pipeline_benigno_end_to_end(self):
        with tempfile.TemporaryDirectory() as base:
            input_file = os.path.join(base, "scan_me.txt")
            with open(input_file, "w", encoding="utf-8") as f:
                f.write("hello world")

            package_dir, classification, temp_dir = run_pipeline(
                input_file, base_dir=base)

            self.assertEqual(classification["verdict"], "seguro")
            self.assertEqual(classification["risk_score"], 0)

            for report_name in ("report.json", "static_analysis.json",
                                "dynamic_report.json", "classification.json",
                                "surgery_report.json",
                                "integrity_verification.json"):
                self.assertTrue(os.path.isfile(
                    os.path.join(temp_dir, report_name)),
                    f"falta {report_name}")

            with open(os.path.join(temp_dir, "surgery_report.json"),
                      encoding="utf-8") as f:
                surgery = json.load(f)
            self.assertEqual(surgery["surgery_status"], "not_needed")

            with open(os.path.join(temp_dir, "integrity_verification.json"),
                      encoding="utf-8") as f:
                verification = json.load(f)
            self.assertEqual(verification["verification_status"], "skipped")

            self.assertTrue(os.path.isdir(package_dir))
            self.assertTrue(os.path.isfile(
                os.path.join(package_dir, "complete_report.json")))
            self.assertTrue(os.path.isfile(
                os.path.join(package_dir, "README.md")))


class TestGUIHelpers(unittest.TestCase):

    def test_export_html(self):
        with tempfile.TemporaryDirectory() as base:
            input_file = os.path.join(base, "scan_me.txt")
            with open(input_file, "w", encoding="utf-8") as f:
                f.write("hello world")

            package_dir, _, temp_dir = run_pipeline(input_file, base_dir=base)

            dest = os.path.join(base, "out.html")
            sqs_gui.export_html(temp_dir, dest)
            self.assertTrue(os.path.isfile(dest))
            with open(dest, encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Veredicto", content)
            self.assertIn("seguro", content)

            reports = sqs_gui.load_reports(temp_dir)
            self.assertIn("classification", reports)


if __name__ == "__main__":
    unittest.main()