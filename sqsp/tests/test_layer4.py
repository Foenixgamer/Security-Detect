"""Tests de la Capa 4: layer4_report_generator (spec de capas).

Verifica generación del informe final a partir de Capa 1/2/3, tolerancia a
datos faltantes, conteos del resumen, exportación JSON/HTML/CSV y escape de
contenido en el HTML.
"""

import json
import os
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_THIS_DIR)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from layer4_report_generator import (
    build_report,
    export_to_csv,
    export_to_html,
    generate_final_report,
)


class TestLayer4(unittest.TestCase):
    def setUp(self):
        self.layer1_data = [
            {"path": "app.exe", "type": "executable", "size": 1024},
            {"path": "script.py", "type": "script", "size": 512},
        ]
        self.layer2_data = [
            {"component": "app.exe", "execution_time": 1.2, "exit_code": 0},
            {"component": "script.py", "execution_time": 0.5, "exit_code": 0},
        ]
        self.layer3_data = [
            {"component": "app.exe", "vulnerabilities": ["No firmado"],
             "risk_level": "medio"},
            {"component": "script.py", "vulnerabilities": [], "risk_level": "bajo"},
        ]

    def test_generate_final_report(self):
        report = generate_final_report(self.layer1_data, self.layer2_data,
                                       self.layer3_data)

        self.assertIn("timestamp", report)
        self.assertIn("summary", report)
        self.assertIn("components", report)
        self.assertIn("vulnerabilities", report)

        component_paths = [c["component"]["path"]
                           for c in report["components"]]
        self.assertIn("app.exe", component_paths)
        self.assertIn("script.py", component_paths)

    def test_summary_counts(self):
        report = build_report(self.layer1_data, self.layer2_data,
                              self.layer3_data)
        summary = report["summary"]
        self.assertEqual(summary["total_components"], 2)
        self.assertEqual(summary["executables"], 1)
        self.assertEqual(summary["scripts"], 1)
        self.assertEqual(summary["others"], 0)
        self.assertEqual(summary["risk_distribution"],
                         {"bajo": 1, "medio": 1, "alto": 0})

    def test_missing_type_counts_as_other(self):
        report = build_report([{"path": "x.bin", "size": 1},
                               {"path": "y.txt", "type": "other", "size": 2}],
                              [], [])
        summary = report["summary"]
        self.assertEqual(summary["others"], 2)
        self.assertEqual(summary["executables"], 0)
        self.assertEqual(summary["scripts"], 0)

    def test_missing_dynamic_analysis_is_none(self):
        report = build_report([{"path": "app.exe", "type": "executable"}],
                              [], self.layer3_data)
        entry = report["components"][0]
        self.assertIsNone(entry["dynamic_analysis"])
        self.assertEqual(entry["vulnerabilities"]["risk_level"], "medio")

    def test_missing_vulnerability_is_none(self):
        report = build_report([{"path": "app.exe", "type": "executable"}],
                              self.layer2_data, [])
        entry = report["components"][0]
        self.assertIsNone(entry["vulnerabilities"])
        self.assertEqual(entry["dynamic_analysis"]["exit_code"], 0)

    def test_vulnerability_summary_only_with_issues(self):
        report = build_report(self.layer1_data, self.layer2_data,
                              self.layer3_data)
        self.assertEqual(len(report["vulnerabilities"]), 1)
        self.assertEqual(report["vulnerabilities"][0]["component"], "app.exe")
        self.assertEqual(report["vulnerabilities"][0]["issues"], ["No firmado"])

    def test_json_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "final_report.json")
            report = generate_final_report(self.layer1_data, self.layer2_data,
                                           self.layer3_data, out)
            with open(out, encoding="utf-8") as f:
                loaded = json.load(f)
        self.assertEqual(loaded.keys(), report.keys())
        self.assertEqual(loaded["summary"]["total_components"], 2)

    def test_export_to_html(self):
        report = build_report(self.layer1_data, self.layer2_data,
                              self.layer3_data)
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "final_report.html")
            path = export_to_html(report, out)
            with open(path, encoding="utf-8") as f:
                content = f.read()
        self.assertEqual(path, out)
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("app.exe", content)
        self.assertIn("Informe de Seguridad del Paquete", content)
        self.assertIn("No firmado", content)

    def test_html_escapes_content(self):
        evil = [{"path": "<script>alert(1)</script>", "type": "script"}]
        report = build_report(evil, [], [])
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "esc.html")
            export_to_html(report, out)
            with open(out, encoding="utf-8") as f:
                content = f.read()
        self.assertNotIn("<script>alert(1)</script>", content)
        self.assertIn("&lt;script&gt;", content)

    def test_export_to_csv(self):
        report = build_report(self.layer1_data, self.layer2_data,
                              self.layer3_data)
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "final_report.csv")
            path = export_to_csv(report, out)
            with open(path, encoding="utf-8", newline="") as f:
                rows = list(__import__("csv").reader(f))
        self.assertEqual(rows[0],
                         ["component", "type", "risk_level", "exit_code",
                          "issues"])
        app_row = [r for r in rows if r[0] == "app.exe"]
        self.assertEqual(len(app_row), 1)
        self.assertEqual(app_row[0][2], "medio")

    def test_html_warns_on_empty_components(self):
        report = build_report([], [], [])
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "final_report.html")
            export_to_html(report, out)
            with open(out, encoding="utf-8") as f:
                content = f.read()
        self.assertIn("Sin componentes", content)
        self.assertEqual(report["summary"]["total_components"], 0)


if __name__ == "__main__":
    unittest.main()