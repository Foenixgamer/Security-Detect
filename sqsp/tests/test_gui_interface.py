"""Tests de la GUI del spec de capas: gui_interface.py.

Cubren la lógica pura (analyze_package con las capas reales injectadas,
formatos de filas y recomendaciones) y, si hay display disponible, un smoke
test que instancia la GUI tkinter sin ejecutar el bucle de eventos.
"""

import os
import sys
import unittest
from unittest import mock

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_THIS_DIR)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import gui_interface as gui
from gui_interface import (
    analyze_package,
    component_rows,
    format_size,
    recommendations,
    vulnerability_rows,
    STAGES,
)


def _fake_report():
    return {
        "package_path": "/pkg",
        "summary": {
            "total_components": 2,
            "executables": 1,
            "scripts": 1,
            "others": 0,
            "risk_distribution": {"bajo": 1, "medio": 0, "alto": 1},
        },
        "components": [
            {"component": {"path": "a.exe", "type": "executable", "size": 2048},
             "dynamic_analysis": {"exit_code": -2},
             "vulnerabilities": {
                 "risk_level": "alto",
                 "vulnerabilities": ["No firmado digitalmente"],
                 "details": {"signature_status": "unsigned",
                             "dangerous_functions": ["CreateProcessW"],
                             "execution_status": "execution_error"}}},
            {"component": {"path": "b.txt", "type": "other", "size": 10},
             "dynamic_analysis": None,
             "vulnerabilities": {"risk_level": "bajo",
                                 "vulnerabilities": [],
                                 "details": {"signature_status": "unknown",
                                             "dangerous_functions": [],
                                             "execution_status": None}}},
        ],
        "vulnerabilities": [
            {"component": "a.exe", "risk_level": "alto",
             "issues": ["No firmado digitalmente"]},
        ],
    }


class TestFormatSize(unittest.TestCase):
    def test_bytes(self):
        self.assertEqual(format_size(0), "0 B")
        self.assertEqual(format_size(512), "512.0 B")

    def test_prefixes(self):
        self.assertEqual(format_size(2048), "2.0 KB")
        self.assertEqual(format_size(5 * 1024 * 1024), "5.0 MB")

    def test_invalid(self):
        self.assertEqual(format_size(None), "0 B")
        self.assertEqual(format_size("x"), "0 B")


class TestAnalyzePackage(unittest.TestCase):
    def setUp(self):
        self.components = [{"path": "a.exe", "type": "executable", "size": 1}]
        self.dynamic = [{"component": "a.exe", "exit_code": 0}]
        self.vulns = [{"component": "a.exe", "risk_level": "bajo",
                       "vulnerabilities": []}]
        self.report = {"summary": {"total_components": 1},
                       "components": [], "vulnerabilities": []}
        patcher_c1 = mock.patch("gui_interface.extract_components",
                                return_value=self.components)
        patcher_c2 = mock.patch("gui_interface.analyze_package_dynamically",
                                return_value=self.dynamic)
        patcher_c3 = mock.patch("gui_interface.analyze_vulnerabilities",
                                return_value=self.vulns)
        patcher_c4 = mock.patch("gui_interface.build_report",
                                return_value=self.report)
        for p in (patcher_c1, patcher_c2, patcher_c3, patcher_c4):
            p.start()
        self.addCleanup(patcher_c1.stop)
        self.addCleanup(patcher_c2.stop)
        self.addCleanup(patcher_c3.stop)
        self.addCleanup(patcher_c4.stop)

    def test_runs_all_stages_and_progress(self):
        calls = []
        report = analyze_package("/pkg", progress_cb=lambda i, l: calls.append((i, l)))

        gui.extract_components.assert_called_once_with("/pkg")
        gui.analyze_package_dynamically.assert_called_once()
        kwargs = gui.analyze_package_dynamically.call_args[1]
        self.assertEqual(kwargs["timeout"], 15)
        self.assertTrue(kwargs["run_scripts"])
        gui.analyze_vulnerabilities.assert_called_once_with(
            self.components, self.dynamic, base_dir="/pkg")
        gui.build_report.assert_called_once_with(self.components,
                                                 self.dynamic,
                                                 self.vulns)
        self.assertEqual(report["package_path"], "/pkg")
        self.assertEqual([label for _, label in calls], STAGES)
        self.assertEqual([i for i, _ in calls], [0, 1, 2, 3])

    def test_stop_aborts_between_stages(self):
        report = analyze_package("/pkg", progress_cb=lambda i, l: None,
                                 should_stop=lambda: True)
        self.assertIsNone(report)

    def test_passes_custom_timeout_and_run_scripts(self):
        analyze_package("/pkg", timeout=5, run_scripts=False)
        kwargs = gui.analyze_package_dynamically.call_args[1]
        self.assertEqual(kwargs["timeout"], 5)
        self.assertFalse(kwargs["run_scripts"])


class TestRows(unittest.TestCase):
    def test_component_rows(self):
        rows = component_rows(_fake_report())
        self.assertEqual(len(rows), 2)
        a = rows[0]
        self.assertEqual(a[0], "a.exe")
        self.assertEqual(a[1], "executable")
        self.assertEqual(a[2], "2.0 KB")
        self.assertEqual(a[3], "alto")
        self.assertEqual(a[4], "-2")

    def test_vulnerability_rows(self):
        rows = vulnerability_rows(_fake_report())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0], ("a.exe", "alto", "No firmado digitalmente"))

    def test_recommendations(self):
        lines = recommendations(_fake_report())
        text = "\n".join(lines)
        self.assertIn("2 componente(s)", text)
        self.assertIn("Firmar digitalmente", text)
        self.assertIn("funciones peligrosas", text)
        self.assertIn("no pudieron ejecutarse", text)

    def test_recommendations_empty_when_clean(self):
        clean = _fake_report()
        clean["summary"]["risk_distribution"] = {"bajo": 2, "medio": 0,
                                                  "alto": 0}
        for entry in clean["components"]:
            v = entry["vulnerabilities"]
            v["risk_level"] = "bajo"
            v["vulnerabilities"] = []
            v["details"] = {"signature_status": "unknown",
                            "dangerous_functions": [],
                            "execution_status": "ok"}
        clean["vulnerabilities"] = []
        lines = recommendations(clean)
        self.assertTrue(any("No se detectaron vulnerabilidades"
                            in line for line in lines))


class TestGUISmoke(unittest.TestCase):
    def test_instantiates_when_display_available(self):
        try:
            import tkinter as tk
            root = tk.Tk()
        except tk.TclError:
            self.skipTest("Sin display disponible (headless)")
        root.withdraw()
        try:
            app = gui.PackageAnalyzerGUI(root)
            self.assertTrue(app.components_tree)
            self.assertTrue(app.vulnerabilities_tree)
            self.assertTrue(app.recommendations_text)
            self.assertIsNone(app.report)
        finally:
            root.destroy()

    def test_display_populates_trees(self):
        try:
            import tkinter as tk
            root = tk.Tk()
        except tk.TclError:
            self.skipTest("Sin display disponible (headless)")
        root.withdraw()
        try:
            app = gui.PackageAnalyzerGUI(root)
            app.report = _fake_report()
            app._display()
            self.assertEqual(len(app.components_tree.get_children()), 2)
            self.assertEqual(len(app.vulnerabilities_tree.get_children()), 1)
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()