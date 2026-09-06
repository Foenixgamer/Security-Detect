"""
Tests de Capa 2 integrada: layer2_analyzer.py

Los análisis de ejecución se verifican con mocks (subprocess) para que sean
portables y herméticos en Windows y Linux/CI. Cubre:
- camino feliz (exit_code, salida truncada a 500, execution_time)
- timeout (exit_code -1)
- error de ejecución (exit_code -2)
- resolución de rutas relativas contra el paquete
- filtrado por tipo (solo executable/script; run_scripts=False)
- guardado/recarga de layer2_dynamic_analysis.json
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from layer2_analyzer import (
    analyze_package_dynamically,
    save_dynamic_analysis,
)
from layer1_extractor import extract_components


class TestAnalyzeDynamic(unittest.TestCase):

    def test_happy_path_entries(self):
        result = mock.Mock(
            returncode=0, stdout="hola mundo", stderr="")
        with mock.patch("layer2_analyzer.subprocess.run",
                        return_value=result):
            results = analyze_package_dynamically(
                "/pkg", [{"type": "executable", "path": "app.exe"}])

        self.assertEqual(len(results), 1)
        entry = results[0]
        self.assertEqual(entry["component"], "app.exe")
        self.assertEqual(entry["exit_code"], 0)
        self.assertEqual(entry["output"], "hola mundo")
        self.assertEqual(entry["error"], "")
        self.assertGreaterEqual(entry["execution_time"], 0)

    def test_output_truncated_to_500(self):
        result = mock.Mock(returncode=0, stdout="x" * 1200, stderr="")
        with mock.patch("layer2_analyzer.subprocess.run",
                        return_value=result):
            results = analyze_package_dynamically("/pkg", [
                {"type": "executable", "path": "app.exe"}])
        self.assertEqual(len(results[0]["output"]), 500)

    def test_timeout_sets_exit_code_minus_one(self):
        with mock.patch("layer2_analyzer.subprocess.run",
                        side_effect=subprocess.TimeoutExpired(
                            cmd=["x"], timeout=5)):
            results = analyze_package_dynamically("/pkg", [
                {"type": "executable", "path": "app.exe"}], timeout=5)

        self.assertEqual(results[0]["exit_code"], -1)
        self.assertIn("Timeout", results[0]["error"])
        self.assertEqual(results[0]["execution_time"], 5.0)

    def test_exception_sets_exit_code_minus_two(self):
        with mock.patch("layer2_analyzer.subprocess.run",
                        side_effect=FileNotFoundError("no existe")):
            results = analyze_package_dynamically("/pkg", [
                {"type": "executable", "path": "app.exe"}])

        self.assertEqual(results[0]["exit_code"], -2)
        self.assertIn("no existe", results[0]["error"])

    def test_relative_path_resolved_against_package(self):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch("layer2_analyzer.subprocess.run", side_effect=fake_run):
            analyze_package_dynamically(
                "/pkg", [{"type": "executable", "path": "sub/app.exe"}])

        self.assertEqual(
            os.path.normpath(captured["cmd"][0]),
            os.path.normpath(os.path.join("/pkg", "sub", "app.exe")))

    def test_single_file_package_resolves_against_its_dir(self):
        captured = {}
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(d, "setup.exe")
            with open(real, "wb"):
                pass

            def fake_run(cmd, **kwargs):
                captured["cmd"] = cmd
                return mock.Mock(returncode=1, stdout="", stderr="err")

            with mock.patch("layer2_analyzer.subprocess.run",
                            side_effect=fake_run):
                analyze_package_dynamically(
                    real, [{"type": "executable",
                            "path": os.path.basename(real)}])

        self.assertEqual(captured["cmd"], [real])

    def test_skips_non_run_types(self):
        components = [
            {"type": "executable", "path": "a.exe"},
            {"type": "other", "path": "nota.txt"},
            {"type": "installer", "path": "setup.msi"},
        ]
        with mock.patch("layer2_analyzer.subprocess.run") as run_mock:
            results = analyze_package_dynamically("/pkg", components)
        self.assertEqual(len(results), 1)
        run_mock.assert_called_once()

    def test_run_scripts_flag(self):
        components = [
            {"type": "executable", "path": "a.exe"},
            {"type": "script", "path": "run.py"},
        ]
        with mock.patch("layer2_analyzer.subprocess.run") as run_mock:
            with_scripts = analyze_package_dynamically("/pkg", components)
            without_scripts = analyze_package_dynamically(
                "/pkg", components, run_scripts=False)

        self.assertEqual(len(with_scripts), 2)
        self.assertEqual(len(without_scripts), 1)
        self.assertEqual(without_scripts[0]["component"], "a.exe")


class TestIntegrationWithLayer1(unittest.TestCase):

    def test_layer1_inventory_feeds_layer2(self):
        with tempfile.TemporaryDirectory() as d:
            exe = os.path.join(d, "app.exe")
            with open(exe, "wb") as f:
                f.write(b"MZ" + b"\x00" * 16)
            script = os.path.join(d, "run.py")
            with open(script, "w", encoding="utf-8") as f:
                f.write("print('hi')")

            components = extract_components(d)
            self.assertEqual(len(components), 2)

            with mock.patch("layer2_analyzer.subprocess.run") as run_mock:
                results = analyze_package_dynamically(d, components)

            self.assertEqual(len(results), 2)
            self.assertEqual(run_mock.call_count, 2)
            # La ruta ejecutada es absoluta (resuelta contra el paquete)
            for call in run_mock.call_args_list:
                self.assertTrue(os.path.isabs(call.args[0][0]))


class TestSaveDynamicAnalysis(unittest.TestCase):

    def test_save_and_reload(self):
        with tempfile.TemporaryDirectory() as d:
            results = [{"component": "a.exe", "execution_time": 1.0,
                        "exit_code": 0, "output": "", "error": ""}]
            out = os.path.join(d, "layer2_dynamic_analysis.json")
            save_dynamic_analysis(results, out)

            self.assertTrue(os.path.isfile(out))
            with open(out, encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(loaded, results)


if __name__ == "__main__":
    unittest.main()