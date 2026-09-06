"""Tests de la Capa 3: layer3_vuln_analyzer (spec de capas).

Verifica check_component_security, análisis de funciones peligrosas reales
(reutiliza imports_analyzer/strings_analyzer de layers/layer1), firma digital,
obsolescencia, correlación con el análisis dinámico y guardado del informe.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_THIS_DIR)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import layer3_vuln_analyzer as vuln
from layer3_vuln_analyzer import (
    analyze_vulnerabilities,
    check_component_security,
    is_outdated,
    is_signed,
    has_dangerous_functions,
    save_vulnerability_report,
)


class TestCheckComponentSecurity(unittest.TestCase):
    def test_keys_and_default_bajo(self):
        with mock.patch("layer3_vuln_analyzer.is_signed",
                        return_value="signed"), \
                mock.patch("layer3_vuln_analyzer.has_dangerous_functions",
                           return_value=(False, [])), \
                mock.patch("layer3_vuln_analyzer.is_outdated",
                           return_value=False):
            result = check_component_security(
                {"type": "executable", "path": "test.exe", "size": 1024}, [])

        self.assertIn("component", result)
        self.assertIn("vulnerabilities", result)
        self.assertIn("risk_level", result)
        self.assertEqual(result["risk_level"], "bajo")
        self.assertEqual(result["vulnerabilities"], [])

    def test_unsigned_is_medio(self):
        with mock.patch("layer3_vuln_analyzer.is_signed",
                        return_value="unsigned"), \
                mock.patch("layer3_vuln_analyzer.has_dangerous_functions",
                           return_value=(False, [])), \
                mock.patch("layer3_vuln_analyzer.is_outdated",
                           return_value=False):
            result = check_component_security(
                {"type": "executable", "path": "app.exe"}, [])

        self.assertEqual(result["risk_level"], "medio")
        self.assertIn("No firmado digitalmente", result["vulnerabilities"])

    def test_unsigned_plus_dangerous_is_alto(self):
        with mock.patch("layer3_vuln_analyzer.is_signed",
                        return_value="unsigned"), \
                mock.patch("layer3_vuln_analyzer.has_dangerous_functions",
                           return_value=(True,
                                         ["CreateProcessW", "ShellExecuteW"])), \
                mock.patch("layer3_vuln_analyzer.is_outdated",
                           return_value=False):
            result = check_component_security(
                {"type": "executable", "path": "dropper.exe"}, [])

        self.assertEqual(result["risk_level"], "alto")
        self.assertIn("No firmado digitalmente", result["vulnerabilities"])
        self.assertTrue(any("funciones peligrosas" in v
                            for v in result["vulnerabilities"]))

    def test_script_does_not_check_signature(self):
        with mock.patch("layer3_vuln_analyzer.is_signed") as sig, \
                mock.patch("layer3_vuln_analyzer.has_dangerous_functions",
                           return_value=(False, [])), \
                mock.patch("layer3_vuln_analyzer.is_outdated",
                           return_value=False):
            result = check_component_security(
                {"type": "script", "path": "install.sh"}, [])

        sig.assert_not_called()
        self.assertEqual(result["risk_level"], "bajo")

    def test_dynamic_timeout_adds_vulnerability(self):
        with mock.patch("layer3_vuln_analyzer.is_signed",
                        return_value="signed"), \
                mock.patch("layer3_vuln_analyzer.has_dangerous_functions",
                           return_value=(False, [])), \
                mock.patch("layer3_vuln_analyzer.is_outdated",
                           return_value=False):
            result = check_component_security(
                {"type": "executable", "path": "a.exe"},
                [{"component": "a.exe", "exit_code": -1}])

        self.assertTrue(any("Timeout en ejecución" in v
                            for v in result["vulnerabilities"]))
        self.assertEqual(result["details"]["execution_status"], "timeout")

    def test_dynamic_error_adds_vulnerability(self):
        with mock.patch("layer3_vuln_analyzer.is_signed",
                        return_value="signed"), \
                mock.patch("layer3_vuln_analyzer.has_dangerous_functions",
                           return_value=(False, [])), \
                mock.patch("layer3_vuln_analyzer.is_outdated",
                           return_value=False):
            result = check_component_security(
                {"type": "executable", "path": "a.exe"},
                [{"component": "a.exe", "exit_code": -2}])

        self.assertTrue(any("No se pudo ejecutar el componente" in v
                            for v in result["vulnerabilities"]))
        self.assertEqual(result["details"]["execution_status"],
                         "execution_error")

    def test_dynamic_ok_does_not_add_vulnerability(self):
        with mock.patch("layer3_vuln_analyzer.is_signed",
                        return_value="signed"), \
                mock.patch("layer3_vuln_analyzer.has_dangerous_functions",
                           return_value=(False, [])), \
                mock.patch("layer3_vuln_analyzer.is_outdated",
                           return_value=False):
            result = check_component_security(
                {"type": "executable", "path": "a.exe"},
                [{"component": "a.exe", "exit_code": 0}])

        self.assertEqual(result["vulnerabilities"], [])
        self.assertEqual(result["details"]["execution_status"], "ok")


class TestIsSigned(unittest.TestCase):
    def test_parse_signature_status(self):
        self.assertEqual(vuln._parse_signature_status(
            "Status              : Valid\n"), "signed")
        self.assertEqual(vuln._parse_signature_status(
            "Status              : NotSigned\n"), "unsigned")
        self.assertEqual(vuln._parse_signature_status(
            "Status              : UnknownError\n"), "unknown")

    def test_missing_file_is_unknown(self):
        with mock.patch("layer3_vuln_analyzer.os.name", "nt"):
            self.assertEqual(is_signed("no_existe.exe"), "unknown")

    def test_powershell_output_mapped(self):
        fake_out = mock.Mock(stdout="Status : Valid\n", stderr="")
        with mock.patch("layer3_vuln_analyzer.os.name", "nt"):
            with mock.patch("layer3_vuln_analyzer.os.path.isfile",
                            return_value=True):
                with mock.patch("layer3_vuln_analyzer.subprocess.run",
                                return_value=fake_out) as run:
                    self.assertEqual(is_signed("C:\\x\\app.exe"), "signed")
                    run.assert_called_once()

    def test_powershell_crashes_is_unknown(self):
        with mock.patch("layer3_vuln_analyzer.os.name", "nt"):
            with mock.patch("layer3_vuln_analyzer.os.path.isfile",
                            return_value=True):
                with mock.patch("layer3_vuln_analyzer.subprocess.run",
                                side_effect=subprocess.TimeoutExpired(
                                    "powershell", 30)):
                    self.assertEqual(is_signed("C:\\x\\app.exe"), "unknown")

    def test_non_windows_is_unknown(self):
        with mock.patch("layer3_vuln_analyzer.os.name", "posix"):
            self.assertEqual(is_signed("/bin/ls"), "unknown")


class TestHasDangerousFunctions(unittest.TestCase):
    def test_script_with_dangerous_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = os.path.join(tmp, "x.py")
            with open(script, "w", encoding="utf-8") as f:
                f.write("import os\nos.system('boom')\n")
            found, names = has_dangerous_functions(script)
        self.assertTrue(found)
        self.assertTrue(any("system(" in n for n in names))

    def test_clean_script_no_danger(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = os.path.join(tmp, "x.py")
            with open(script, "w", encoding="utf-8") as f:
                f.write("# hola mundo\nprint('ok')\n")
            found, names = has_dangerous_functions(script)
        self.assertFalse(found)
        self.assertEqual(names, [])

    def test_missing_file_no_danger(self):
        found, names = has_dangerous_functions("no_existe.py")
        self.assertFalse(found)


class TestIsOutdated(unittest.TestCase):
    def test_new_file_not_outdated(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.txt")
            with open(path, "w") as f:
                f.write("x")
            self.assertFalse(is_outdated(path))

    def test_old_file_outdated(self):
        import time
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a.txt")
            with open(path, "w") as f:
                f.write("x")
            old = time.time() - (11 * 365 * 24 * 3600)
            os.utime(path, (old, old))
            self.assertTrue(is_outdated(path))

    def test_missing_file_not_outdated(self):
        self.assertFalse(is_outdated("no_existe.txt"))


class TestAnalyzeAndSave(unittest.TestCase):
    def test_analyze_vulnerabilities_loops_components(self):
        with mock.patch("layer3_vuln_analyzer.is_signed",
                        return_value="signed"), \
                mock.patch("layer3_vuln_analyzer.has_dangerous_functions",
                           return_value=(False, [])), \
                mock.patch("layer3_vuln_analyzer.is_outdated",
                           return_value=False):
            report = analyze_vulnerabilities(
                [{"type": "executable", "path": "a.exe", "size": 1},
                 {"type": "other", "path": "data.bin", "size": 2}],
                [{"component": "a.exe", "exit_code": 0}])

        self.assertEqual(len(report), 2)
        self.assertEqual(report[0]["risk_level"], "bajo")

    def test_analyze_resolves_relative_paths_against_base_dir(self):
        with mock.patch("layer3_vuln_analyzer.is_signed",
                        return_value="signed"), \
                mock.patch("layer3_vuln_analyzer.has_dangerous_functions",
                           return_value=(True, ["system("])), \
                mock.patch("layer3_vuln_analyzer._component_age_days",
                           return_value=2.0):
            report = analyze_vulnerabilities(
                [{"type": "script", "path": "run.py", "size": 1}],
                [{"component": "run.py", "exit_code": 0}],
                base_dir=os.getcwd())

        self.assertEqual(report[0]["component"], "run.py")
        self.assertEqual(report[0]["details"]["age_days"], 2.0)
        self.assertEqual(report[0]["risk_level"], "medio")

    def test_save_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "layer3_vulnerability_report.json")
            save_vulnerability_report(
                [{"component": "a.exe", "vulnerabilities": [],
                  "risk_level": "bajo", "details": {}}], path)
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        self.assertEqual(data[0]["risk_level"], "bajo")


class TestIntegrationWithLayer1Layer2(unittest.TestCase):
    def test_pipeline_component_types(self):
        components = [
            {"type": "executable", "path": "app.exe", "size": 512},
            {"type": "script", "path": "run.py", "size": 64},
            {"type": "installer", "path": "setup.msi", "size": 4096},
            {"type": "other", "path": "readme.txt", "size": 10},
        ]
        dynamic = [{"component": "app.exe", "exit_code": -2},
                   {"component": "run.py", "exit_code": 0}]

        with mock.patch("layer3_vuln_analyzer.is_signed",
                        return_value="signed"), \
                mock.patch("layer3_vuln_analyzer.has_dangerous_functions",
                           return_value=(True, ["system("])), \
                mock.patch("layer3_vuln_analyzer.is_outdated",
                           return_value=False):
            report = analyze_vulnerabilities(components, dynamic)

        paths = [r["component"] for r in report]
        self.assertEqual(len(paths), 4)
        app = report[0]
        self.assertEqual(app["risk_level"], "alto")
        self.assertTrue(any("No se pudo ejecutar el componente" in v
                            for v in app["vulnerabilities"]))
        other = report[3]
        self.assertEqual(other["details"]["signature_status"], "unknown")


if __name__ == "__main__":
    unittest.main()