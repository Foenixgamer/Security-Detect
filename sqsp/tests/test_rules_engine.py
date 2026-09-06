"""
Tests del motor de reglas (Capa 4) y del sandbox Docker opcional (Capa 3).

Cubre:
- Carga de reglas JSON (YAML solo si PyYAML está instalado).
- Evaluación de condiciones (exists / equals / contains / greater / regex).
- Puntos de riesgo por severidad y override con base_add.
- Integración con classification_layer (classification.json + rules_report.json).
- Sandbox Docker: comportamiento cuando Docker no está disponible.
- Parser de la variable de entorno SQS_DOCKER.
"""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import rules_engine
import classification_layer
import dynamic_analysis_layer
from sandbox import docker_runner


class TestLoadRules(unittest.TestCase):

    def test_loads_json_rules(self):
        rules = rules_engine.load_rules()
        self.assertTrue(rules)
        names = [r["name"] for r in rules]
        self.assertIn("Process_Injection_API", names)
        self.assertIn("YARA_Signature_Match", names)

    def test_example_yaml_ignored(self):
        # example_signatures.yaml existe pero NO debe activarse
        self.assertEqual(len(rules_engine.load_rules()), 6)

    def test_load_rules_skips_bad_files(self):
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "mal.json")
            with open(bad, "w", encoding="utf-8") as f:
                f.write("{{{{no es json")
            self.assertEqual(rules_engine.load_rules(d), [])


class TestEvaluateConditions(unittest.TestCase):

    def test_exists(self):
        self.assertTrue(rules_engine._evaluate_condition(
            {"a": {"b": [1, 2]}}, {"field": "a.b", "op": "exists"}))
        self.assertFalse(rules_engine._evaluate_condition(
            {"a": {"b": []}}, {"field": "a.b", "op": "exists"}))
        self.assertFalse(rules_engine._evaluate_condition(
            {"a": {}}, {"field": "a.b", "op": "exists"}))

    def test_contains_on_list(self):
        signals = {"static_analysis": {"suspicious_imports": [
            {"function": "CreateRemoteThread"}, {"function": "ReadFile"}]}}
        self.assertTrue(rules_engine._evaluate_condition(
            signals, {"field": "static_analysis.suspicious_imports",
                      "op": "contains", "value": "CreateRemoteThread"}))

    def test_equals_and_greater_and_regex(self):
        self.assertTrue(rules_engine._evaluate_condition(
            {"m": {"status": "malicious"}},
            {"field": "m.status", "op": "equals", "value": "malicious"}))
        self.assertTrue(rules_engine._evaluate_condition(
            {"n": 42}, {"field": "n", "op": "greater", "value": 10}))
        self.assertFalse(rules_engine._evaluate_condition(
            {"n": 4}, {"field": "n", "op": "greater", "value": 10}))
        self.assertTrue(rules_engine._evaluate_condition(
            {"s": "URGENT!"}, {"field": "s", "op": "regex",
                               "value": r"URG.+T!"}))

    def test_unknown_fields_never_crash(self):
        self.assertFalse(rules_engine._evaluate_condition(
            {"a": 1}, {"field": "x.y.z", "op": "regex", "value": "r:."}))


class TestEvaluateRules(unittest.TestCase):

    def test_points_by_severity(self):
        rules = [
            {"name": "r1", "severity": "high",
             "condition": {"field": "trigger", "op": "exists"}},
            {"name": "r2", "base_add": 7,
             "condition": {"field": "trigger", "op": "exists"}},
        ]
        result = rules_engine.evaluate({"trigger": True}, rules=rules)
        self.assertEqual(result["risk_added"], 3 + 7)
        self.assertEqual(len(result["matched"]), 2)

    def test_no_fire(self):
        result = rules_engine.evaluate({"missing_field": None}, rules=[{
            "name": "r",
            "condition": {"field": "no_existe.campo", "op": "exists"}}])
        self.assertEqual(result["risk_added"], 0)
        self.assertEqual(result["matched"], [])


class TestClassificationRulesIntegration(unittest.TestCase):

    def test_rules_add_risk_and_write_report(self):
        with tempfile.TemporaryDirectory() as base:
            static = {
                "is_executable": False,
                "file_path": os.path.join(base, "f.bin"),
                "static_analysis": {
                    "suspicious_strings_found": [
                        {"string": "IEX .DownloadFile", "offset": 0,
                         "pattern": "Descarga remota (.DownloadFile)"}],
                },
            }
            with open(os.path.join(base, "static_analysis.json"), "w",
                      encoding="utf-8") as f:
                json.dump(static, f)
            with open(os.path.join(base, "dynamic_report.json"), "w",
                      encoding="utf-8") as f:
                json.dump({}, f)

            classification = classification_layer.classify_file(base)

            # string base(1) + regla alta(3) = 4
            self.assertEqual(classification["risk_score"], 4)
            self.assertEqual(classification["rules_risk_added"], 3)
            self.assertEqual(classification["rules_matched"],
                             ["Remote_Download_Indicator"])
            self.assertTrue(any("Regla 'Remote_Download_Indicator'"
                                in t for t in classification["threats_found"]))

            with open(os.path.join(base, "rules_report.json"),
                      encoding="utf-8") as f:
                rules_report = json.load(f)
            self.assertEqual(rules_report["risk_added"], 3)


class TestDockerSandbox(unittest.TestCase):

    def test_docker_unavailable(self):
        with mock.patch("sandbox.docker_runner.subprocess.run",
                        side_effect=FileNotFoundError):
            with tempfile.TemporaryDirectory() as tmp:
                report = docker_runner.run_in_docker(
                    os.path.join(tmp, "target"), tmp)
                self.assertTrue(report.get("docker_unavailable"))
                self.assertIn("error", report)

    def test_docker_available_false_on_error(self):
        # docker version devuelve error -> daemon no disponible
        ret = mock.Mock(returncode=1, stdout="", stderr="error")
        with mock.patch("sandbox.docker_runner.subprocess.run",
                        return_value=ret):
            self.assertFalse(docker_runner.docker_available())

    def test_env_hook_parser(self):
        parse = dynamic_analysis_layer._docker_sandbox_enabled
        for value in ("1", "true", "TRUE", "yes"):
            with mock.patch.dict(os.environ, {"SQS_DOCKER": value}):
                self.assertTrue(parse())
        for value in ("0", "false", "", "off"):
            with mock.patch.dict(os.environ, {"SQS_DOCKER": value},
                                 clear=False):
                self.assertFalse(parse())

    def test_run_in_sandbox_falls_back_without_env(self):
        # Sin SQS_DOCKER, el sandbox usa subprocess local (sin Docker)
        with mock.patch.dict(os.environ, {}, clear=True):
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "objeto.txt")
                with open(path, "w", encoding="utf-8") as f:
                    f.write("no ejecutable")
                report = dynamic_analysis_layer.run_in_sandbox(
                    path, tmp, timeout=5)
                self.assertIn("note", report)
                self.assertEqual(report["execution_log"], [])


if __name__ == "__main__":
    unittest.main()