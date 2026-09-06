"""
Tests del guarda defensivo (security_guard.py).
"""

import os
import sys
import tempfile
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from security_guard import (
    SecurityViolation,
    check_action,
    scan_artifact,
    scan_content,
)


class TestSecurityGuard(unittest.TestCase):

    def test_accept_defensive_action(self):
        self.assertTrue(check_action("Parcheo NOP de funciones maliciosas"))
        self.assertTrue(check_action("Cuarentena con copia de solo lectura"))
        self.assertTrue(check_action("Reconstrucción del paquete limpio"))

    def test_reject_evasion_action(self):
        for desc in ("Evasion de antivirus", "payload_hiding",
                     "ofuscación de malware para no ser detectado",
                     "bypass antivirus"):
            with self.assertRaises(SecurityViolation, msg=desc):
                check_action(desc)

    def test_reject_empty_action(self):
        with self.assertRaises(SecurityViolation):
            check_action("")
        with self.assertRaises(SecurityViolation):
            check_action(None)

    def test_scan_content_clean(self):
        clean = (
            "http://update.gamecrack.example/agent.exe\n"
            "schtasks /create /tn GameUpdater\n"
            "netstat -ano\n"
            "AntiAnalysis label (anti-depuración)\n"
            "create_synth_test() genera bytes inertes\n")
        self.assertEqual(scan_content(clean), [])

    def test_scan_content_finds_evasion(self):
        dirty = "usa evasión de antivirus para ocultar el payload\n"
        hits = scan_content(dirty)
        self.assertTrue(hits)

    def test_scan_artifact_file(self):
        with tempfile.TemporaryDirectory() as base:
            path = os.path.join(base, "sample.txt")
            with open(path, "w", encoding="ascii") as f:
                f.write("solo datos inertes para educar defensores\n")
            self.assertEqual(scan_artifact(path), [])

            dirty = os.path.join(base, "dirty.txt")
            with open(dirty, "w", encoding="ascii") as f:
                f.write("evasion de deteccion\n")
            self.assertTrue(scan_artifact(dirty))

    def test_scan_artifact_missing(self):
        self.assertTrue(scan_artifact(r"C:\no_tal_archivo_xyz.bin"))


if __name__ == "__main__":
    unittest.main()