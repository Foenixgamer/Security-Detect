"""
Tests de Capa 1 integrada: layer1_extractor.py

Verifica el inventario de componentes (tipo, ruta relativa, tamaño, sha256,
magic_type) tanto para paquetes-directorio como para archivos únicos.
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from layer1_extractor import (
    extract_components,
    get_file_type,
    save_components,
)


class TestGetFileType(unittest.TestCase):

    def test_executable_extensions(self):
        self.assertEqual(get_file_type("app.exe"), "executable")
        self.assertEqual(get_file_type("lib.dll"), "executable")
        self.assertEqual(get_file_type("tool.DLL"), "executable")  # mayúsculas

    def test_script_extensions(self):
        for name in ("script.py", "util.js", "macro.vbs", "run.bat"):
            self.assertEqual(get_file_type(name), "script")

    def test_installer_and_other(self):
        self.assertEqual(get_file_type("setup.msi"), "installer")
        self.assertEqual(get_file_type("README.txt"), "other")
        self.assertEqual(get_file_type("sin_extension"), "other")


class TestExtractComponents(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.script = os.path.join(self.temp_dir, "test_script.py")
        with open(self.script, "w", encoding="utf-8") as f:
            f.write("print('Hello')")

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_extract_from_simple_dir(self):
        components = extract_components(self.temp_dir)
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]["path"], "test_script.py")
        self.assertEqual(components[0]["type"], "script")

    def test_sha256_present_and_correct(self):
        with open(self.script, "rb") as f:
            expected = hashlib.sha256(f.read()).hexdigest()
        components = extract_components(self.temp_dir)
        self.assertEqual(components[0]["sha256"], expected)

    def test_nested_directories_and_types(self):
        exe_path = os.path.join(self.temp_dir, "app.exe")
        with open(exe_path, "wb") as f:
            f.write(b"MZ" + b"\x00" * 16)
        os.makedirs(os.path.join(self.temp_dir, "docs"))
        with open(os.path.join(self.temp_dir, "docs", "nota.txt"),
                  "w", encoding="utf-8") as f:
            f.write("hola")

        components = extract_components(self.temp_dir)
        self.assertEqual(len(components), 3)

        by_path = {c["path"]: c for c in components}
        self.assertEqual(by_path["app.exe"]["type"], "executable")
        self.assertEqual(by_path["app.exe"]["magic_type"], "PE")
        self.assertEqual(by_path["docs/nota.txt"]["type"], "other")
        self.assertEqual(by_path["test_script.py"]["type"], "script")

        # Todos llevan hash
        for c in components:
            self.assertEqual(len(c["sha256"]), 64)

    def test_single_file_as_package(self):
        exe_path = os.path.join(self.temp_dir, "setup.exe")
        with open(exe_path, "wb") as f:
            f.write(b"MZ" + b"\x00" * 16)

        components = extract_components(exe_path)
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]["type"], "installer")
        self.assertEqual(components[0]["path"], "setup.exe")
        self.assertEqual(components[0]["magic_type"], "PE")


class TestSaveComponents(unittest.TestCase):

    def test_save_and_reload(self):
        with tempfile.TemporaryDirectory() as d:
            comps = [{"type": "script", "path": "a.py", "size": 3,
                      "sha256": "x" * 64, "magic_type": "UNKNOWN"}]
            out = os.path.join(d, "layer1_extracted_components.json")
            save_components(comps, out)

            self.assertTrue(os.path.isfile(out))
            with open(out, encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(loaded, comps)


if __name__ == "__main__":
    unittest.main()