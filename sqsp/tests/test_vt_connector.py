"""Tests de vt_connector.py (red simulado con mock, sin conexión real)."""

import os
import tempfile
import unittest
from unittest import mock

import sys
import os as _os

sys.path.insert(0, _os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__))))

import vt_connector as vtc


class TestKeyManagement(unittest.TestCase):

    def _temp_key_env(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        os.remove(path)
        self._env = mock.patch.dict(
            os.environ, {"SQS_VT_KEY_FILE": path})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_save_and_load_roundtrip(self):
        self._temp_key_env()
        self.assertTrue(vtc.save_api_key("mi-clave-secreta"))
        self.assertEqual("mi-clave-secreta", vtc.load_api_key())

    def test_save_empty_removes(self):
        path = self._temp_key_env()
        vtc.save_api_key("abc")
        self.assertEqual(vtc.load_api_key(), "abc")
        vtc.save_api_key(" \t")
        self.assertEqual("", vtc.load_api_key())


class TestHash(unittest.TestCase):

    def test_file_sha256_known_value(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"hola")
            name = f.name
        try:
            self.assertEqual(
                "b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cd4ddb79",
                vtc.file_sha256(name))
        finally:
            os.remove(name)

    def test_file_sha256_missing(self):
        self.assertIsNone(vtc.file_sha256("no_existe_zzz.exe"))


class TestChecksKey(unittest.TestCase):

    def test_no_key_raises(self):
        with self.assertRaises(vtc.VTConfigError):
            vtc._check_key("")
        with self.assertRaises(vtc.VTConfigError):
            vtc._check_key(None)

    def test_key_trimmed(self):
        self.assertEqual("k", vtc._check_key("  k  "))


class TestReport(unittest.TestCase):

    def _payload(self, stats=None, results=None):
        attr = {"last_analysis_stats": stats or {}}
        if results is not None:
            attr["last_analysis_results"] = results
        return {"data": {"attributes": attr}}

    def test_fetch_found(self):
        payload = self._payload({"malicious": 5, "suspicious": 1},
                                {"av1": {"category": "malicious",
                                         "result": "Trojan.Agent",
                                         "engine_name": "AV1"}})
        with mock.patch.object(vtc, "_http_json", return_value=payload):
            report = vtc.fetch_file_report("key", "a" * 64)
        self.assertEqual(5, report["last_analysis_stats"]["malicious"])
        self.assertEqual("Trojan.Agent",
                         report["last_analysis_results"]["av1"]["result"])

    def test_fetch_not_found(self):
        with mock.patch.object(vtc, "_http_json",
                               side_effect=vtc.VTNotFound("404")):
            self.assertEqual({"status": "not_found"},
                             vtc.fetch_file_report("key", "a" * 64))

    def test_fetch_no_key(self):
        with self.assertRaises(vtc.VTConfigError):
            vtc.fetch_file_report("", "a" * 64)


class TestSubmit(unittest.TestCase):

    def test_submit_returns_id(self):
        with mock.patch.object(
                vtc, "_post_multipart",
                return_value={"data": {"id": "abc-123"}}) as pm:
            self.assertEqual("abc-123", vtc.submit_file("key", "x.exe"))
        pm.assert_called_once()
        url = pm.call_args.args[0]
        self.assertIn("/files", url)


class TestScanURL(unittest.TestCase):

    def test_scan_url_returns_id(self):
        with mock.patch.object(
                vtc, "_http_json",
                return_value={"data": {"id": "url-1"}}) as hj:
            self.assertEqual("url-1", vtc.scan_url("key",
                                                   "http://evil.example"))
        args = hj.call_args.args
        self.assertIn("/urls", args[0])
        self.assertIn("evil.example", hj.call_args.kwargs["data"])

    def test_scan_url_no_key(self):
        with self.assertRaises(vtc.VTConfigError):
            vtc.scan_url("", "http://x.example")


class TestAnalyzeFile(unittest.TestCase):

    def _stats(self, malicious=0, suspicious=0, undetected=3):
        return {"malicious": malicious, "suspicious": suspicious,
                "undetected": undetected, "status": "completed"}

    def test_found_direct(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"x")
            name = f.name
        try:
            payload = {"data": {"attributes": {
                "last_analysis_stats": self._stats(2, 1, 3),
                "last_analysis_results": {
                    "k1": {"category": "malicious", "result": "R2D2",
                           "engine_name": "A"},
                    "k2": {"category": "harmless", "result": "ok",
                           "engine_name": "B"},
                }}}}
            with mock.patch.object(vtc, "fetch_file_report",
                                   return_value=payload["data"]["attributes"]):
                res = vtc.analyze_file("key", name)
            self.assertTrue(res["found"])
            self.assertEqual(res["malicious"], 2)
            self.assertEqual(res["suspicious"], 1)
            self.assertEqual(res["engines"], ["R2D2"])
        finally:
            os.remove(name)

    def test_upload_when_not_found(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"y")
            name = f.name
        try:
            with mock.patch.object(vtc, "fetch_file_report",
                                   return_value={"status": "not_found"}):
                with mock.patch.object(vtc, "submit_file",
                                       return_value="ana-1") as sub:
                    with mock.patch.object(
                            vtc, "fetch_analysis",
                            return_value=self._stats(9, 0, 1)):
                        res = vtc.analyze_file("key", name)
            sub.assert_called_once_with("key", name)
            self.assertTrue(res["found"])
            self.assertEqual(res["malicious"], 9)
            self.assertEqual(res["status"], "completed")
        finally:
            os.remove(name)

    def test_error_propagates(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"z")
            name = f.name
        try:
            with mock.patch.object(vtc, "fetch_file_report",
                                   side_effect=vtc.VTError("HTTP 429")):
                with self.assertRaises(vtc.VTError):
                    vtc.analyze_file("key", name)
        finally:
            os.remove(name)


if __name__ == "__main__":
    unittest.main()