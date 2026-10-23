"""Smoke tests for the intentionally isolated PC-5 lab site (stdlib only)."""
import importlib.util
import pathlib
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import urlopen

FILE = pathlib.Path(__file__).with_name("server.py")
spec = importlib.util.spec_from_file_location("mon_training_server", FILE)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


class TrainingWebsiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def get(self, route):
        return urlopen(self.base + route, timeout=3)

    def test_main_website(self):
        with self.get("/") as response:
            self.assertIn(b"CAMPUS GATEWAY", response.read())

    def test_public_file(self):
        with self.get("/download?file=public-notice.txt") as response:
            self.assertIn(b"CAMPUS NOTICE", response.read())

    def test_lab_directory_traversal_uses_only_fake_canary(self):
        with self.get("/download?file=../training-private/lab-only.txt") as response:
            self.assertIn(b"MON LAB CANARY", response.read())

    def test_host_files_are_not_accessible(self):
        with self.assertRaises(HTTPError) as failure:
            self.get("/download?file=../../../../../etc/passwd")
        self.assertEqual(failure.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
