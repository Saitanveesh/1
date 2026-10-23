"""Smoke/security-boundary tests for the isolated fictional PC-5 lab site."""
import importlib.util
import json
import pathlib
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

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

    def test_main_website_and_non_inline_assets(self):
        with self.get("/") as response:
            text = response.read()
            self.assertIn(b"Campus Gateway", text)
            self.assertIn(b"Fictional University", text)
        with self.get("/app.js") as response:
            self.assertIn(b"notice-form", response.read())
        with self.get("/app.css") as response:
            self.assertIn(b".hero", response.read())

    def test_health_is_real_service_readiness(self):
        with self.get("/health") as response:
            self.assertEqual(json.load(response)["status"], "READY")

    def test_public_file(self):
        with self.get("/download?file=public-notice.txt") as response:
            self.assertIn(b"CAMPUS NOTICE", response.read())

    def test_lab_directory_traversal_uses_only_fake_canary(self):
        with self.get("/download?file=../training-private/lab-only.txt") as response:
            self.assertIn(b"MON LAB CANARY", response.read())

    def test_host_files_are_not_accessible(self):
        try:
            with self.get("/download?file=../../../../../etc/passwd"):
                self.fail("Host file must never be readable")
        except HTTPError as error:
            self.assertEqual(error.code, 404)
            error.close()

    def test_safe_notice_search_returns_one_fixture(self):
        with self.get("/api/notices?q=timetable") as response:
            data = json.load(response)
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["results"][0]["headline"], "Semester timetable")

    def test_intentional_sqli_changes_fixture_results(self):
        injection = quote("' OR 1=1 -- ")
        with self.get("/api/notices?q=" + injection) as response:
            data = json.load(response)
        self.assertEqual(data["count"], len(module.NOTICES))
        self.assertTrue(all(x["visibility"] in {"Public", "FAKE INTERNAL"} for x in data["results"]))

    def test_fictional_idor_can_access_another_fixture(self):
        with self.get("/api/student?id=STU-1002&viewer=STU-1001") as response:
            data = json.load(response)
        self.assertEqual(data["record"]["student_id"], "STU-1002")
        self.assertEqual(data["viewer_claim"], "STU-1001")
        self.assertTrue(data["record"]["lab_token"].startswith("FAKE-"))

    def test_no_real_student_identifiers_exist(self):
        try:
            with self.get("/api/student?id=REAL-PERSON-01&viewer=STU-1001"):
                self.fail("Unknown student should not exist")
        except HTTPError as error:
            self.assertEqual(error.code, 404)
            error.close()

    def test_toy_login_success_and_denied(self):
        for password, expected in (("labpass-1001", 200), ("wrong", 401)):
            req = Request(
                self.base + "/api/login", method="POST",
                data=json.dumps({"username": "demo.student", "password": password}).encode(),
                headers={"Content-Type": "application/json"},
            )
            try:
                with urlopen(req, timeout=3) as response:
                    self.assertEqual(response.status, expected)
                    self.assertNotIn("Set-Cookie", response.headers)
            except HTTPError as error:
                self.assertEqual(error.code, expected)
                error.close()

    def test_host_access_policy(self):
        self.assertTrue(module.source_allowed("10.77.0.60"))
        self.assertTrue(module.source_allowed("127.0.0.1"))
        self.assertFalse(module.source_allowed("10.5.114.47"))
        self.assertFalse(module.source_allowed("8.8.8.8"))


if __name__ == "__main__":
    unittest.main()
