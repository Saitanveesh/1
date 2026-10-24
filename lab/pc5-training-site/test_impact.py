"""Victim HTTP-response accounting tests with real loopback requests and fake data."""
import json
import pathlib
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import urlopen
from unittest.mock import patch

import mon_stage4_impact as impact
import server as site


class RealFixtureImpactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.journal=pathlib.Path(cls.temp.name)/"ledger.jsonl"
        cls.patch=patch.object(impact,"JOURNAL",cls.journal)
        cls.patch.start()
        cls.httpd=ThreadingHTTPServer(("127.0.0.1",0),site.Handler)
        cls.thread=threading.Thread(target=cls.httpd.serve_forever,daemon=True)
        cls.thread.start()
        cls.url=f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(2)
        cls.patch.stop()
        cls.temp.cleanup()

    def setUp(self):
        if self.journal.exists(): self.journal.unlink()
        old=self.journal.with_suffix(".previous.jsonl")
        if old.exists(): old.unlink()

    def get(self,path):
        return urlopen(self.url+path,timeout=3)

    def wait_for_ledger(self, expected_requests: int) -> dict:
        """HTTP body completion may precede the handler's finally/journal fsync.

        Wait for committed server-side evidence instead of racing its writer.
        If an event never arrives, the test still fails with the observed count.
        """
        deadline = time.monotonic() + 3.0
        summary = impact.impact_summary("127.0.0.1")
        while summary["observed_requests"] < expected_requests and time.monotonic() < deadline:
            time.sleep(0.02)
            summary = impact.impact_summary("127.0.0.1")
        self.assertEqual(
            summary["observed_requests"], expected_requests,
            "Missing server-committed HTTP evidence, not just a completed client read",
        )
        return summary

    def test_only_successful_fictional_leaks_are_counted(self):
        with self.get("/download?file=public-notice.txt") as r:
            self.assertEqual(r.status,200)
        with self.get("/download?file=../training-private/lab-only.txt") as r:
            self.assertIn(b"MON LAB CANARY",r.read())
        with self.get("/api/student?id=STU-1002&viewer=STU-1001") as r:
            self.assertEqual(json.load(r)["record"]["student_id"],"STU-1002")
        q=quote("' OR 1=1 -- ")
        with self.get("/api/notices?q="+q) as r:
            self.assertEqual(json.load(r)["count"],len(site.NOTICES))
        result=self.wait_for_ledger(4)
        self.assertEqual(result["fictional_exposure_responses"],3)
        self.assertEqual(result["fictional_records_in_responses"],4)
        self.assertGreater(result["fictional_response_bytes_written"],0)
        self.assertEqual(result["exposure_categories"]["fictional_canary"],1)
        self.assertEqual(result["exposure_categories"]["fictional_student"],1)
        self.assertEqual(result["exposure_categories"]["fictional_internal_notices"],1)
        self.assertTrue(all("password" not in json.dumps(row) for row in result["recent_events"]))

    def test_failed_host_file_read_is_not_exposure(self):
        try:
            self.get("/download?file=../../../../../etc/passwd")
            self.fail("Host files must be inaccessible")
        except HTTPError as exc:
            self.assertEqual(exc.code,404)
            exc.close()
        report=self.wait_for_ledger(1)
        self.assertEqual(report["fictional_exposure_responses"],0)

    def test_impact_endpoint_requires_gateway_source(self):
        with self.get("/api/impact?source=10.77.0.70") as response:
            data=json.load(response)
        self.assertEqual(data["source"],"10.77.0.70")
        self.assertEqual(data["fictional_exposure_responses"],0)
        try:
            self.get("/api/impact?source=8.8.8.8")
            self.fail("Only known laboratory sources are supported")
        except HTTPError as exc:
            self.assertEqual(exc.code,400)
            exc.close()

    def test_exposure_is_from_handler_writes_not_attacker_metadata(self):
        with self.get("/api/student?id=STU-1002&viewer=STU-1002") as response:
            self.assertEqual(response.status,200)
        self.assertEqual(self.wait_for_ledger(1)["fictional_exposure_responses"],0)

    def test_summary_from_other_source_has_no_cross_source_records(self):
        with self.get("/download?file=../training-private/lab-only.txt") as response:
            response.read()
        self.wait_for_ledger(1)
        self.assertEqual(impact.impact_summary("10.77.0.70")["observed_requests"],0)

if __name__ == "__main__":
    unittest.main()
