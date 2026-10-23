"""Regression tests for PC-2 portal routing checks under systemd."""
import importlib.util
import pathlib
import subprocess
import unittest
from unittest.mock import patch

SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "tools" / "mon-lab-portal.py"
spec = importlib.util.spec_from_file_location("mon_route_check_test", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


class RouteCheckTests(unittest.TestCase):
    def test_plain_text_iproute2_matches_pc5_wg0(self):
        value = "10.77.0.50 dev wg0 src 10.77.0.1 uid 1000\n    cache\n"
        self.assertEqual(module.parse_selected_route_interface(value), "wg0")

    def test_plain_text_iproute2_detects_wrong_route(self):
        value = "10.77.0.50 via 10.5.112.1 dev enp128s31f6 src 10.5.112.132\n"
        self.assertEqual(module.parse_selected_route_interface(value), "enp128s31f6")

    def test_route_check_uses_plain_text_not_json(self):
        response = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="10.77.0.50 dev wg0 src 10.77.0.1 uid 1000\n", stderr=""
        )
        with patch.object(module, "PROTECTED_HOST_IP", "10.77.0.50"), \
             patch.object(module, "PROTECTED_CAPTURE_INTERFACE", "wg0"), \
             patch.object(module.shutil, "which", return_value="/usr/sbin/ip"), \
             patch.object(module.subprocess, "run", return_value=response) as call:
            status = module.inspect_protected_route()
        self.assertEqual(status["protected_route_check"], "MATCHES_CAPTURE_INTERFACE")
        self.assertEqual(status["protected_route_interface"], "wg0")
        self.assertNotIn("-j", call.call_args.args[0])

    def test_route_check_returns_mismatch_when_kernel_selects_lan(self):
        response = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="10.77.0.50 via 10.5.112.1 dev enp128s31f6 src 10.5.112.132\n",
            stderr=""
        )
        with patch.object(module, "PROTECTED_HOST_IP", "10.77.0.50"), \
             patch.object(module, "PROTECTED_CAPTURE_INTERFACE", "wg0"), \
             patch.object(module.shutil, "which", return_value="/usr/bin/ip"), \
             patch.object(module.subprocess, "run", return_value=response):
            status = module.inspect_protected_route()
        self.assertEqual(status["protected_route_check"], "DIFFERENT_INTERFACE")

    def test_fallback_for_minimal_systemd_path(self):
        response = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="10.77.0.50 dev wg0 src 10.77.0.1\n", stderr=""
        )
        with patch.object(module, "PROTECTED_HOST_IP", "10.77.0.50"), \
             patch.object(module.shutil, "which", return_value=None), \
             patch.object(module.os.path, "isfile", side_effect=lambda path: path == "/usr/sbin/ip"), \
             patch.object(module.os, "access", return_value=True), \
             patch.object(module.subprocess, "run", return_value=response) as call:
            status = module.inspect_protected_route()
        self.assertEqual(status["protected_route_check"], "MATCHES_CAPTURE_INTERFACE")
        self.assertEqual(call.call_args.args[0][0], "/usr/sbin/ip")

    def test_query_failure_is_reported_as_unverified_with_reason(self):
        response = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="RTNETLINK failed"
        )
        with patch.object(module, "PROTECTED_HOST_IP", "10.77.0.50"), \
             patch.object(module.shutil, "which", return_value="/usr/bin/ip"), \
             patch.object(module.subprocess, "run", return_value=response):
            status = module.inspect_protected_route()
        self.assertEqual(status["protected_route_check"], "UNVERIFIED")
        self.assertIn("failed", status["protected_route_reason"])


    def test_pc2_portal_service_keeps_sandbox_and_allows_route_netlink(self):
        script = (pathlib.Path(__file__).resolve().parents[2] /
                  "tools" / "mon-batch1-fix-pc2.sh").read_text()
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_PACKET AF_NETLINK", script)
        self.assertIn("RestrictAddressFamilies=\\nRestrictAddressFamilies=", script)


if __name__ == "__main__":
    unittest.main()
