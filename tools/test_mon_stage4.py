"""Stage 4 unit tests; never need or modify the system firewall."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from unittest.mock import patch

TOOLS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from mon_stage4_gate import NftGate, validate_source, validate_ttl
from mon_stage4_bridge import evidence_for_block, verify_source, gate_request


class FakeNft:
    def __init__(self):
        self.ready = True
        self.elements = {}
        self.calls = []
    def __call__(self, args, *, input=None, text=True, capture_output=True, timeout=6, check=False):
        self.calls.append((args, input))
        if "list" in args and "table" in args:
            return subprocess.CompletedProcess(args, 0, stdout=(
                'table inet mon_stage4_range {\n'
                ' set blocked_sources { type ipv4_addr; flags timeout; }\n'
                ' chain training_forward { type filter hook forward priority -55; policy accept; '
                'iifname "wg0" oifname "wg0" ip saddr @blocked_sources '
                'ip daddr 10.77.0.50 tcp dport 8085 counter packets 0 bytes 0 drop; }\n}'
            ), stderr="")
        if "-j" in args:
            return subprocess.CompletedProcess(args,0,
                stdout=json.dumps({"nftables":[{"set":{"elem":[
                    {"elem":{"val":ip,"timeout":seconds*1000,"expires":seconds*1000}}
                    for ip,seconds in self.elements.items()]}}]}),stderr="")
        if input and input.startswith("add element"):
            parts=input.split("{")[1].split("}")[0].split()
            self.elements[parts[0]]=int(parts[2].rstrip("s"))
        if input and input.startswith("delete element"):
            key=input.split("{")[1].split("}")[0].strip()
            self.elements.pop(key,None)
        return subprocess.CompletedProcess(args,0,stdout="",stderr="")


class ContainmentTests(unittest.TestCase):
    def test_source_and_duration_are_strict(self):
        for source in ("10.77.0.1","10.77.0.50","8.8.8.8","10.77.0.80","10.77.0.60;rm -rf /"):
            with self.assertRaises(ValueError):
                validate_source(source)
                verify_source(source)
        for bad in (True, 0, 20, 181, "120", -1):
            with self.assertRaises(ValueError):
                validate_ttl(bad)
        self.assertEqual(validate_ttl(120),120)

    def test_firewall_scope_never_contains_management_or_other_ports(self):
        fake=FakeNft()
        gate=NftGate(fake)
        record=gate.block("10.77.0.70",60)
        self.assertTrue(record["active"])
        self.assertEqual(record["expires_in_seconds"],60)
        self.assertIn("10.77.0.70",fake.elements)
        self.assertTrue(gate.release("10.77.0.70")["active"] is False)
        self.assertNotIn("10.77.0.70",fake.elements)
        self.assertFalse(any("/bin/sh" in " ".join(cmd) or "sudo" in " ".join(cmd)
                             for cmd,_ in fake.calls))

    def test_existing_block_cannot_be_extended_silently(self):
        fake=FakeNft()
        gate=NftGate(fake)
        gate.block("10.77.0.60",30)
        with self.assertRaisesRegex(ValueError,"already exists"):
            gate.block("10.77.0.60",180)

    def test_eve_signature_from_true_target_required(self):
        now=datetime.now(UTC)
        row={"event_type":"alert","timestamp":now.isoformat(),
             "signature_id":42000503,"signature":"MON LAB fake IDOR",
             "src_ip":"10.77.0.70","src_port":56123,
             "dst_ip":"10.77.0.50","dst_port":8085}
        from mon_alert_ack import evidence_key
        key=evidence_key(row)
        good={"service_state":"active","status":"RECENT_EVE","records":[row]}
        self.assertEqual(evidence_for_block(key,"10.77.0.70",good)["signature_id"],42000503)
        for changed in (
            {"service_state":"inactive",**good},
            {**good,"records":[{**row,"dst_ip":"10.77.0.1"}]},
            {**good,"records":[{**row,"src_ip":"10.77.0.60"}]},
            {**good,"records":[{**row,"signature_id":999}]},
            {**good,"records":[{**row,"dst_port":22}]},
            {**good,"records":[]}
        ):
            with self.assertRaises(ValueError):
                evidence_for_block(key,"10.77.0.70",changed)
        from datetime import timedelta
        stale={**row,"timestamp":(now-timedelta(minutes=5)).isoformat()}
        with self.assertRaises(ValueError):
            evidence_for_block(evidence_key(stale),"10.77.0.70",{**good,"records":[stale]})

    def test_gate_request_has_no_external_command_or_destination(self):
        with self.assertRaises(ValueError):
            gate_request("block","10.77.0.1",120)
        with self.assertRaises(ValueError):
            gate_request("block","10.77.0.60",500)
        with self.assertRaises(ValueError):
            gate_request("execute","10.77.0.70")


if __name__ == "__main__":
    unittest.main()
