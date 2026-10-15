"""Measured, disposable HTTP target for an uplink-free Linux namespace lab."""
from __future__ import annotations

import datetime as dt
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        started = time.monotonic()
        if self.path == "/health/live":
            payload = {
                "environment": "isolated-linux-netns",
                "service": "MON disposable test service",
            }
            status = 200
        elif self.path == "/api/students?limit=1":
            # A deliberately serial test-only service exposes real latency
            # under *bounded* multi-origin load; no campus system is involved.
            time.sleep(0.12)
            payload = {"dataset": "FICTIONAL", "records": ["DEMO-00001"]}
            status = 200
        else:
            payload = {"error": "not found"}
            status = 404
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        print(json.dumps({
            "observed_at": dt.datetime.now(dt.UTC).isoformat(),
            "src_ip": self.client_address[0],
            "path": self.path,
            "status": status,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
        }), flush=True)

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    print("MON isolated namespace-only target starting", flush=True)
    HTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
