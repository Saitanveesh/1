from __future__ import annotations

import argparse
import contextlib
import threading
import webbrowser
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class NoCacheHandler(SimpleHTTPRequestHandler):
    """Serve the demo without browser caching stale scenario assets."""

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        super().end_headers()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Serve the MON cinematic security-fabric simulation."
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765)")
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not automatically open the simulation in a browser.",
    )
    return parser


def serve(host: str, port: int, *, open_browser: bool = True) -> None:
    root = Path(__file__).resolve().parent
    handler = partial(NoCacheHandler, directory=str(root))

    with ThreadingHTTPServer((host, port), handler) as httpd:
        actual_port = httpd.server_address[1]
        display_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
        url = f"http://{display_host}:{actual_port}/"

        print("MON Security Fabric — Cinematic Simulation")
        print(f"Serving: {url}")
        print("Synthetic educational telemetry only. Press Ctrl+C to stop.")

        if open_browser:
            threading.Timer(0.35, lambda: webbrowser.open(url)).start()

        with contextlib.suppress(KeyboardInterrupt):
            httpd.serve_forever(poll_interval=0.25)


def main() -> None:
    args = build_parser().parse_args()
    if not 0 <= args.port <= 65535:
        raise SystemExit("--port must be between 0 and 65535")
    serve(args.host, args.port, open_browser=not args.no_browser)


if __name__ == "__main__":
    main()
