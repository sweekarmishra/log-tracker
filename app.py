"""Log Tracker - a small local web app.

Run:  python app.py          (opens http://127.0.0.1:8000 in your browser)
Only the Python standard library is needed. The server listens on this computer only.
"""
import argparse
import json
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import generate_mock_logs
import log_tracker

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_BYTES = 25 * 1024 * 1024


def api_logtracker(payload):
    """Analyze mock logs (payload {"sample": true}) or uploaded files ({"files": [{name, text}]})."""
    if payload.get("sample"):
        items = list(generate_mock_logs.generate().items())
    else:
        files = payload.get("files") or []
        items = [(str(f.get("name", "file.log")), str(f.get("text", ""))) for f in files]
    if not items:
        return {"error": "No log files received."}
    r = log_tracker.analyze_texts(items)
    if not r["total"]:
        return {"error": "No lines matched the expected log format "
                         "(YYYY-MM-DD HH:MM:SS.mmm NODE LEVEL message)."}
    errors = sorted(r["errors"], key=lambda e: e["time"])
    return {
        "status": r["status"], "total": r["total"], "files": r["files"],
        "error_count": len(errors), "error_rate": round(r["error_rate"], 1),
        "first": r["first"].strftime("%Y-%m-%d %H:%M:%S"), "last": r["last"].strftime("%H:%M:%S"),
        "unparsed": [{"file": f, "line": n, "text": t} for f, n, t in r["unparsed"][:5]],
        "unparsed_count": len(r["unparsed"]),
        "levels": [[k, r["levels"][k]] for k in ("CRITICAL", "ERROR", "WARN", "INFO", "DEBUG") if r["levels"].get(k)],
        "nodes": r["node_errors"].most_common(),
        "timeline": sorted(r["timeline"].items()),
        "patterns": r["signatures"].most_common(8),
        "bursts": [{"node": b["node"], "count": b["count"],
                    "start": b["start"].strftime("%H:%M:%S"), "end": b["end"].strftime("%H:%M:%S")}
                   for b in r["bursts"]],
        "imsis": r["imsis"].most_common(8),
        "errors": [{"time": e["time"].strftime("%H:%M:%S"), "minute": e["time"].strftime("%H:%M"),
                    "node": e["node"], "level": e["level"], "msg": e["msg"],
                    "sig": log_tracker.signature(e["msg"])} for e in errors[:1000]],
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            with open(os.path.join(HERE, "web", "index.html"), "rb") as f:
                self._send(200, f.read(), "text/html; charset=utf-8")
        else:
            self._send(404, "Not found", "text/plain")

    def do_POST(self):
        if self.path != "/api/logtracker":
            return self._send(404, "Not found", "text/plain")
        size = int(self.headers.get("Content-Length", 0))
        if size > MAX_BYTES:
            return self._send(413, json.dumps({"error": "File too large (limit 25 MB)."}), "application/json")
        try:
            result = api_logtracker(json.loads(self.rfile.read(size) or b"{}"))
        except Exception as exc:  # keep the server alive on bad input
            result = {"error": f"Could not process the input ({type(exc).__name__})."}
        self._send(200, json.dumps(result), "application/json")

    def log_message(self, *args):
        pass


def main():
    ap = argparse.ArgumentParser(description="Log Tracker (local web app)")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{args.port}"
    print(f"Log Tracker running at {url}  (press Ctrl+C to stop)")
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
