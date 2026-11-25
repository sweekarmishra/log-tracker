"""Log Tracker: scan core-network log files and print a summary report.

Usage:
    python log_tracker.py logs/                       # scan every *.log in a folder
    python log_tracker.py logs/ --report report.txt   # also save the report
    python log_tracker.py logs/ --csv errors.csv      # also save every error line
    python log_tracker.py logs/ --html report.html    # browser dashboard
Exit code is 1 if any CRITICAL line was found, otherwise 0.
"""
import argparse
import csv
import glob
import html
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<node>\S+)\s+(?P<level>DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL)\s+(?P<msg>.*)$"
)
IMSI_RE = re.compile(r"imsi=(\d+)")
ERROR_LEVELS = {"ERROR", "CRITICAL"}


def parse_line(text):
    """Return a dict for a valid log line, or None if the line does not match."""
    m = LINE_RE.match(text.strip())
    if not m:
        return None
    d = m.groupdict()
    d["level"] = "WARN" if d["level"] == "WARNING" else d["level"]
    fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in d["ts"] else "%Y-%m-%d %H:%M:%S"
    d["time"] = datetime.strptime(d["ts"], fmt)
    return d


def signature(msg):
    """Turn a message into a pattern so similar errors group together."""
    s = re.sub(r"imsi=\d+", "imsi=<id>", msg)
    s = re.sub(r"\b\d+\.\d+\.\d+\.\d+\b", "<ip>", s)
    s = re.sub(r"\b0x[0-9a-fA-F]+\b", "<hex>", s)
    s = re.sub(r"(?<![A-Za-z])\d+(?![A-Za-z])", "<n>", s)
    return s


def find_bursts(entries, window=60, threshold=5):
    """Find windows where one node logs >= threshold errors within `window` seconds."""
    by_node = defaultdict(list)
    for e in entries:
        if e["level"] in ERROR_LEVELS:
            by_node[e["node"]].append(e["time"])
    bursts = []
    for node, times in by_node.items():
        times.sort()
        i = 0
        while i < len(times):
            j = i
            while j + 1 < len(times) and times[j + 1] - times[i] <= timedelta(seconds=window):
                j += 1
            count = j - i + 1
            if count >= threshold:
                bursts.append({"node": node, "start": times[i], "end": times[j], "count": count})
                i = j + 1
            else:
                i += 1
    return sorted(bursts, key=lambda b: b["start"])


def analyze(paths):
    items = []
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as f:
            items.append((os.path.basename(path), f.read()))
    return analyze_texts(items)


def analyze_texts(items):
    """Analyze [(file_name, text), ...]. Used by the CLI and by the web app."""
    entries, unparsed = [], []
    for name, text in items:
        for n, raw in enumerate(text.splitlines(), 1):
            if not raw.strip():
                continue
            e = parse_line(raw)
            if e:
                e["file"] = name
                entries.append(e)
            else:
                unparsed.append((name, n, raw.strip()))

    levels = Counter(e["level"] for e in entries)
    errors = [e for e in entries if e["level"] in ERROR_LEVELS]
    node_errors = Counter(e["node"] for e in errors)
    sigs = Counter(signature(e["msg"]) for e in errors)
    imsis = Counter()
    for e in errors:
        m = IMSI_RE.search(e["msg"])
        if m:
            imsis[m.group(1)] += 1
    total = len(entries)
    err_rate = (len(errors) / total * 100) if total else 0.0
    if levels["CRITICAL"]:
        status = "CRITICAL"
    elif err_rate >= 5:
        status = "DEGRADED"
    else:
        status = "HEALTHY"
    return {
        "files": [name for name, _ in items], "total": total, "unparsed": unparsed,
        "levels": levels, "errors": errors, "node_errors": node_errors, "signatures": sigs,
        "imsis": imsis, "bursts": find_bursts(entries), "error_rate": err_rate, "status": status,
        "timeline": Counter(e["time"].strftime("%H:%M") for e in errors),
        "first": min((e["time"] for e in entries), default=None),
        "last": max((e["time"] for e in entries), default=None),
    }


def format_report(r, top=5):
    L = ["=" * 60, "LOG TRACKER SUMMARY REPORT", "=" * 60,
         f"Files scanned : {len(r['files'])} ({', '.join(r['files'])})",
         f"Lines parsed  : {r['total']}   Unparsed lines: {len(r['unparsed'])}"]
    if r["first"]:
        L.append(f"Time range    : {r['first']:%Y-%m-%d %H:%M:%S} to {r['last']:%H:%M:%S}")
    L += [f"Overall status: {r['status']}   (error rate {r['error_rate']:.1f}%)", "",
          "Lines by level:"]
    for lvl in ("CRITICAL", "ERROR", "WARN", "INFO", "DEBUG"):
        if r["levels"].get(lvl):
            L.append(f"  {lvl:<9}{r['levels'][lvl]}")
    L += ["", "Errors by node:"]
    for node, c in r["node_errors"].most_common():
        L.append(f"  {node:<6}{c}")
    L += ["", f"Top {top} error patterns:"]
    for sig, c in r["signatures"].most_common(top):
        L.append(f"  {c:>3} x {sig}")
    L += ["", "Error bursts (5+ errors from one node within 60 s):"]
    if r["bursts"]:
        for b in r["bursts"]:
            L.append(f"  {b['node']}: {b['count']} errors, {b['start']:%H:%M:%S} to {b['end']:%H:%M:%S}")
    else:
        L.append("  none")
    L += ["", "Most affected subscribers (IMSI in error lines):"]
    if r["imsis"]:
        for imsi, c in r["imsis"].most_common(top):
            L.append(f"  {imsi}  ({c} error{'s' if c > 1 else ''})")
    else:
        L.append("  none")
    if r["unparsed"]:
        L += ["", "Unparsed lines (first 3):"]
        for fn, n, txt in r["unparsed"][:3]:
            L.append(f"  {fn}:{n}: {txt}")
    return "\n".join(L)


def _bars(items, color):
    """Horizontal bars from [(label, value)] using plain HTML/CSS."""
    if not items:
        return "<p class='muted'>none</p>"
    top = max(v for _, v in items) or 1
    rows = []
    for label, v in items:
        w = max(2, int(v / top * 100))
        rows.append(f"<div class='row'><span class='lab' title='{html.escape(str(label), quote=True)}'>{html.escape(str(label))}</span>"
                    f"<span class='bar' style='width:{w}%;background:{color}'></span>"
                    f"<span class='val'>{v}</span></div>")
    return "".join(rows)


def format_html(r, top=5):
    """Return a self-contained HTML dashboard (no external files or libraries)."""
    colors = {"HEALTHY": "#1a7f37", "DEGRADED": "#b8860b", "CRITICAL": "#c62828"}
    lv = [(k, r["levels"][k]) for k in ("CRITICAL", "ERROR", "WARN", "INFO") if r["levels"].get(k)]
    nodes = r["node_errors"].most_common()
    sigs = r["signatures"].most_common(top)
    tl = sorted(r["timeline"].items())
    bursts = "".join(
        f"<tr><td>{b['node']}</td><td>{b['count']}</td><td>{b['start']:%H:%M:%S} - {b['end']:%H:%M:%S}</td></tr>"
        for b in r["bursts"]) or "<tr><td colspan='3' class='muted'>none</td></tr>"
    imsis = "".join(f"<tr><td>{i}</td><td>{c}</td></tr>" for i, c in r["imsis"].most_common(top)) \
        or "<tr><td colspan='2' class='muted'>none</td></tr>"
    rng = f"{r['first']:%Y-%m-%d %H:%M:%S} to {r['last']:%H:%M:%S}" if r["first"] else "-"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Log Tracker Report</title>
<style>
body{{font-family:Arial,Helvetica,sans-serif;margin:0;background:#f4f5f7;color:#1a1a1a}}
header{{background:#1a1a1a;color:#fff;padding:16px 24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}}
h1{{font-size:20px;margin:0}} .badge{{padding:6px 14px;border-radius:14px;font-weight:bold;background:{colors[r['status']]}}}
main{{padding:20px 24px;max-width:1000px;margin:auto}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}}
.card{{background:#fff;border-radius:8px;padding:12px 14px;box-shadow:0 1px 3px #0002}}
.card b{{display:block;font-size:24px}} .muted{{color:#777}}
section{{background:#fff;border-radius:8px;padding:14px 16px;margin-bottom:16px;box-shadow:0 1px 3px #0002}}
h2{{font-size:15px;margin:0 0 10px}}
.row{{display:flex;align-items:center;gap:8px;margin:4px 0;font-size:13px}}
.lab{{width:230px;flex:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.bar{{height:14px;border-radius:3px;display:inline-block}} .val{{font-weight:bold}}
table{{border-collapse:collapse;width:100%;font-size:13px}} td,th{{border-bottom:1px solid #e3e3e3;padding:5px 6px;text-align:left}}
</style></head><body>
<header><h1>Log Tracker Report</h1><span class="badge">{r['status']}</span></header><main>
<div class="cards">
<div class="card"><span class="muted">Lines parsed</span><b>{r['total']}</b></div>
<div class="card"><span class="muted">Errors</span><b>{len(r['errors'])}</b></div>
<div class="card"><span class="muted">Error rate</span><b>{r['error_rate']:.1f}%</b></div>
<div class="card"><span class="muted">Files</span><b>{len(r['files'])}</b></div></div>
<p class="muted">Time range: {rng} &nbsp;|&nbsp; Unparsed lines: {len(r['unparsed'])}</p>
<section><h2>Lines by level</h2>{_bars(lv, '#546e7a')}</section>
<section><h2>Errors by node</h2>{_bars(nodes, '#c62828')}</section>
<section><h2>Errors per minute</h2>{_bars(tl, '#ef6c00')}</section>
<section><h2>Top error patterns</h2>{_bars([(s, c) for s, c in sigs], '#6a1b9a')}</section>
<section><h2>Error bursts (5+ errors from one node within 60 s)</h2>
<table><tr><th>Node</th><th>Errors</th><th>Time</th></tr>{bursts}</table></section>
<section><h2>Most affected subscribers (IMSI)</h2>
<table><tr><th>IMSI</th><th>Errors</th></tr>{imsis}</table></section>
</main></body></html>"""


def write_csv(r, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["time", "node", "level", "message", "file"])
        for e in sorted(r["errors"], key=lambda x: x["time"]):
            w.writerow([e["ts"], e["node"], e["level"], e["msg"], e["file"]])


def main(argv=None):
    ap = argparse.ArgumentParser(description="Scan core-network logs and print a summary report.")
    ap.add_argument("path", help="a log file, or a folder containing *.log files")
    ap.add_argument("--report", help="save the report to this text file")
    ap.add_argument("--html", help="save a browser dashboard (HTML) to this file")
    ap.add_argument("--csv", help="save all ERROR/CRITICAL lines to this CSV file")
    args = ap.parse_args(argv)
    paths = sorted(glob.glob(os.path.join(args.path, "*.log"))) if os.path.isdir(args.path) else [args.path]
    if not paths:
        print("No .log files found.")
        return 2
    r = analyze(paths)
    text = format_report(r)
    print(text)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(format_html(r))
        print(f"\nDashboard saved to {args.html} (open it in your browser)")
    if args.csv:
        write_csv(r, args.csv)
    return 1 if r["levels"].get("CRITICAL") else 0


if __name__ == "__main__":
    sys.exit(main())
