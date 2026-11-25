import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from log_tracker import analyze, format_html, find_bursts, parse_line, signature  # noqa: E402


def test_parse_valid_line():
    e = parse_line("2026-11-20 10:00:01.250 AMF  ERROR Authentication failure imsi=404010000000001")
    assert e["node"] == "AMF" and e["level"] == "ERROR" and "imsi=" in e["msg"]


def test_parse_invalid_line_returns_none():
    assert parse_line("### core dump header ###") is None


def test_signature_groups_similar_errors():
    a = signature("Authentication failure imsi=404010000000001")
    b = signature("Authentication failure imsi=404019999999999")
    assert a == b


def test_burst_detected():
    entries = [{"node": "UPF", "level": "ERROR", "time": parse_line(
        f"2026-11-20 10:04:{s:02d}.000 UPF ERROR x")["time"]} for s in range(0, 30, 3)]
    assert find_bursts(entries)[0]["count"] == 10


def test_critical_sets_status(tmp_path):
    f = tmp_path / "a.log"
    f.write_text("2026-11-20 10:00:00.000 SMF  CRITICAL process restarted\n"
                 "2026-11-20 10:00:01.000 SMF  INFO ok\n")
    r = analyze([str(f)])
    assert r["status"] == "CRITICAL" and r["total"] == 2


def test_unparsed_lines_counted(tmp_path):
    f = tmp_path / "a.log"
    f.write_text("garbage line\n2026-11-20 10:00:01.000 SMF  INFO ok\n")
    r = analyze([str(f)])
    assert len(r["unparsed"]) == 1 and r["total"] == 1


def test_html_dashboard(tmp_path):
    f = tmp_path / "a.log"
    f.write_text("2026-11-20 10:00:00.000 SMF  CRITICAL process restarted\n"
                 "2026-11-20 10:00:01.000 UPF  ERROR PFCP association lost seid=12\n")
    page = format_html(analyze([str(f)]))
    assert "CRITICAL" in page and "PFCP association lost" in page and "<html" in page
