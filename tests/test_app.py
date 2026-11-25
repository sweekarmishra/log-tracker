import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import api_logtracker  # noqa: E402


def test_sample_logs():
    r = api_logtracker({"sample": True})
    assert r["status"] == "CRITICAL" and r["bursts"] and r["errors"]


def test_uploaded_text():
    text = "2026-11-20 10:00:00.000 SMF  ERROR PFCP failed imsi=404010000000001\n"
    r = api_logtracker({"files": [{"name": "x.log", "text": text}]})
    assert r["error_count"] == 1 and r["imsis"][0][0] == "404010000000001"


def test_bad_input_gives_error():
    assert "error" in api_logtracker({"files": [{"name": "x.log", "text": "nothing useful"}]})
    assert "error" in api_logtracker({})
