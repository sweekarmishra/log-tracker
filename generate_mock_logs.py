"""Create mock 4G/5G core-network log files for testing log_tracker.py.

The logs are synthetic (random but seeded, so every run gives the same files).
They mimic node output from AMF, SMF, UPF, MME, SGW and HSS and include a few
planted incidents so the tracker has something real to find.
"""
import os
import random
from datetime import datetime, timedelta

START = datetime(2026, 11, 20, 10, 0, 0)
NODES = ["AMF", "SMF", "UPF", "MME", "SGW", "HSS"]

NORMAL = {
    "AMF": ["Registration Request received imsi={imsi}", "Registration Accept sent imsi={imsi}",
            "Authentication successful imsi={imsi}"],
    "SMF": ["PDU Session Establishment Request imsi={imsi}", "PDU Session created imsi={imsi} ip=10.45.0.{n}"],
    "UPF": ["PFCP Session Establishment OK seid={seid}", "GTP-U tunnel up teid={seid}"],
    "MME": ["Attach Request received imsi={imsi}", "Attach Accept sent imsi={imsi}"],
    "SGW": ["Create Session Request imsi={imsi}", "Create Session Response cause=16 imsi={imsi}"],
    "HSS": ["Authentication Info Request imsi={imsi}", "Update Location Answer result=2001 imsi={imsi}"],
}


def imsi():
    return "40401" + "".join(random.choice("0123456789") for _ in range(10))


def line(ts, node, level, msg):
    return f"{ts.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} {node:<4} {level:<5} {msg}"


def generate():
    """Return {file_name: text} for the mock logs (same output on every call)."""
    random.seed(42)
    rows = {n: [] for n in NODES}

    # normal traffic over 10 minutes
    for _ in range(600):
        node = random.choice(NODES)
        ts = START + timedelta(seconds=random.uniform(0, 600))
        msg = random.choice(NORMAL[node]).format(imsi=imsi(), n=random.randint(2, 250),
                                                 seid=random.randint(1000, 9999))
        rows[node].append((ts, "INFO", msg))

    # background warnings
    for _ in range(25):
        node = random.choice(NODES)
        ts = START + timedelta(seconds=random.uniform(0, 600))
        rows[node].append((ts, "WARN", f"High processing latency {random.randint(150, 400)} ms"))

    # incident 1: PFCP association lost on UPF (burst of errors around minute 4)
    t0 = START + timedelta(minutes=4)
    for i in range(12):
        rows["UPF"].append((t0 + timedelta(seconds=i * 3), "ERROR",
                            f"PFCP association lost with SMF seid={random.randint(1000, 9999)}"))
    for i in range(6):
        rows["SMF"].append((t0 + timedelta(seconds=i * 5 + 1), "ERROR",
                            f"PFCP Session Establishment failed imsi={imsi()} cause=timeout"))

    # incident 2: scattered Diameter timeouts between MME and HSS
    for i in range(4):
        ts = START + timedelta(seconds=random.uniform(60, 540))
        rows["MME"].append((ts, "ERROR", f"Diameter S6a timeout waiting for AIA imsi={imsi()}"))

    # incident 3: authentication failures on AMF
    for i in range(5):
        ts = START + timedelta(seconds=random.uniform(100, 500))
        rows["AMF"].append((ts, "ERROR", f"Authentication failure MAC mismatch imsi={imsi()}"))

    # incident 4: one critical restart
    rows["SMF"].append((START + timedelta(minutes=4, seconds=40), "CRITICAL",
                        "SMF process restarted unexpectedly"))

    # a malformed line to prove the parser copes
    junk = "### core dump header ###"

    files = {}
    for node, items in rows.items():
        items.sort()
        text = "".join(line(ts, node, level, msg) + "\n" for ts, level, msg in items)
        if node == "UPF":
            text += junk + "\n"
        files[f"{node.lower()}.log"] = text
    return files


def main(out_dir="logs"):
    os.makedirs(out_dir, exist_ok=True)
    for name, text in generate().items():
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as f:
            f.write(text)
    print(f"Mock logs written to {out_dir}/")


if __name__ == "__main__":
    main()
