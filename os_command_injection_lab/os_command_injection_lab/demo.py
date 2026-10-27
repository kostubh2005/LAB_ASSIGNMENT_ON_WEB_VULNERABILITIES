"""HTTP demonstration for the local OS command injection lab.

Start app.py in another terminal, then run: python demo.py
"""
from __future__ import annotations

import json
import os
import sys
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import urlopen

BASE = "http://127.0.0.1:5000"
MARKER = "INJECTION_PROOF"
if os.name == "nt":
    PAYLOAD = f"127.0.0.1 & echo {MARKER}"
else:
    PAYLOAD = f"127.0.0.1; echo {MARKER}"


def request_json(path: str, host: str) -> dict:
    url = f"{BASE}{path}?{urlencode({'host': host})}"
    with urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    print("OS COMMAND INJECTION — LOCAL IN-BAND DEMO")
    print(f"Target: {BASE}")
    print(f"Payload: {PAYLOAD}")
    print("=" * 72)
    try:
        vulnerable = request_json("/api/vulnerable", PAYLOAD)
        safe = request_json("/api/safe", PAYLOAD)
    except URLError as exc:
        print("Could not connect to the local lab.")
        print("Start it first in another terminal with: python app.py")
        print(f"Details: {exc}")
        return 2

    print("\n[1] VULNERABLE ENDPOINT")
    print(f"Constructed command: {vulnerable.get('command')}")
    print(f"Output:\n{vulnerable.get('output') or vulnerable.get('error') or '(no output)'}")
    marker_executed = MARKER in (vulnerable.get("output") or "")

    print("\n[2] MITIGATED ENDPOINT")
    print(f"Result: {safe.get('output') or safe.get('error') or '(no output)'}")
    blocked = (safe.get("output") or "").startswith("BLOCKED:")

    print("\n[3] CHECK")
    print(f"Marker appears in vulnerable command output: {'PASS' if marker_executed else 'CHECK MANUALLY'}")
    print(f"Same payload rejected by allow-list mitigation: {'PASS' if blocked else 'CHECK MANUALLY'}")
    if marker_executed and blocked:
        print("DEMO RESULT: vulnerable behavior reproduced; mitigation blocked the same input.")
        return 0
    print("The app responded, but review the output above before recording evidence.")
    print("Some environments lack ping; the injected echo marker should still appear in the vulnerable output.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
