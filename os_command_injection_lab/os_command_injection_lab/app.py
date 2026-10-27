"""Local-only OS command injection teaching lab (Python standard library only).

WARNING: /api/vulnerable intentionally executes shell input. Keep this app on
127.0.0.1, use only the supplied harmless demo payload, and stop it when done.
"""
from __future__ import annotations

import html
import ipaddress
import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from typing import Any

HOST = "127.0.0.1"
PORT = 5000
ROOT = Path(__file__).resolve().parent
IS_WINDOWS = os.name == "nt"


def run_vulnerable(host: str) -> dict[str, Any]:
    """INTENTIONALLY VULNERABLE: user input is concatenated into a shell string."""
    prefix = "ping -n 1" if IS_WINDOWS else "ping -c 1"
    command = f"{prefix} {host}"
    try:
        completed = subprocess.run(
            command,
            shell=True,  # The vulnerability: the shell parses user-supplied metacharacters.
            capture_output=True,
            text=True,
            errors="replace",
            timeout=6,
        )
        return {
            "mode": "vulnerable", "input": host, "command": command,
            "returncode": completed.returncode,
            "output": (completed.stdout or "") + (completed.stderr or ""), "error": None,
        }
    except subprocess.TimeoutExpired:
        return {
            "mode": "vulnerable", "input": host, "command": command,
            "returncode": None, "output": "", "error": "Command timed out after 6 seconds.",
        }
    except Exception as exc:
        return {
            "mode": "vulnerable", "input": host, "command": command,
            "returncode": None, "output": "", "error": f"Execution failed: {exc}",
        }


def run_safe(host: str) -> dict[str, Any]:
    """Mitigation implemented: allow-list validation using Python's IP parser.

    Only a canonical IPv4/IPv6 address can reach the command. Shell separators,
    spaces, and command text are rejected before any OS process is started.
    """
    try:
        validated_host = str(ipaddress.ip_address(host.strip()))
    except ValueError:
        return {
            "mode": "safe", "input": host, "command": None, "returncode": None,
            "output": "BLOCKED: host must be a single valid IPv4 or IPv6 address. No OS command was run.",
            "error": None,
        }

    # The input has been reduced to a canonical IP string by the allow-list check.
    prefix = "ping -n 1" if IS_WINDOWS else "ping -c 1"
    command = f"{prefix} {validated_host}"
    try:
        completed = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            errors="replace", timeout=6,
        )
        return {
            "mode": "safe", "input": host, "validated_input": validated_host,
            "command": command, "returncode": completed.returncode,
            "output": (completed.stdout or "") + (completed.stderr or ""), "error": None,
        }
    except subprocess.TimeoutExpired:
        return {
            "mode": "safe", "input": host, "validated_input": validated_host,
            "command": command, "returncode": None, "output": "",
            "error": "Command timed out after 6 seconds.",
        }
    except Exception as exc:
        return {
            "mode": "safe", "input": host, "validated_input": validated_host,
            "command": command, "returncode": None, "output": "",
            "error": f"Execution failed: {exc}",
        }


def result_html(result: dict[str, Any]) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    mode = esc(result.get("mode", ""))
    submitted = esc(result.get("input", ""))
    block = [
        '<section class="card result">',
        f"<h2>Result: {mode.capitalize()}</h2>",
        f"<p><strong>Submitted input:</strong> <code>{submitted}</code></p>",
    ]
    if result.get("validated_input") is not None:
        block.append(f"<p><strong>Validated input:</strong> <code>{esc(result['validated_input'])}</code></p>")
    if result.get("command"):
        block.append(f"<p><strong>Command:</strong> <code>{esc(result['command'])}</code></p>")
    if result.get("returncode") is not None:
        block.append(f"<p><strong>Return code:</strong> {esc(result['returncode'])}</p>")
    if result.get("error"):
        block.append(f"<p><strong>Execution note:</strong> {esc(result['error'])}</p>")
    output = result.get("output") or "(No output returned.)"
    block.extend(["<p><strong>Output / block message:</strong></p>", f"<pre>{esc(output)}</pre>", "</section>"])
    return "\n".join(block)


class LabHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        # Minimal request log for the class demo.
        print(f"[{self.log_date_time_string()}] {format % args}")

    def send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: dict[str, Any]) -> None:
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_bytes(200, body, "application/json; charset=utf-8")

    def send_page(self, result: dict[str, Any] | None = None) -> None:
        template_path = ROOT / "templates" / "index.html"
        template = template_path.read_text(encoding="utf-8")
        result_block = result_html(result) if result is not None else ""
        page = template.replace("$RESULT_BLOCK", result_block)
        self.send_bytes(200, page.encode("utf-8"), "text/html; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        parsed = urlsplit(self.path)
        params = parse_qs(parsed.query, keep_blank_values=True)
        host = params.get("host", ["127.0.0.1"])[0]

        if len(host) > 256:
            self.send_bytes(414, b"Input too long", "text/plain; charset=utf-8")
            return

        if parsed.path == "/":
            self.send_page()
        elif parsed.path == "/ui/vulnerable":
            self.send_page(run_vulnerable(host))
        elif parsed.path == "/ui/safe":
            self.send_page(run_safe(host))
        elif parsed.path == "/api/vulnerable":
            self.send_json(run_vulnerable(host))
        elif parsed.path == "/api/safe":
            self.send_json(run_safe(host))
        else:
            self.send_bytes(404, b"Not found", "text/plain; charset=utf-8")


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), LabHandler)
    print(f"OS Command Injection teaching lab: http://{HOST}:{PORT}")
    print("WARNING: vulnerable endpoint is intentionally unsafe. Localhost only; stop when done.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nLab stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
