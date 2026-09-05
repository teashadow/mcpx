#!/usr/bin/env python3
"""Синтетические MCP-серверы для проверки mcpx. 🔴 OPSEC: localhost, не реальные цели.

  уязвимый — инструмент `run_command` (exec), ресурс с путём /srv, инструмент без схемы.
             mcpx обязан дать вердикт критический (TOOL_EXEC_HINT) + code 1.
  чистый   — безопасные инструменты со строгими схемами, без exec, без файловых ресурсов.
             Вердикт чистый + code 0. (authless проверяется реально — оба отдают tools без auth,
             так что NO_AUTH будет у обоих, но критическую разницу даёт именно EXEC.)

Запуск: python3 подопытный_mcp.py уязвимый 8599  |  чистый 8598
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

СЕРВЕРЫ = {
    "уязвимый": {
        "tools": [
            {"name": "run_command", "description": "Run a shell command."},   # exec, без схемы
            {"name": "get_time", "description": "Return current time.",
             "inputSchema": {"type": "object", "properties": {}}},
        ],
        "resources": [{"uri": "file:///srv/app/config.yaml", "name": "config"}],
        "prompts": [],
    },
    "чистый": {
        "tools": [
            {"name": "get_time", "description": "Return current time.",
             "inputSchema": {"type": "object", "properties": {}}},
            {"name": "lookup_city", "description": "Look up a city.",
             "inputSchema": {"type": "object",
                             "properties": {"city": {"type": "string", "enum": ["MX", "US"]}}}},
        ],
        "resources": [],
        "prompts": [],
    },
}


def обработчик(режим: str):
    s = СЕРВЕРЫ[режим]

    class Ручка(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, obj):
            тело = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(тело)))
            self.end_headers()
            self.wfile.write(тело)

        def do_GET(self):
            self._send({"mcp": "ready"})

        def do_POST(self):
            сырое = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            try:
                req = json.loads(сырое)
            except Exception:
                self.send_response(400); self.end_headers(); return
            m, rid = req.get("method"), req.get("id", 1)
            res = {}
            if m == "initialize":
                res = {"protocolVersion": "2024-11-05",
                       "serverInfo": {"name": f"mcp-{режим}", "version": "0.1.0"},
                       "capabilities": {"tools": {}}}
            elif m == "tools/list":
                res = {"tools": s["tools"]}
            elif m == "resources/list":
                res = {"resources": s["resources"]}
            elif m == "prompts/list":
                res = {"prompts": s["prompts"]}
            self._send({"jsonrpc": "2.0", "id": rid, "result": res})

    return Ручка


if __name__ == "__main__":
    режим = sys.argv[1] if len(sys.argv) > 1 else "чистый"
    порт = int(sys.argv[2]) if len(sys.argv) > 2 else 8598
    HTTPServer(("127.0.0.1", порт), обработчик(режим)).serve_forever()
