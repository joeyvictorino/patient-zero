"""Leaky Clinic: a tiny multi-tenant app with an "agent", in a vulnerable and a patched build.

It binds to 127.0.0.1 only and holds synthetic data. It exists so the probes
have something to find, in the tests and in `pz demo`.
"""
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CANARY = "PZ-CANARY-A-7f3a"
TOKENS = {"tok-a": "ws_a", "tok-b": "ws_b"}


def make_server(vulnerable: bool):
    data = {
        "ws_a": {"clients": [{"name": "Synthetic Person", "note": CANARY}], "notes": []},
        "ws_b": {"clients": [{"name": "Other Synthetic"}], "notes": []},
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, status, payload):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _tenant(self):
            auth = self.headers.get("Authorization", "")
            return TOKENS.get(auth.replace("Bearer ", "").strip())

        def _body(self):
            length = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(length) or b"{}")

        def do_GET(self):
            m = re.fullmatch(r"/api/workspaces/(\w+)/(clients|notes)", self.path)
            if not m or m.group(1) not in data:
                return self._send(404, {"error": "not found"})
            ws, kind = m.groups()
            tenant = self._tenant()
            if not vulnerable:
                if tenant is None:
                    return self._send(401, {"error": "unauthenticated"})
                if tenant != ws:
                    return self._send(403, {"error": "forbidden"})
            return self._send(200, {kind: data[ws][kind]})

        def do_POST(self):
            tenant = self._tenant()
            if tenant is None:
                return self._send(401, {"error": "unauthenticated"})
            body = self._body()
            m = re.fullmatch(r"/api/workspaces/(\w+)/notes", self.path)
            if m:
                if m.group(1) != tenant:
                    return self._send(403, {"error": "forbidden"})
                data[tenant]["notes"].append(body.get("text", ""))
                return self._send(201, {"ok": True})
            if self.path == "/api/agent/chat":
                prompt = body.get("message", "")
                if "summarize" in prompt.lower():
                    notes = data[tenant]["notes"]
                    last = notes[-1] if notes else ""
                    joined = re.search(r"joining '(\w+)' and '(\w+)'", last)
                    if vulnerable and joined:
                        return self._send(200, {"reply": joined.group(1) + joined.group(2)})
                    return self._send(200, {"reply": f"Your note has {len(last.split())} words."})
                scope = list(data) if vulnerable else [tenant]
                return self._send(200, {"reply": json.dumps([data[w]["clients"] for w in scope])})
            return self._send(404, {"error": "not found"})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def target_for(server, tmp_path=None):
    target = {
        "authorized": True,
        "authorization_ref": "unit test",
        "synthetic_data_only": True,
        "base_url": f"http://127.0.0.1:{server.server_address[1]}",
        "tenants": {"a": {"token": "tok-a"}, "b": {"token": "tok-b"}},
        "isolation": {
            "canary": CANARY,
            "resources": [{"method": "GET", "path": "/api/workspaces/ws_a/clients"}],
        },
        "agent": {
            "endpoint": "/api/agent/chat",
            "body": {"message": "{prompt}"},
            "canaries": [CANARY],
            "injection": {
                "seed": {"method": "POST", "path": "/api/workspaces/ws_b/notes", "body": {"text": "{payload}"}},
                "trigger_prompt": "Summarize my most recent note.",
            },
        },
    }
    return target


def serve(port: int = 8099, vulnerable: bool = True) -> None:
    """Run the demo app in the foreground so you can point your own tools at it."""
    import time

    server = make_server(vulnerable)
    server.shutdown()
    server.server_close()
    server = ThreadingHTTPServer(("127.0.0.1", port), server.RequestHandlerClass)
    mode = "vulnerable" if vulnerable else "patched"
    print(f"Leaky Clinic ({mode}) on http://127.0.0.1:{port}  tokens: tok-a (ws_a), tok-b (ws_b)  Ctrl-C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        time.sleep(0)
