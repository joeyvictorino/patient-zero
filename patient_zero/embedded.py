"""Embedded mode: run the probes inside your own test suite, in-process.

No server to start, no target file, no port. Hand the probe your framework's
test client (or a bare WSGI app) and it talks to your application directly.
This is the cheapest way to meet TEST-1: cross-tenant tests on every route,
on every commit.

    from patient_zero.embedded import assert_isolated

    def test_tenants_cannot_read_each_other(client):          # your framework's test client
        assert_isolated(client, token_a=TOKEN_A, token_b=TOKEN_B,
                        resources=["/api/workspaces/ws_a/clients", "/api/workspaces/ws_a/notes"],
                        canary="a string only tenant A's data contains")

Works with anything shaped like `requests` (httpx, Starlette and FastAPI test
clients), with Flask and Werkzeug test clients, and with any WSGI callable.
"""
from __future__ import annotations

import io
import json
from typing import Any, Callable, Dict, Iterable, Optional, Tuple
from wsgiref.util import setup_testing_defaults

from .probes import agent, isolation
from .probes.common import ProbeResult

Transport = Callable[[str, str, Dict[str, str], Any], Tuple[int, str]]


def wsgi_transport(app: Callable) -> Transport:
    def send(method: str, path: str, headers: Dict[str, str], body: Any) -> Tuple[int, str]:
        payload = json.dumps(body).encode("utf-8") if body is not None else b""
        path_info, _, query = path.partition("?")
        environ: Dict[str, Any] = {}
        setup_testing_defaults(environ)
        environ.update({"REQUEST_METHOD": method, "PATH_INFO": path_info, "QUERY_STRING": query,
                        "CONTENT_LENGTH": str(len(payload)), "wsgi.input": io.BytesIO(payload)})
        for name, value in headers.items():
            key = name.upper().replace("-", "_")
            environ[key if key in ("CONTENT_TYPE", "CONTENT_LENGTH") else "HTTP_" + key] = value
        seen: Dict[str, Any] = {}

        def start_response(status, response_headers, exc_info=None):
            seen["status"] = int(status.split(" ", 1)[0])

        chunks = app(environ, start_response)
        try:
            text = b"".join(chunks).decode("utf-8", "replace")
        finally:
            if hasattr(chunks, "close"):
                chunks.close()
        return seen.get("status", 500), text

    return send


def client_transport(client: Any) -> Transport:
    """Adapt a test client. Requests-shaped clients expose .request; Flask and Werkzeug expose .open."""
    def send(method: str, path: str, headers: Dict[str, str], body: Any) -> Tuple[int, str]:
        if hasattr(client, "request"):
            resp = client.request(method, path, headers=headers, json=body) if body is not None \
                else client.request(method, path, headers=headers)
            return int(resp.status_code), resp.text
        resp = client.open(path, method=method, headers=headers, json=body) if body is not None \
            else client.open(path, method=method, headers=headers)
        return int(resp.status_code), resp.get_data(as_text=True)

    return send


def transport_for(app_or_client: Any) -> Transport:
    if hasattr(app_or_client, "request") or hasattr(app_or_client, "open"):
        return client_transport(app_or_client)
    if callable(app_or_client):
        return wsgi_transport(app_or_client)
    raise TypeError("expected a WSGI app or a test client with .request or .open")


def embedded_target(app_or_client: Any, token_a: str, token_b: str, **sections: Any) -> Dict[str, Any]:
    target = {
        "authorized": True,                 # it is your own application, in your own process
        "synthetic_data_only": True,
        "authorization_ref": "embedded: in-process test of the caller's own application",
        "base_url": "http://embedded.invalid",
        "tenants": {"a": {"token": token_a}, "b": {"token": token_b}},
        "_transport": transport_for(app_or_client),
    }
    target.update(sections)
    return target


def check_isolation(app_or_client: Any, token_a: str, token_b: str, resources: Iterable[Any],
                    canary: Optional[str] = None, **options: Any) -> ProbeResult:
    section: Dict[str, Any] = {"resources": [r if isinstance(r, dict) else {"method": "GET", "path": r} for r in resources]}
    if canary:
        section["canary"] = canary
    return isolation.run(embedded_target(app_or_client, token_a, token_b, isolation=section, **options))


def check_agent(app_or_client: Any, token_a: str, token_b: str, **agent_config: Any) -> ProbeResult:
    return agent.run(embedded_target(app_or_client, token_a, token_b, agent=agent_config))


def _raise_on_findings(result: ProbeResult) -> ProbeResult:
    if result.findings:
        raise AssertionError(f"{result.probe} probe: " + "; ".join(result.grouped()))
    if result.void:
        raise AssertionError(f"{result.probe} probe tested nothing: " + "; ".join(result.inconclusive))
    return result


def assert_isolated(app_or_client: Any, token_a: str, token_b: str, resources: Iterable[Any],
                    canary: Optional[str] = None, **options: Any) -> ProbeResult:
    """Fail the test on any cross-tenant read, and also when no route could be tested at all."""
    return _raise_on_findings(check_isolation(app_or_client, token_a, token_b, resources, canary, **options))


def assert_agent_contained(app_or_client: Any, token_a: str, token_b: str, **agent_config: Any) -> ProbeResult:
    return _raise_on_findings(check_agent(app_or_client, token_a, token_b, **agent_config))
