"""Transport probe (BASE-2, in-transit half only)."""
from __future__ import annotations

import socket
import ssl
from typing import Any, Dict
from urllib.parse import urlparse

from .common import ProbeResult, request, start

_LOCAL = {"localhost", "127.0.0.1", "::1"}
_WEAK = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def run(target: Dict[str, Any]) -> ProbeResult:
    result = start("tls", ["BASE-2"], target)
    parsed = urlparse(target["base_url"])
    host = parsed.hostname or ""
    result.checks += 1
    if parsed.scheme != "https":
        if host in _LOCAL:
            result.inconclusive.append("target is plain HTTP on localhost; run this probe against a deployed environment")
        else:
            result.add("BASE-2", "critical", "Target is served over plain HTTP", "PHI in transit must use TLS 1.2 or later")
        return result

    port = parsed.port or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                version = tls.version() or "unknown"
    except ssl.SSLCertVerificationError as exc:
        result.add("BASE-2", "high", "Certificate did not validate", str(exc.verify_message))
        return result
    except (ssl.SSLError, OSError) as exc:
        result.inconclusive.append(f"could not complete a TLS handshake: {exc}")
        return result
    result.checks_for["BASE-2"] = 1
    if version in _WEAK:
        result.add("BASE-2", "high", f"Server negotiated {version}", "TLS 1.2 or later is required")

    result.checks += 1
    resp = request(target, "GET", "/")
    if not any(k.lower() == "strict-transport-security" for k in resp.headers):
        result.inconclusive.append("no Strict-Transport-Security header on / (recommended)")
    result.inconclusive.append(f"negotiated {version}; encryption at rest and key management need a config review")
    return result
