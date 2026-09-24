"""Best-effort runtime enrichment: domain age (WHOIS) and SSL certificate info.

These lookups hit the network and can be slow or blocked, so every function
here is wrapped in a timeout + try/except and returns ``None`` on failure.
They are *advisory* signals for the reason generator, never hard requirements.
"""
from __future__ import annotations

import concurrent.futures
import datetime as _dt
import socket
import ssl
from typing import Optional

_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=4)


def _run_with_timeout(fn, timeout: float):
    try:
        return _POOL.submit(fn).result(timeout=timeout)
    except Exception:
        return None


def _domain_age_days_blocking(domain: str) -> Optional[int]:
    import whois  # imported lazily -- python-whois shells out / parses slowly

    data = whois.whois(domain)
    created = data.creation_date
    if isinstance(created, list):
        created = created[0]
    if not isinstance(created, _dt.datetime):
        return None
    if created.tzinfo is not None:
        created = created.replace(tzinfo=None)
    return max((_dt.datetime.utcnow() - created).days, 0)


def get_domain_age_days(domain: str, timeout: float = 3.0) -> Optional[int]:
    if not domain:
        return None
    return _run_with_timeout(lambda: _domain_age_days_blocking(domain), timeout)


def _ssl_info_blocking(hostname: str, port: int = 443) -> Optional[dict]:
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=3) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()

    def _name(seq):
        out = {}
        for rdn in seq or ():
            for k, v in rdn:
                out[k] = v
        return out

    issuer = _name(cert.get("issuer"))
    not_after = cert.get("notAfter")
    days_to_expiry = None
    if not_after:
        try:
            exp = _dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_to_expiry = (exp - _dt.datetime.utcnow()).days
        except ValueError:
            pass
    return {
        "valid": True,  # handshake + hostname check passed
        "issuer_org": issuer.get("organizationName") or issuer.get("commonName"),
        "days_to_expiry": days_to_expiry,
    }


def get_ssl_info(hostname: str, timeout: float = 3.0) -> Optional[dict]:
    """Returns dict on a successful validated handshake, ``{"valid": False}``
    if the handshake/verification fails, or ``None`` if the check couldn't run."""
    if not hostname:
        return None

    def _attempt():
        try:
            return _ssl_info_blocking(hostname)
        except ssl.SSLError:
            return {"valid": False, "issuer_org": None, "days_to_expiry": None}
        except ssl.CertificateError:
            return {"valid": False, "issuer_org": None, "days_to_expiry": None}
        except (socket.gaierror, socket.timeout, ConnectionError, OSError):
            return None

    return _run_with_timeout(_attempt, timeout)
