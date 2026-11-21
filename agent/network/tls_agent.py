"""Defensive TLS certificate and protocol inspection."""

from __future__ import annotations

import datetime
import socket
import ssl

from agent.network.security import (
    AuthorizationScope,
    resolve_authorized_addresses,
    utc_now,
)


class TLSSecurityAgent:
    name = "tls_security"

    def __init__(self, timeout: float = 3.0) -> None:
        self.timeout = timeout

    def inspect(self, host: str, port: int, authorized_targets: list[str]) -> dict:
        scope = AuthorizationScope.from_values(authorized_targets)
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or port < 1
            or port > 65535
        ):
            raise ValueError("Invalid TLS port.")

        addresses = resolve_authorized_addresses(host, scope, self.timeout)
        findings = []
        cert = None
        protocol = None
        last_error: Exception | None = None
        for address in addresses:
            try:
                context = ssl.create_default_context()
                with socket.create_connection(
                    (address, port), timeout=self.timeout
                ) as raw:
                    with context.wrap_socket(raw, server_hostname=host) as tls:
                        protocol = tls.version()
                        cert = tls.getpeercert()
                break
            except (
                ssl.SSLCertVerificationError,
                ssl.SSLError,
                socket.timeout,
                OSError,
            ) as exc:
                last_error = exc
        if cert is None:
            return {
                "agent": self.name,
                "host": host,
                "port": port,
                "addresses": addresses,
                "certificate": None,
                "protocol": protocol,
                "findings": [
                    {
                        "category": "tls_error",
                        "observation": "TLS inspection failed.",
                        "error_category": type(last_error).__name__
                        if last_error
                        else "TLSInspectionError",
                        "timestamp": utc_now(),
                    }
                ],
                "timestamp": utc_now(),
            }

        now = datetime.datetime.now(datetime.timezone.utc)
        not_after = cert.get("notAfter")
        expires = (
            datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=datetime.timezone.utc
            )
            if not_after
            else None
        )
        if expires and expires < now:
            findings.append(
                {
                    "category": "expired_certificate",
                    "observation": "Certificate has expired.",
                    "timestamp": utc_now(),
                }
            )

        try:
            ssl.match_hostname(cert, host)
        except ssl.CertificateError:
            findings.append(
                {
                    "category": "hostname_mismatch",
                    "observation": "Certificate hostname does not match target.",
                    "timestamp": utc_now(),
                }
            )

        if protocol in {"TLSv1", "TLSv1.1"}:
            findings.append(
                {
                    "category": "weak_tls_protocol",
                    "observation": f"{protocol} is deprecated.",
                    "timestamp": utc_now(),
                }
            )

        return {
            "agent": self.name,
            "host": host,
            "port": port,
            "addresses": addresses,
            "certificate": {
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "not_before": cert.get("notBefore"),
                "not_after": not_after,
                "serial_number": cert.get("serialNumber"),
            },
            "protocol": protocol,
            "findings": findings,
            "timestamp": utc_now(),
        }
