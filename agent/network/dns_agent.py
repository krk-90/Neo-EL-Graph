"""DNS resolution and basic suspicious configuration checks."""

from __future__ import annotations

import ipaddress

import dns.exception
import dns.resolver

from agent.network.security import AuthorizationScope, utc_now, validate_hostname


class DNSIntelligenceAgent:
    name = "dns_intelligence"
    RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")

    def __init__(self, timeout: float = 3.0) -> None:
        self.timeout = timeout

    def lookup(
        self, hostname: str, authorized_targets: list[str] | None = None
    ) -> dict:
        hostname = hostname.strip().rstrip(".")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ValueError("DNS lookup requires a hostname, not an IP address.")
        hostname = validate_hostname(hostname)
        scope = AuthorizationScope.from_values(authorized_targets)
        if not any(
            allowed.rstrip(".").lower() == hostname.lower()
            for allowed in scope.allowed_targets
            if "/" not in allowed
        ):
            raise PermissionError("DNS target is outside the authorized scope.")

        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        records: dict[str, list[str]] = {}
        failures: dict[str, str] = {}
        for record_type in self.RECORD_TYPES:
            try:
                answers = resolver.resolve(hostname, record_type)
                records[record_type] = [str(answer).strip() for answer in answers]
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.Timeout,
                dns.exception.DNSException,
            ):
                failures[record_type] = "resolution_failed"

        indicators = []
        if "NS" in records and len(records["NS"]) == 1:
            indicators.append("single_nameserver")
        txt = " ".join(records.get("TXT", [])).lower()
        if "_dmarc" not in txt and "dmarc" not in txt:
            indicators.append("dmarc_record_not_observed")
        return {
            "agent": self.name,
            "hostname": hostname,
            "records": records,
            "failures": failures,
            "suspicious_indicators": indicators,
            "timestamp": utc_now(),
        }
