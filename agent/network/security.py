"""Authorization and validation controls for network operations."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

import dns.exception
import dns.resolver

from agent.config import load_runtime_config

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
PROHIBITED_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
}


@dataclass(frozen=True)
class AuthorizationScope:
    allowed_targets: tuple[str, ...]

    @classmethod
    def from_values(
        cls, values: list[str] | tuple[str, ...] | None
    ) -> "AuthorizationScope":
        if not values:
            raise ValueError("Explicit authorized_targets scope is required.")
        return cls(
            tuple(
                value.strip()
                for value in values
                if isinstance(value, str) and value.strip()
            )
        )


def utc_now() -> str:
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def is_prohibited_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return is_prohibited_ip(address.ipv4_mapped)
    if address in PROHIBITED_IPS:
        return True
    if getattr(address, "is_loopback", False):
        return True
    if getattr(address, "is_link_local", False):
        return True
    if getattr(address, "is_multicast", False):
        return True
    if getattr(address, "is_unspecified", False):
        return True
    return False


def validate_ip_or_cidr(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Target must be a non-empty string.")
    value = value.strip()
    if "/" not in value:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(
                "Target must be a valid IP address or CIDR range."
            ) from exc
        if is_prohibited_ip(address):
            raise ValueError("Target is in a prohibited network scope.")
        return str(address)
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise ValueError("Target must be a valid IP address or CIDR range.")
    if network.prefixlen < (96 if network.version == 6 else 24):
        raise ValueError("CIDR range is too broad.")
    if (
        network.is_loopback
        or network.is_link_local
        or network.is_multicast
        or network.network_address.is_unspecified
    ):
        raise ValueError("CIDR range contains a prohibited network scope.")
    for prohibited in PROHIBITED_IPS:
        if prohibited in network:
            raise ValueError("CIDR range contains a prohibited address.")
    return str(network)


def validate_hostname(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Hostname must be a string.")
    value = value.strip().rstrip(".")
    if not HOSTNAME_PATTERN.match(value):
        raise ValueError("Invalid hostname.")
    if value.lower() in {"localhost", "localhost.localdomain"}:
        raise ValueError("Localhost targets are prohibited.")
    return value


def resolve_public_or_private_host(hostname: str, timeout: float = 3.0) -> list[str]:
    hostname = validate_hostname(hostname)
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    addresses: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            records = resolver.resolve(hostname, record_type)
        except dns.exception.DNSException:
            continue
        for record in records:
            address = str(record)
            parsed = ipaddress.ip_address(address)
            if not is_prohibited_ip(parsed) and address not in addresses:
                addresses.append(address)
    if not addresses:
        raise RuntimeError("DNS returned no permitted IP addresses.")
    return addresses


def target_is_authorized(target: str, scope: AuthorizationScope) -> bool:
    target = target.strip()
    try:
        if "/" in target:
            target_network = ipaddress.ip_network(target, strict=False)
            return any(
                "/" in allowed
                and target_network.subnet_of(
                    ipaddress.ip_network(allowed, strict=False)
                )
                for allowed in scope.allowed_targets
            )
        target_address = ipaddress.ip_address(target)
        if is_prohibited_ip(target_address):
            return False
        for allowed in scope.allowed_targets:
            try:
                if "/" in allowed:
                    if target_address in ipaddress.ip_network(allowed, strict=False):
                        return True
                elif ipaddress.ip_address(allowed) == target_address:
                    return True
            except ValueError:
                continue
        return False
    except ValueError:
        target_host = validate_hostname(target)
        for allowed in scope.allowed_targets:
            if "/" in allowed:
                continue
            try:
                ipaddress.ip_address(allowed)
            except ValueError:
                if allowed.rstrip(".").lower() == target_host.lower():
                    return True
                continue
        return False


def resolve_authorized_addresses(
    target: str,
    scope: AuthorizationScope,
    timeout: float = 3.0,
) -> list[str]:
    if not target_is_authorized(target, scope):
        raise PermissionError("Target is outside the authorized scope.")
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        return resolve_public_or_private_host(target, timeout)
    if is_prohibited_ip(address):
        raise PermissionError("Target is in a prohibited network scope.")
    return [str(address)]


def validate_port_list(
    ports: list[int] | tuple[int, ...], max_ports: int = 64
) -> list[int]:
    if not ports:
        raise ValueError("At least one port is required.")
    if len(ports) > max_ports:
        raise ValueError(f"Port count exceeds limit of {max_ports}.")
    validated = []
    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int):
            raise ValueError("Ports must be integers.")
        if port < 1 or port > 65535:
            raise ValueError("Ports must be between 1 and 65535.")
        if port not in validated:
            validated.append(port)
    return validated


def network_limits() -> dict[str, int]:
    config = load_runtime_config()
    return {
        "max_hosts": config.network_max_hosts,
        "max_ports": config.network_max_ports,
        "max_concurrent": config.network_max_concurrent,
        "timeout": config.network_timeout_seconds,
    }
