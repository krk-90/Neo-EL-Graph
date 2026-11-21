"""Authorized host discovery using TCP availability checks."""

from __future__ import annotations

import asyncio
import ipaddress
import socket

from agent.network.security import (
    AuthorizationScope,
    is_prohibited_ip,
    network_limits,
    target_is_authorized,
    utc_now,
    validate_ip_or_cidr,
    validate_port_list,
)


class NetworkDiscoveryAgent:
    name = "network_discovery"

    def __init__(
        self,
        max_concurrent: int = 32,
        timeout: float = 3.0,
        max_hosts: int = 256,
        max_ports: int = 64,
    ) -> None:
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.max_hosts = max_hosts
        self.max_ports = max_ports

    async def _check_host(self, address: str, ports: list[int]) -> dict:
        loop = asyncio.get_running_loop()
        open_ports = []
        for port in ports:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(address, port),
                    timeout=self.timeout,
                )
                writer.close()
                await writer.wait_closed()
                open_ports.append(port)
            except Exception:
                continue
        try:
            await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, address),
                timeout=self.timeout,
            )
            reverse_dns = True
        except Exception:
            reverse_dns = False

        return {
            "ip": address,
            "reachable": bool(open_ports),
            "open_ports": open_ports,
            "reverse_dns": reverse_dns,
            "timestamp": utc_now(),
        }

    async def discover(
        self,
        target_range: str,
        authorized_targets: list[str],
        ports: list[int] | None = None,
    ) -> dict:
        normalized = validate_ip_or_cidr(target_range)
        scope = AuthorizationScope.from_values(authorized_targets)
        network = ipaddress.ip_network(normalized, strict=False)
        limits = network_limits()
        max_hosts = min(self.max_hosts, limits["max_hosts"])
        max_ports = min(self.max_ports, limits["max_ports"])
        host_count = network.num_addresses
        if network.version == 4 and network.prefixlen < 31:
            host_count -= 2
        if host_count > max_hosts:
            raise ValueError(f"Discovery range exceeds {max_hosts} hosts.")
        scan_ports = validate_port_list(
            ports or [80, 443],
            max_ports=max_ports,
        )
        addresses = [
            str(address)
            for address in network.hosts()
            if not is_prohibited_ip(address)
            and target_is_authorized(str(address), scope)
        ]
        if not addresses:
            raise PermissionError("Discovery range contains no authorized hosts.")

        sem = asyncio.Semaphore(self.max_concurrent)

        async def bounded(address: str) -> dict:
            async with sem:
                return await self._check_host(address, scan_ports)

        results = await asyncio.gather(*(bounded(address) for address in addresses))
        return {
            "agent": self.name,
            "target_range": normalized,
            "hosts": list(results),
            "ports_requested": scan_ports,
            "timestamp": utc_now(),
        }
