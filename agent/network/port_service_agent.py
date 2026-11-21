"""Limited TCP port checks for explicitly authorized hosts."""

from __future__ import annotations

import asyncio
import socket

from agent.network.security import (
    AuthorizationScope,
    network_limits,
    resolve_authorized_addresses,
    utc_now,
    validate_port_list,
)


class PortServiceAnalysisAgent:
    name = "port_service_analysis"

    def __init__(self, timeout: float = 3.0, max_concurrent: int = 32) -> None:
        self.timeout = timeout
        self.max_concurrent = max_concurrent

    async def check_ports(
        self,
        host: str,
        ports: list[int],
        authorized_targets: list[str],
    ) -> dict:
        scope = AuthorizationScope.from_values(authorized_targets)
        addresses = resolve_authorized_addresses(host, scope, self.timeout)
        validated_ports = validate_port_list(
            ports,
            max_ports=network_limits()["max_ports"],
        )
        sem = asyncio.Semaphore(self.max_concurrent)

        async def check(port: int) -> dict:
            async with sem:
                statuses = []
                for address in addresses:
                    try:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(address, port),
                            timeout=self.timeout,
                        )
                        writer.close()
                        await writer.wait_closed()
                        return {
                            "port": port,
                            "status": "open",
                            "service": None,
                            "addresses": addresses,
                            "timestamp": utc_now(),
                        }
                    except asyncio.TimeoutError:
                        statuses.append("timeout")
                    except ConnectionRefusedError:
                        statuses.append("closed")
                    except socket.gaierror:
                        statuses.append("dns_error")
                    except OSError:
                        statuses.append("connection_error")
                if "timeout" in statuses:
                    status = "timeout"
                elif "connection_error" in statuses or "dns_error" in statuses:
                    status = "connection_error"
                else:
                    status = "closed"
                return {
                    "port": port,
                    "status": status,
                    "service": None,
                    "addresses": addresses,
                    "timestamp": utc_now(),
                }

        observations = await asyncio.gather(*(check(port) for port in validated_ports))
        return {
            "agent": self.name,
            "host": host,
            "observations": list(observations),
            "timestamp": utc_now(),
        }
