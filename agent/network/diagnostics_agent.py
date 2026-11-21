"""Safe ping, traceroute, TCP, and DNS diagnostic orchestration."""

from __future__ import annotations

import platform
import shutil
import subprocess

from agent.network.security import (
    AuthorizationScope,
    resolve_authorized_addresses,
    utc_now,
)


class NetworkDiagnosticsAgent:
    name = "network_diagnostics"

    def __init__(self, timeout: float = 3.0) -> None:
        self.timeout = timeout

    def ping(self, host: str, authorized_targets: list[str]) -> dict:
        scope = AuthorizationScope.from_values(authorized_targets)
        address = resolve_authorized_addresses(host, scope, self.timeout)[0]
        executable = shutil.which("ping")
        if not executable:
            return {
                "host": host,
                "address": address,
                "status": "unavailable",
                "output": "",
                "timestamp": utc_now(),
            }
        count_arg = "-n" if platform.system().lower().startswith("windows") else "-c"
        try:
            completed = subprocess.run(
                [
                    executable,
                    count_arg,
                    "1",
                    "-w" if platform.system().lower().startswith("windows") else "-W",
                    str(int(self.timeout * 1000))
                    if platform.system().lower().startswith("windows")
                    else str(int(self.timeout)),
                    address,
                ],
                capture_output=True,
                text=True,
                timeout=max(self.timeout, 5),
                check=False,
            )
            return {
                "host": host,
                "address": address,
                "status": "success" if completed.returncode == 0 else "failure",
                "output": completed.stdout[-2000:],
                "timestamp": utc_now(),
            }
        except subprocess.TimeoutExpired:
            return {
                "host": host,
                "address": address,
                "status": "timeout",
                "output": "",
                "timestamp": utc_now(),
            }

    def traceroute(self, host: str, authorized_targets: list[str]) -> dict:
        scope = AuthorizationScope.from_values(authorized_targets)
        address = resolve_authorized_addresses(host, scope, self.timeout)[0]
        name = (
            "tracert"
            if platform.system().lower().startswith("windows")
            else "traceroute"
        )
        executable = shutil.which(name)
        if not executable:
            return {
                "host": host,
                "address": address,
                "status": "unavailable",
                "output": "",
                "timestamp": utc_now(),
            }
        try:
            command = (
                [
                    executable,
                    "-w",
                    str(int(self.timeout)),
                    "-m",
                    "15",
                    address,
                ]
                if name == "traceroute"
                else [
                    executable,
                    "-w",
                    str(int(self.timeout * 1000)),
                    "-h",
                    "15",
                    address,
                ]
            )
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=max(self.timeout, 30),
                check=False,
            )
            return {
                "host": host,
                "address": address,
                "status": "success" if completed.returncode == 0 else "failure",
                "output": completed.stdout[-4000:],
                "timestamp": utc_now(),
            }
        except subprocess.TimeoutExpired:
            return {
                "host": host,
                "address": address,
                "status": "timeout",
                "output": "",
                "timestamp": utc_now(),
            }
