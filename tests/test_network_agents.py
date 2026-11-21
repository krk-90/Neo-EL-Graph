import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from agent.network.diagnostics_agent import NetworkDiagnosticsAgent
from agent.network.discovery_agent import NetworkDiscoveryAgent
from agent.network.dns_agent import DNSIntelligenceAgent
from agent.network.port_service_agent import PortServiceAnalysisAgent
from agent.network.tls_agent import TLSSecurityAgent


class NetworkAgentTests(unittest.TestCase):
    def test_dns_lookup_rejects_ip_targets(self):
        with self.assertRaisesRegex(ValueError, "requires a hostname"):
            DNSIntelligenceAgent().lookup(
                "10.0.0.25",
                ["10.0.0.0/24"],
            )

    def test_dns_lookup_requires_explicit_scope(self):
        with self.assertRaisesRegex(ValueError, "authorized_targets"):
            DNSIntelligenceAgent().lookup("example.com")

    def test_discovery_checks_requested_ports(self):
        class FakeWriter:
            def close(self):
                pass

            async def wait_closed(self):
                pass

        async def scenario():
            with (
                patch(
                    "agent.network.discovery_agent.asyncio.open_connection",
                    new=AsyncMock(return_value=(object(), FakeWriter())),
                ) as open_connection,
                patch(
                    "agent.network.discovery_agent.socket.gethostbyaddr",
                    return_value=("host.example", [], ["192.0.2.1"]),
                ),
            ):
                result = await NetworkDiscoveryAgent(timeout=0.01).discover(
                    "192.0.2.1/32",
                    ["192.0.2.1"],
                    [8443],
                )
            return result, open_connection

        result, open_connection = asyncio.run(scenario())
        self.assertEqual(result["ports_requested"], [8443])
        self.assertEqual(result["hosts"][0]["open_ports"], [8443])
        open_connection.assert_awaited_once_with("192.0.2.1", 8443)

    def test_discovery_respects_configured_host_limit(self):
        async def scenario():
            return await NetworkDiscoveryAgent(max_hosts=8).discover(
                "192.168.1.0/24",
                ["192.168.1.0/24"],
            )

        with self.assertRaisesRegex(ValueError, "exceeds 8 hosts"):
            asyncio.run(scenario())

    def test_discovery_omits_network_and_broadcast_addresses(self):
        async def scenario():
            with (
                patch(
                    "agent.network.discovery_agent.asyncio.open_connection",
                    new=AsyncMock(side_effect=ConnectionRefusedError),
                ),
                patch(
                    "agent.network.discovery_agent.socket.gethostbyaddr",
                    side_effect=OSError,
                ),
            ):
                return await NetworkDiscoveryAgent(timeout=0.01).discover(
                    "192.168.1.0/30",
                    ["192.168.1.0/30"],
                    [443],
                )

        result = asyncio.run(scenario())
        self.assertEqual(
            [host["ip"] for host in result["hosts"]],
            ["192.168.1.1", "192.168.1.2"],
        )

    @patch(
        "agent.network.diagnostics_agent.platform.system",
        return_value="Windows",
    )
    @patch(
        "agent.network.diagnostics_agent.shutil.which",
        return_value="C:\\Windows\\System32\\tracert.exe",
    )
    @patch("agent.network.diagnostics_agent.subprocess.run")
    def test_windows_traceroute_uses_millisecond_timeout(
        self, run, _which, _platform
    ):
        run.return_value = SimpleNamespace(returncode=0, stdout="route")
        NetworkDiagnosticsAgent(timeout=5).traceroute(
            "192.0.2.1",
            ["192.0.2.0/24"],
        )

        command = run.call_args.args[0]
        self.assertEqual(command[command.index("-w") + 1], "5000")

    def test_tcp_timeout_and_closed_status(self):
        async def scenario():
            with patch(
                "agent.network.port_service_agent.asyncio.open_connection",
                new=AsyncMock(side_effect=asyncio.TimeoutError),
            ):
                return await PortServiceAnalysisAgent(timeout=0.01).check_ports(
                    "192.168.1.10", [443], ["192.168.1.10"]
                )

        result = asyncio.run(scenario())
        self.assertEqual(result["observations"][0]["status"], "timeout")

    def test_tcp_checks_resolved_ip_not_hostname(self):
        class FakeWriter:
            def close(self):
                pass

            async def wait_closed(self):
                pass

        async def scenario():
            with (
                patch(
                    "agent.network.port_service_agent.resolve_authorized_addresses",
                    return_value=["192.0.2.10"],
                ),
                patch(
                    "agent.network.port_service_agent.asyncio.open_connection",
                    new=AsyncMock(return_value=(object(), FakeWriter())),
                ) as open_connection,
            ):
                result = await PortServiceAnalysisAgent(timeout=0.01).check_ports(
                    "owned.example",
                    [443],
                    ["owned.example"],
                )
            return result, open_connection

        result, open_connection = asyncio.run(scenario())
        self.assertEqual(result["observations"][0]["status"], "open")
        open_connection.assert_awaited_once_with("192.0.2.10", 443)

    def test_tcp_outside_scope_rejected(self):
        async def scenario():
            return await PortServiceAnalysisAgent().check_ports(
                "10.0.0.10", [443], ["10.0.1.0/24"]
            )

        with self.assertRaises(PermissionError):
            asyncio.run(scenario())

    def test_tls_inspection_handles_connection_error(self):
        with (
            patch(
                "agent.network.tls_agent.resolve_authorized_addresses",
                return_value=["192.0.2.10"],
            ),
            patch(
                "agent.network.tls_agent.socket.create_connection",
                side_effect=TimeoutError,
            ) as connection,
        ):
            result = TLSSecurityAgent(timeout=0.1).inspect(
                "owned.example", 443, ["owned.example"]
            )

        connection.assert_called_once_with(("192.0.2.10", 443), timeout=0.1)
        self.assertEqual(result["findings"][0]["category"], "tls_error")


if __name__ == "__main__":
    unittest.main()
