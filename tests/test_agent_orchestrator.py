import unittest
from unittest.mock import patch

from agent.orchestrator.graph import run_security_assessment
from agent.orchestrator.nodes import classify_node
from tools.mcp_tools.handlers import (
    safe_handler,
    security_assessment,
    tls_inspect,
)
from tools.mcp_tools.schemas import PortCheckInput
from tools.mcp_tools.server import mcp


class OrchestratorTests(unittest.TestCase):
    def test_request_classification(self):
        state = classify_node({"request": "check DNS and TLS on this target"})
        self.assertIn("dns_intelligence", state["selected_agents"])
        self.assertIn("tls_security", state["selected_agents"])
        self.assertEqual(state["classification"], "combined")

    def test_target_range_selects_discovery(self):
        state = classify_node(
            {"request": "Find authorized hosts", "target_range": "192.168.1.0/24"}
        )
        self.assertEqual(state["selected_agents"], ["network_discovery"])

    @patch(
        "agent.orchestrator.nodes.DNSIntelligenceAgent.lookup",
        return_value={"agent": "dns_intelligence", "records": {}},
    )
    @patch(
        "agent.orchestrator.nodes.TLSSecurityAgent.inspect",
        return_value={
            "agent": "tls_security",
            "host": "example.com",
            "port": 443,
            "certificate": {},
            "protocol": "TLSv1.3",
            "findings": [],
        },
    )
    def test_combined_request_runs_both_selected_agents(self, _inspect, _lookup):
        result = run_security_assessment(
            request="Check DNS and TLS",
            target="example.com",
            authorized_targets=["example.com"],
            ports=[443],
        )

        self.assertEqual(result["classification"], "combined")
        self.assertEqual(
            set(result["selected_agents"]), {"dns_intelligence", "tls_security"}
        )
        self.assertIn("dns_intelligence", result["results"])
        self.assertIn("tls_security", result["results"])

    def test_authorization_safe_error(self):
        @safe_handler
        def denied():
            raise PermissionError

        output = denied()
        self.assertEqual(output["status"], "error")
        self.assertEqual(output["error"]["category"], "authorization_denied")

    def test_mcp_validation_error_is_reported_as_invalid_input(self):
        @safe_handler
        def invalid():
            return PortCheckInput(
                host="192.0.2.1",
                ports=[0],
                authorized_targets=["192.0.2.1"],
            ).model_dump()

        output = invalid()
        self.assertEqual(output["status"], "error")
        self.assertEqual(output["error"]["category"], "invalid_input")

    @patch(
        "tools.mcp_tools.handlers.TLSSecurityAgent.inspect",
        return_value={
            "findings": [
                {
                    "category": "tls_error",
                    "error_category": "TimeoutError",
                }
            ]
        },
    )
    def test_mcp_tls_timeout_is_not_reported_as_success(self, _inspect):
        output = tls_inspect(
            "192.0.2.1",
            443,
            ["192.0.2.1"],
        )

        self.assertEqual(output["status"], "error")
        self.assertEqual(output["error"]["error_type"], "TimeoutError")

    @patch(
        "tools.mcp_tools.handlers.run_security_assessment",
        return_value={"assessment": {"partial_results": True}},
    )
    def test_mcp_assessment_preserves_partial_status(self, _assessment):
        output = security_assessment(
            request="Assess authorized host",
            target="192.0.2.1",
            authorized_targets=["192.0.2.1"],
        )

        self.assertEqual(output["status"], "partial")

    @patch(
        "agent.orchestrator.nodes.TLSSecurityAgent.inspect",
        return_value={
            "agent": "tls_security",
            "host": "192.168.1.10",
            "port": 443,
            "certificate": None,
            "protocol": None,
            "findings": [
                {
                    "category": "tls_error",
                    "observation": "TLS inspection failed.",
                    "error_category": "TimeoutError",
                }
            ],
        },
    )
    def test_tls_connection_error_is_reported_as_incomplete(self, _inspect):
        result = run_security_assessment(
            request="Check TLS certificate",
            target="192.168.1.10",
            authorized_targets=["192.168.1.0/24"],
            ports=[443],
        )

        tls_trace = next(
            item
            for item in result["execution_trace"]
            if item.get("agent") == "tls_security"
        )
        self.assertEqual(tls_trace["status"], "failure")
        self.assertEqual(tls_trace["error_category"], "TimeoutError")
        self.assertTrue(result["assessment"]["partial_results"])
        self.assertEqual(result["findings"], [])
        self.assertEqual(
            result["results"]["tls_security"]["findings"][0]["error_category"],
            "TimeoutError",
        )

    def test_mcp_tools_registered(self):
        tools = set(mcp._tool_manager._tools)
        expected = {
            "network_discover_tool",
            "dns_lookup_tool",
            "ping_host_tool",
            "traceroute_host_tool",
            "tcp_check_tool",
            "port_check_tool",
            "tls_inspect_tool",
            "network_diagnose_tool",
            "cve_lookup_tool",
            "search_cve_knowledge_tool",
            "security_assessment_tool",
        }
        self.assertEqual(expected, tools)


if __name__ == "__main__":
    unittest.main()
