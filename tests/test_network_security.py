import ipaddress
import unittest
from unittest.mock import patch

import dns.resolver
from pydantic import ValidationError

from agent.network.security import (
    AuthorizationScope,
    is_prohibited_ip,
    resolve_public_or_private_host,
    target_is_authorized,
    validate_ip_or_cidr,
    validate_port_list,
)
from tools.mcp_tools.schemas import DiscoveryInput, PortCheckInput


class NetworkSecurityTests(unittest.TestCase):
    def test_private_and_public_ip_authorization(self):
        scope = AuthorizationScope.from_values(["10.0.0.0/24", "8.8.8.8"])
        self.assertTrue(target_is_authorized("10.0.0.15", scope))
        self.assertTrue(target_is_authorized("8.8.8.8", scope))
        self.assertFalse(target_is_authorized("10.0.1.15", scope))

    @patch("agent.network.security.dns.resolver.Resolver")
    def test_hostname_resolution_filters_prohibited_addresses(self, resolver_class):
        class FakeResolver:
            def resolve(self, hostname, record_type):
                if record_type == "A":
                    return ["192.0.2.10", "169.254.169.254"]
                raise dns.resolver.NoAnswer

        resolver_class.return_value = FakeResolver()
        self.assertEqual(
            resolve_public_or_private_host("owned.example", timeout=1),
            ["192.0.2.10"],
        )

    def test_metadata_endpoint_rejected(self):
        with self.assertRaises(ValueError):
            validate_ip_or_cidr("169.254.169.254")
        self.assertTrue(is_prohibited_ip(ipaddress.ip_address("169.254.169.254")))
        self.assertTrue(
            is_prohibited_ip(ipaddress.ip_address("::ffff:169.254.169.254"))
        )

    def test_cidr_validation_and_limit(self):
        self.assertEqual(validate_ip_or_cidr("192.168.1.42"), "192.168.1.42")
        self.assertEqual(validate_ip_or_cidr("192.168.1.0/24"), "192.168.1.0/24")
        with self.assertRaises(ValueError):
            validate_ip_or_cidr("0.0.0.0/0")
        for prohibited_range in (
            "127.0.0.0/24",
            "169.254.1.0/24",
            "224.0.0.0/24",
            "0.0.0.0/24",
            "::/96",
        ):
            with self.subTest(prohibited_range=prohibited_range):
                with self.assertRaises(ValueError):
                    validate_ip_or_cidr(prohibited_range)
        with self.assertRaises(ValueError):
            validate_ip_or_cidr("not-an-address")

    def test_port_validation(self):
        self.assertEqual(validate_port_list([80, 443, 80]), [80, 443])
        with self.assertRaises(ValueError):
            validate_port_list([0])
        with self.assertRaises(ValueError):
            validate_port_list(list(range(1, 66)))

    def test_mcp_schemas_reject_invalid_inputs(self):
        with self.assertRaises(ValidationError):
            DiscoveryInput(target_range="0.0.0.0/0", authorized_targets=["8.8.8.8"])
        with self.assertRaises(ValidationError):
            PortCheckInput(
                host="8.8.8.8", ports=[70000], authorized_targets=["8.8.8.8"]
            )
        with self.assertRaises(ValidationError):
            PortCheckInput(
                host="8.8.8.8", ports=[True], authorized_targets=["8.8.8.8"]
            )


if __name__ == "__main__":
    unittest.main()
