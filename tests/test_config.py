import tempfile
import unittest
from pathlib import Path

from agent.config import load_runtime_config


class RuntimeConfigTests(unittest.TestCase):
    def test_environment_overrides_yaml_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yml"
            config_path.write_text(
                "mcp:\n  host: 127.0.0.1\n  port: 8000\n"
                "network:\n  max_hosts: 128\n  max_ports: 32\n",
                encoding="utf-8",
            )
            config = load_runtime_config(
                config_path,
                {"MCP_PORT": "8123", "NETWORK_MAX_HOSTS": "16"},
            )

        self.assertEqual(config.mcp_port, 8123)
        self.assertEqual(config.network_max_hosts, 16)
        self.assertEqual(config.network_max_ports, 32)

    def test_invalid_environment_override_fails_clearly(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yml"
            config_path.write_text("mcp:\n  port: 8000\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "MCP_PORT"):
                load_runtime_config(config_path, {"MCP_PORT": "70000"})


if __name__ == "__main__":
    unittest.main()
