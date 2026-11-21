import unittest
from unittest.mock import patch

from agent.nvd_api_agent import NVDApiAgent


def api_cve(cve_id: str = "CVE-2021-44228") -> dict:
    return {
        "cve": {
            "id": cve_id,
            "vulnStatus": "Analyzed",
            "published": "2021-12-10T10:15:09.143",
            "lastModified": "2026-08-11T19:33:44.513",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Remote code execution vulnerability.",
                }
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "version": "3.1",
                            "baseScore": 10.0,
                            "baseSeverity": "CRITICAL",
                            "vectorString": "CVSS:3.1/AV:N",
                        },
                        "baseSeverity": "CRITICAL",
                    }
                ]
            },
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}]}],
            "references": [{"url": "https://example.com/advisory"}],
        }
    }


class NVDApiAgentTests(unittest.TestCase):
    @patch.object(NVDApiAgent, "_request")
    def test_exact_cve_lookup(self, request_mock):
        request_mock.return_value = {"vulnerabilities": [api_cve()]}
        result = NVDApiAgent().ask("Summarize CVE-2021-44228")

        self.assertEqual(result.cve_ids, ("CVE-2021-44228",))
        self.assertEqual(
            result.vulnerabilities[0]["cve_id"],
            "CVE-2021-44228",
        )
        request_mock.assert_called_once_with({"cveId": "CVE-2021-44228"})

    @patch.object(NVDApiAgent, "_request")
    def test_keyword_search_with_severity(self, request_mock):
        request_mock.return_value = {"vulnerabilities": [api_cve("CVE-2021-44228")]}
        result = NVDApiAgent().ask(
            "remote code execution",
            limit=5,
            severity="CRITICAL",
        )

        self.assertEqual(result.cve_ids, ())
        self.assertEqual(len(result.vulnerabilities), 1)
        request_mock.assert_called_once_with(
            {
                "keywordSearch": "remote code execution",
                "resultsPerPage": "5",
                "cvssV3Severity": "CRITICAL",
            }
        )

    def test_invalid_cve_id_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Invalid CVE ID"):
            NVDApiAgent().fetch_cve("not-a-cve")


if __name__ == "__main__":
    unittest.main()
