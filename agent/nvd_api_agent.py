"""NVD API agent for exact and keyword vulnerability lookups."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


@dataclass(frozen=True)
class NVDAgentResult:
    query: str
    cve_ids: tuple[str, ...]
    vulnerabilities: tuple[dict, ...]


def _english_description(cve: dict) -> str:
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en":
            return description.get("value", "")
    return ""


def _cvss(cve: dict) -> dict:
    metrics = cve.get("metrics", {})
    for metric_name in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        entries = metrics.get(metric_name, [])
        if not entries:
            continue
        entry = entries[0]
        data = entry.get("cvssData", {})
        return {
            "version": data.get("version"),
            "score": data.get("baseScore"),
            "severity": data.get("baseSeverity") or entry.get("baseSeverity"),
            "vector": data.get("vectorString"),
        }
    return {"version": None, "score": None, "severity": "UNKNOWN", "vector": None}


def summarize_vulnerability(item: dict) -> dict:
    cve = item.get("cve", item)
    return {
        "cve_id": cve.get("id"),
        "status": cve.get("vulnStatus"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": _english_description(cve),
        "cvss": _cvss(cve),
        "weaknesses": sorted(
            {
                value
                for weakness in cve.get("weaknesses", [])
                for value in (
                    description.get("value")
                    for description in weakness.get("description", [])
                    if description.get("value", "").startswith("CWE-")
                )
            }
        ),
        "references": list(
            dict.fromkeys(
                reference.get("url")
                for reference in cve.get("references", [])
                if reference.get("url")
            )
        ),
    }


class NVDApiAgent:
    def __init__(
        self,
        api_key: str | None = None,
        timeout: int = 30,
    ) -> None:
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.timeout = timeout

    def _request(self, params: dict[str, str]) -> dict:
        url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"NVD API returned HTTP {exc.code}: {exc.reason}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Could not reach the NVD API: {exc.reason}") from exc

    def fetch_cve(self, cve_id: str) -> dict:
        cve_id = cve_id.strip().upper()
        if not CVE_PATTERN.fullmatch(cve_id):
            raise ValueError(f"Invalid CVE ID: {cve_id}")
        payload = self._request({"cveId": cve_id})
        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            raise RuntimeError(f"NVD API returned no record for {cve_id}.")
        return summarize_vulnerability(vulnerabilities[0])

    def search(
        self,
        keyword: str,
        limit: int = 10,
        severity: str | None = None,
    ) -> list[dict]:
        if not keyword.strip():
            raise ValueError("A search keyword is required.")
        if limit < 1 or limit > 200:
            raise ValueError("Limit must be between 1 and 200.")

        params: dict[str, str] = {
            "keywordSearch": keyword.strip(),
            "resultsPerPage": str(limit),
        }
        if severity:
            normalized = severity.strip().upper()
            if normalized not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                raise ValueError("Severity must be LOW, MEDIUM, HIGH or CRITICAL.")
            params["cvssV3Severity"] = normalized

        payload = self._request(params)
        return [
            summarize_vulnerability(item)
            for item in payload.get("vulnerabilities", [])[:limit]
        ]

    def ask(
        self,
        query: str,
        limit: int = 10,
        severity: str | None = None,
    ) -> NVDAgentResult:
        cve_ids = tuple(
            dict.fromkeys(match.upper() for match in CVE_PATTERN.findall(query))
        )
        if cve_ids:
            vulnerabilities = tuple(self.fetch_cve(cve_id) for cve_id in cve_ids)
        else:
            vulnerabilities = tuple(self.search(query, limit=limit, severity=severity))
        return NVDAgentResult(
            query=query,
            cve_ids=cve_ids,
            vulnerabilities=vulnerabilities,
        )
