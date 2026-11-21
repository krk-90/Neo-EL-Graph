"""Strict Pydantic input models for MCP network tools."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


def _validated_ports(values: object, allow_empty: bool) -> list[int]:
    if not isinstance(values, (list, tuple)):
        raise ValueError("Ports must be a list.")
    if not values and allow_empty:
        return []
    from agent.network.security import validate_port_list

    return validate_port_list(values)


class AuthorizedTargetInput(BaseModel):
    authorized_targets: list[str] = Field(min_length=1, max_length=32)

    @field_validator("authorized_targets")
    @classmethod
    def no_blank_targets(cls, values: list[str]) -> list[str]:
        if any(not isinstance(value, str) or not value.strip() for value in values):
            raise ValueError("Authorized targets must be non-empty strings.")
        return values


class DiscoveryInput(AuthorizedTargetInput):
    target_range: str
    ports: list[int] = Field(default_factory=list, max_length=64)

    @field_validator("target_range")
    @classmethod
    def validate_range(cls, value: str) -> str:
        from agent.network.security import validate_ip_or_cidr

        return validate_ip_or_cidr(value)

    @field_validator("ports", mode="before")
    @classmethod
    def validate_ports(cls, values: object) -> list[int]:
        return _validated_ports(values, allow_empty=True)


class DNSLookupInput(AuthorizedTargetInput):
    hostname: str


class HostInput(AuthorizedTargetInput):
    host: str


class TCPCheckInput(HostInput):
    port: int = Field(ge=1, le=65535, strict=True)

class PortCheckInput(HostInput):
    ports: list[int] = Field(min_length=1, max_length=64, strict=True)

    @field_validator("ports", mode="before")
    @classmethod
    def validate_ports(cls, values: object) -> list[int]:
        return _validated_ports(values, allow_empty=False)


class TLSInspectInput(HostInput):
    port: int = Field(default=443, ge=1, le=65535, strict=True)


class NetworkDiagnoseInput(HostInput):
    include_traceroute: bool = True


class CVELookupInput(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    limit: int = Field(default=10, ge=1, le=200, strict=True)
    severity: str | None = Field(default=None)

    @field_validator("query")
    @classmethod
    def non_blank_query(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Query must not be blank.")
        return value

    @field_validator("severity")
    @classmethod
    def valid_severity(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().upper()
        if value not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("Severity must be LOW, MEDIUM, HIGH, or CRITICAL.")
        return value


class RAGSearchInput(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    limit: int = Field(default=5, ge=1, le=20, strict=True)
    severity: str | None = Field(default=None)

    @field_validator("query")
    @classmethod
    def non_blank_query(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Query must not be blank.")
        return value

    @field_validator("severity")
    @classmethod
    def valid_severity(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().upper()
        if value not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("Severity must be LOW, MEDIUM, HIGH, or CRITICAL.")
        return value


class SecurityAssessmentInput(AuthorizedTargetInput):
    request: str = Field(min_length=1, max_length=2000)
    target: str | None = None
    target_range: str | None = None
    ports: list[int] = Field(default_factory=list, max_length=64, strict=True)
    keywords: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("request")
    @classmethod
    def non_blank_request(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Request must not be blank.")
        return value

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str | None) -> str | None:
        if value is not None and "/" in value:
            raise ValueError("Target must be a single host, not a CIDR range.")
        return value

    @field_validator("target_range")
    @classmethod
    def validate_target_range(cls, value: str | None) -> str | None:
        if value is None:
            return None
        from agent.network.security import validate_ip_or_cidr

        return validate_ip_or_cidr(value)

    @field_validator("ports", mode="before")
    @classmethod
    def validate_ports(cls, values: object) -> list[int]:
        return _validated_ports(values, allow_empty=True)

    @field_validator("keywords")
    @classmethod
    def non_blank_keywords(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("Keywords must not be blank.")
        return [value.strip() for value in values]
