from typing import Any, Literal
from pydantic import BaseModel, Field, HttpUrl


class EntityInput(BaseModel):
    id: str = Field(min_length=1, max_length=160)
    type: str = Field(min_length=1, max_length=80)
    label: str = Field(min_length=1, max_length=300)
    properties: dict[str, Any] = Field(default_factory=dict)
    source_url: str | None = None
    confidence: float = Field(default=0.7, ge=0, le=1)
    verified: bool = False


class RelationshipInput(BaseModel):
    source: str
    target: str
    type: str = Field(min_length=1, max_length=100)
    properties: dict[str, Any] = Field(default_factory=dict)
    source_url: str | None = None
    confidence: float = Field(default=0.7, ge=0, le=1)
    verified: bool = False


class IngestRequest(BaseModel):
    source: str = Field(min_length=1, max_length=300)
    entities: list[EntityInput] = Field(default_factory=list, max_length=500)
    relationships: list[RelationshipInput] = Field(default_factory=list, max_length=1000)


class InvestigationRequest(BaseModel):
    query: str = Field(min_length=3, max_length=2000)
    entity_ids: list[str] = Field(default_factory=list, max_length=50)
    max_hops: int = Field(default=2, ge=1, le=3)
    include_unverified: bool = False


class FeedbackRequest(BaseModel):
    investigation_id: str
    verdict: Literal["correct", "incorrect", "partially_correct", "needs_review"]
    notes: str = Field(default="", max_length=4000)
