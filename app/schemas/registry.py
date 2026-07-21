"""Principal and Agent (agent-registry) boundary models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import AutonomyLevel


class PrincipalOut(BaseModel):
    """A delegating human/organization. Demo identities are synthetic and labeled."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    display_name: str
    demo_identity_type: str = "SYNTHETIC"
    notice: str | None = None


class AgentModelMeta(BaseModel):
    provider: str
    name: str
    version: str


class AgentOut(BaseModel):
    """Agent registry record (mirrors schemas/agent-registry.schema.json)."""

    model_config = ConfigDict(from_attributes=True)

    agent_id: str = Field(validation_alias="id", serialization_alias="agent_id")
    name: str
    owner_institution: str
    role: str
    autonomy_level: AutonomyLevel
    model: AgentModelMeta
    allowed_tools: list[str]
    status: str
    kill_switch_owner: str
    jurisdiction_tags: list[str] = Field(default_factory=list)


class AgentRegistryRecord(BaseModel):
    """Inbound agent-registry record shape (matches the JSON Schema field names exactly)."""

    agent_id: str
    name: str
    owner_institution: str
    role: str
    autonomy_level: AutonomyLevel
    model: dict[str, Any]
    allowed_tools: list[str]
    status: str
    kill_switch_owner: str
    jurisdiction_tags: list[str] = Field(default_factory=list)
