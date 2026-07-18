from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, computed_field


class ArtifactType(str, Enum):
    HTTP_RESPONSE = "http_response"
    FILE_CONTENT = "file_content"
    RAW_TEXT = "raw_text"


class Artifact(BaseModel):
    id: str = Field(default_factory=lambda: hashlib.sha256(b"").hexdigest()[:16])
    source_url: str
    content: str
    artifact_type: ArtifactType
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict = Field(default_factory=dict)

    @computed_field
    def content_hash(self) -> str:
        return hashlib.sha256(self.content.encode()).hexdigest()[:16]


class Evidence(BaseModel):
    artifact_id: str
    pattern_name: str
    matched_value: str
    context_before: str = ""
    context_after: str = ""
    entropy_score: float = 0.0
    source_url: str = ""
    metadata: dict = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Candidate(BaseModel):
    evidence: Evidence
    confidence_score: float = Field(ge=0.0, le=1.0)
    priority: int = Field(default=5, ge=1, le=10)

    @computed_field
    def candidate_id(self) -> str:
        raw = f"{self.evidence.artifact_id}:{self.evidence.pattern_name}:{self.evidence.matched_value}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class ValidationResult(str, Enum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    UNKNOWN = "unknown"
    ERROR = "error"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskScore(BaseModel):
    target_url: str
    passive_signals: list[str] = Field(default_factory=list)
    active_signals: list[str] = Field(default_factory=list)
    composite_score: float = Field(ge=0.0, le=1.0, default=0.0)
    risk_level: RiskLevel = RiskLevel.LOW
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @computed_field
    def is_suspicious(self) -> bool:
        return self.composite_score >= 0.6


class Validated(BaseModel):
    candidate: Candidate
    result: ValidationResult
    proof: Optional[str] = None
    validated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    validator_name: str = ""
    risk_score: Optional[RiskScore] = None
    impact_score: Optional[ImpactScore] = None

    @computed_field
    def is_confirmed(self) -> bool:
        return self.result == ValidationResult.CONFIRMED


class ProtocolProbeStatus(str, Enum):
    AUTH_ACCEPTED = "auth_accepted"
    AUTH_REJECTED = "auth_rejected"
    HANDSHAKE_OK = "handshake_ok"
    TIMEOUT = "timeout"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


class ProtocolProbeResult(BaseModel):
    """Résultat d'une vérification protocolaire bénigne (sans exécution)."""
    protocol: str
    status: ProtocolProbeStatus
    banner: Optional[str] = None
    latency_ms: float = 0.0
    details: Optional[str] = None


class BlastRadiusItem(BaseModel):
    """Ressource ou service identifié dans le contexte du secret."""
    resource_type: str  # api_endpoint, s3_bucket, git_repo, db_connection, etc.
    identifier: str
    confidence: float = Field(ge=0.0, le=1.0)


class ImpactScore(BaseModel):
    """Score d'impact basé sur le type de secret, la validation protocolaire et le blast radius."""
    secret_type: str
    protocol_probe: Optional[ProtocolProbeResult] = None
    blast_radius: list[BlastRadiusItem] = Field(default_factory=list)
    impact_level: RiskLevel = RiskLevel.LOW
    composite_score: float = Field(ge=0.0, le=1.0, default=0.0)
    reasoning: str = ""
    assessed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
