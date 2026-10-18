"""Dataclasses shared across the analysis pipeline, the UI and the database."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    """A single explainable observation produced by one verification module."""

    rule_id: str
    module: str
    category: str
    severity: str
    points: int
    evidence: str
    explanation: str
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            rule_id=data["rule_id"],
            module=data["module"],
            category=data["category"],
            severity=data["severity"],
            points=int(data.get("points", 0)),
            evidence=data.get("evidence", ""),
            explanation=data.get("explanation", ""),
            confidence=data.get("confidence", "medium"),
        )


@dataclass
class AnalysisResult:
    """The complete, reproducible output of one OfferGuard analysis run."""

    analysis_id: str
    created_at: str
    score: int
    risk_category: str
    summary: str
    extracted_facts: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    module_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    score_breakdown: dict[str, dict[str, Any]] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    extraction: dict[str, Any] = field(default_factory=dict)
    source_filename: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "created_at": self.created_at,
            "score": self.score,
            "risk_category": self.risk_category,
            "summary": self.summary,
            "extracted_facts": self.extracted_facts,
            "findings": [finding.to_dict() for finding in self.findings],
            "module_results": self.module_results,
            "score_breakdown": self.score_breakdown,
            "recommendations": self.recommendations,
            "limitations": self.limitations,
            "extraction": self.extraction,
            "source_filename": self.source_filename,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnalysisResult:
        return cls(
            analysis_id=data["analysis_id"],
            created_at=data["created_at"],
            score=int(data["score"]),
            risk_category=data["risk_category"],
            summary=data.get("summary", ""),
            extracted_facts=data.get("extracted_facts", {}),
            findings=[Finding.from_dict(item) for item in data.get("findings", [])],
            module_results=data.get("module_results", {}),
            score_breakdown=data.get("score_breakdown", {}),
            recommendations=data.get("recommendations", []),
            limitations=data.get("limitations", []),
            extraction=data.get("extraction", {}),
            source_filename=data.get("source_filename"),
        )
