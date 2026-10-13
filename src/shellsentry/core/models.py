"""Shared evidence and verdict models for deterministic and model-assisted analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


VerdictName = Literal["malicious", "suspicious", "no_indication", "benign", "unknown", "unsupported"]


@dataclass(slots=True)
class ArtifactProfile:
    kind: str
    language: str
    confidence: float
    supported: bool
    is_binary: bool = False
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Evidence:
    source: str
    rule_id: str
    category: str
    severity: str
    confidence: float
    description: str
    line_start: int = 0
    line_end: int = 0
    snippet: str = ""
    taint: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    finding_id: str
    title: str
    category: str
    severity: str
    confidence: float
    artifact_type: str
    description: str
    evidence: list[Evidence] = field(default_factory=list)
    behavior_chain: list[str] = field(default_factory=list)
    false_positive_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AgentVerdict:
    verdict: VerdictName = "unknown"
    confidence: float = 0.0
    artifact_type: str = "unknown"
    summary: str = ""
    behavior_chain: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    counter_evidence: list[str] = field(default_factory=list)
    uncertainties: list[str] = field(default_factory=list)
    model_reviewed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DeterministicVerdict:
    verdict: VerdictName
    risk_score: int
    confidence: float
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def clamp_confidence(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def fuse_verdicts(
    deterministic: DeterministicVerdict,
    agent: AgentVerdict | None,
) -> AgentVerdict:
    """Fuse reproducible evidence with the model review without hiding disagreement."""
    if agent is None or not agent.model_reviewed:
        return AgentVerdict(
            verdict=deterministic.verdict,
            confidence=deterministic.confidence,
            summary=deterministic.reason,
        )

    # 模型认为"清白/无迹象/无法判定"的取值集合
    model_clear = {"benign", "no_indication", "unknown", "unsupported"}
    severe_static = deterministic.verdict == "malicious" and deterministic.confidence >= 0.85
    strong_agent = agent.verdict == "malicious" and agent.confidence >= 0.82 and bool(agent.evidence)

    if severe_static and agent.verdict in {"benign", "no_indication"}:
        agent.verdict = "suspicious"
        agent.confidence = max(0.72, agent.confidence)
        agent.uncertainties.append("模型结论与高置信静态证据冲突，已降级为需人工复核")
    elif strong_agent and deterministic.verdict in {"no_indication", "unknown"}:
        agent.verdict = "malicious"
        agent.uncertainties.append("结论主要来自语义分析，缺少确定性规则佐证")
    elif deterministic.verdict == "malicious" and agent.verdict == "suspicious":
        agent.verdict = "malicious"
        agent.confidence = max(agent.confidence, deterministic.confidence)
    elif deterministic.verdict in {"malicious", "suspicious"} and agent.verdict in model_clear:
        # P1-3：对称降级分支。
        # 原实现只覆盖"静态恶意且置信 ≥0.85"一种情形，静态为 suspicious、
        # 或恶意但置信度未达 0.85 时，模型判 benign 会让静态证据被完全丢弃。
        # 此处统一保留确定性证据并降级为 suspicious，交由人工复核。
        original = agent.verdict
        floor = 0.72 if deterministic.verdict == "malicious" else 0.60
        agent.verdict = "suspicious"
        agent.confidence = max(floor, agent.confidence)
        agent.evidence.append(
            f"[确定性静态证据·风险分 {deterministic.risk_score}] {deterministic.reason}"
        )
        agent.uncertainties.append(
            f"模型判定为 {original}，但静态层结论为 {deterministic.verdict}；"
            f"已保留确定性证据并将结论降级为 suspicious，需人工复核"
        )

    return agent

