"""Stable local-analysis interface shared by the CLI and desktop UI."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .artifact_router import route_bytes, route_text
from .behavior_analyzer import enrich_regex_scan
from .decoder import decode_code
from .input_handler import InputHandler, pre_format_malware_code
from .models import ArtifactProfile, DeterministicVerdict
from .regex_scanner import RegexScanner


@dataclass(slots=True)
class AuditRequest:
    filename: str
    content: bytes | str
    source_type: str = "file"


@dataclass(slots=True)
class AuditResult:
    success: bool
    filename: str
    source_type: str
    artifact: dict[str, Any] = field(default_factory=dict)
    regex_scan: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    deterministic_verdict: dict[str, Any] = field(default_factory=dict)
    decode_confidence: str = "low"
    decode_context: str = ""
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuditEngine:
    """Runs deterministic, non-executing local analysis."""

    def audit(self, request: AuditRequest) -> AuditResult:
        profile: ArtifactProfile
        if isinstance(request.content, bytes):
            profile = route_bytes(request.filename, request.content)
            if not profile.supported:
                return AuditResult(
                    success=False,
                    filename=request.filename,
                    source_type=request.source_type,
                    artifact=profile.to_dict(),
                    deterministic_verdict=DeterministicVerdict(
                        "unsupported", 0, 0.99, profile.reason
                    ).to_dict(),
                    errors=[profile.reason],
                )
            handled = InputHandler.process_upload(request.filename, request.content)
        else:
            profile = route_text(request.filename, request.content)
            handled = InputHandler.process_paste(request.content)
            handled.filename = request.filename

        if not handled.success:
            return AuditResult(
                success=False,
                filename=request.filename,
                source_type=request.source_type,
                artifact=profile.to_dict(),
                warnings=list(handled.warnings),
                errors=list(handled.errors),
            )

        clean_code = pre_format_malware_code(
            handled.code_content,
            filename=handled.filename,
        )
        profile = route_text(handled.filename, clean_code)
        base_scan = RegexScanner.scan_to_dict(clean_code, filename=handled.filename)
        regex_scan, findings, assessment = enrich_regex_scan(clean_code, profile, base_scan)
        decoded = decode_code(clean_code)

        return AuditResult(
            success=True,
            filename=handled.filename,
            source_type=request.source_type,
            artifact=profile.to_dict(),
            regex_scan=regex_scan,
            findings=[item.to_dict() for item in findings],
            deterministic_verdict=assessment.to_dict(),
            decode_confidence=decoded.confidence,
            decode_context=decoded.to_prompt_context(),
            # 输入处理告警 + 正则引擎告警（如超长行触发回溯超时后的分窗降级）
            warnings=list(handled.warnings) + list(regex_scan.get("warnings", [])),
        )

    def audit_path(self, path: str | Path) -> AuditResult:
        target = Path(path)
        return self.audit(
            AuditRequest(
                filename=target.name,
                content=target.read_bytes(),
                source_type="file",
            )
        )

