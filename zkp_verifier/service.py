"""Run verification and persist the outcome without storing the inputs."""

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from .audit import AuditLog
from .config import MAX_BATCH_SIZE
from .core.verify_logic import Verdict, VerificationInput, verify


@dataclass(frozen=True)
class CheckResult:
    position: int
    accepted: bool
    verdict: Verdict


@dataclass(frozen=True)
class RunResult:
    run_id: str
    checked_at_utc: str
    results: list[CheckResult]


def verify_batch(audit: AuditLog, source: str, items: list[VerificationInput]) -> RunResult:
    if not 1 <= len(items) <= MAX_BATCH_SIZE:
        raise ValueError(f"A run must contain 1 to {MAX_BATCH_SIZE} checks.")

    verdicts = [verify(item) for item in items]
    run_id = uuid4().hex
    checked_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    audit.append(run_id, checked_at, source, verdicts)
    return RunResult(run_id, checked_at, [
        CheckResult(position, verdict is Verdict.VERIFIED, verdict)
        for position, verdict in enumerate(verdicts, 1)
    ])
