from app.models import AttackResult


class AttackOrchestrator:
    """Basic orchestrator for running controlled attack scenarios."""

    def __init__(self):
        self.tests: list[AttackResult] = []

    def run_attack(
        self,
        attack_id: str,
        category: str,
        name: str,
        target: str,
        payload: str,
        status: str,
        severity: str,
        evidence: str = "",
        score: int = 0,
    ) -> AttackResult:
        result = AttackResult(
            attack_id=attack_id,
            category=category,
            name=name,
            target=target,
            payload=payload,
            status=status,
            severity=severity,
            evidence=evidence,
            score=score,
        )
        self.tests.append(result)
        return result

    def list_results(self) -> list[AttackResult]:
        return list(self.tests)
