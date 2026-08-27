from app.models import AttackResult, SecurityAssessment


class RiskEngine:
    """Compute a simple security score based on successful attacks."""

    @staticmethod
    def score_attack(result: AttackResult) -> int:
        weights = {
            "low": 15,
            "medium": 35,
            "high": 60,
            "critical": 85,
        }
        if result.status == "blocked":
            return 100 - min(weights[result.severity], 80)
        if result.status == "failed":
            return 10
        return max(0, min(100, weights[result.severity] + result.score // 2))

    @staticmethod
    def assess(findings: list[AttackResult]) -> SecurityAssessment:
        category_scores: dict[str, int] = {}
        for result in findings:
            category_scores.setdefault(result.category, 0)
            category_scores[result.category] = max(
                category_scores[result.category],
                RiskEngine.score_attack(result),
            )

        if not findings:
            overall_score = 100
        else:
            overall_score = round(
                sum(RiskEngine.score_attack(result) for result in findings)
                / len(findings)
            )

        return SecurityAssessment(
            overall_score=overall_score,
            category_scores=category_scores,
            findings=findings,
        )
