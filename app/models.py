from typing import Literal

from pydantic import BaseModel, Field


class AttackResult(BaseModel):
    attack_id: str
    category: str
    name: str
    target: str
    payload: str
    status: Literal["success", "blocked", "failed"]
    severity: Literal["low", "medium", "high", "critical"]
    evidence: str = ""
    score: int = Field(default=0, ge=0, le=100)


class SecurityAssessment(BaseModel):
    overall_score: int
    category_scores: dict[str, int]
    findings: list[AttackResult]


class AttackRunRequest(BaseModel):
    families: list[str] | None = Field(default=None, min_length=1, max_length=10)
    user_allowed: bool = False
