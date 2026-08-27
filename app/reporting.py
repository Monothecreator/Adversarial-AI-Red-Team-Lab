from __future__ import annotations

from typing import Any


def build_security_report() -> dict[str, Any]:
    return {
        "service": "Adversarial AI Red-Team Lab",
        "summary": "AI security assessment completed with focused coverage across prompt injection, tool misuse, and retrieval poisoning.",
        "high_risk_areas": [
            "Prompt injection",
            "Indirect prompt injection",
            "RAG poisoning",
            "Unauthorized tool execution",
        ],
        "overall_score": 86,
        "category_scores": {
            "prompt_injection": 82,
            "data_leakage": 94,
            "rag_poisoning": 76,
            "tool_abuse": 88,
            "jailbreak_resistance": 91,
        },
    }
