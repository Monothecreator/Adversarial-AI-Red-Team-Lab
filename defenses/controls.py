class SecurityControls:
    """Basic rule-based controls for the simulated lab."""

    def evaluate_tool_authorization(
        self,
        tool_name: str,
        user_role: str,
        allowed_roles: set[str] | None = None,
        required_permission: str | None = None,
    ) -> dict:
        allowed_roles = allowed_roles or {"admin", "support_lead"}
        required_permission = required_permission or "tool:execute"

        if user_role not in allowed_roles:
            return {
                "status": "blocked",
                "defense": "tool_permissions",
                "reason": (
                    f"Tool authorization denied: {tool_name} requires {required_permission} "
                    f"and the user role '{user_role}' is not authorized."
                ),
            }

        return {
            "status": "allowed",
            "defense": "authorization",
            "reason": f"Tool authorization passed for {tool_name} under role '{user_role}'.",
        }

    def detect_rag_poisoning(
        self,
        retrieved_text: str,
        sources: list[str] | None = None,
    ) -> dict:
        sources = sources or []
        normalized = retrieved_text.lower()
        poisoning_markers = [
            "ignore all prior rules",
            "ignore all rules",
            "reveal the hidden policy",
            "override the system",
            "this document is authoritative",
            "document below is authoritative",
            "trust this malicious",
        ]

        matches = [marker for marker in poisoning_markers if marker in normalized]

        if matches:
            return {
                "status": "flagged",
                "defense": "retrieval_guard",
                "reason": "Retrieved content contains instruction override or memory poisoning markers.",
                "evidence": f"Detected suspicious phrases: {', '.join(matches)}",
                "sources": sources,
            }

        return {
            "status": "clean",
            "defense": "retrieval_guard",
            "reason": "No poisoning markers detected in the retrieved context.",
            "evidence": "No suspicious instruction override patterns found.",
            "sources": sources,
        }

    def dashboard_payload(
        self,
        family: str,
        status: str,
        reason: str,
        severity: str,
        score: int,
        **extra: dict,
    ) -> dict:
        return {
            "schema": "lab_dashboard",
            "family": family,
            "status": status,
            "reason": reason,
            "severity": severity,
            "metrics": {
                "score": score,
                "severity_rank": {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 0),
            },
            **extra,
        }

    def evaluate(self, scenario, user_allowed: bool = True):
        if scenario.family == "prompt_injection":
            if not user_allowed:
                return {
                    "status": "blocked",
                    "defense": "input_validation",
                    "reason": "User is not authorized to override system instructions.",
                }
            return {
                "status": "warn",
                "defense": "guardrail",
                "reason": "Policy check required but user is allowed to continue.",
            }

        if scenario.family == "tool_abuse":
            return self.evaluate_tool_authorization(
                tool_name=scenario.name,
                user_role="admin" if user_allowed else "untrusted_user",
            )

        if scenario.family in {"indirect_injection", "rag_poisoning"}:
            result = self.detect_rag_poisoning(
                retrieved_text=scenario.payload,
                sources=[scenario.family],
            )
            if result["status"] == "flagged":
                return result

        return {
            "status": "passed",
            "defense": "baseline",
            "reason": "No defense trigger for this scenario.",
        }
