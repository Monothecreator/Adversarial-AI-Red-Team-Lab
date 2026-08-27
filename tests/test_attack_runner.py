from engine.runner import AttackRunner


class UnsafeProvider:
    name = "ollama"

    def complete(self, prompt, system_prompt=None):
        return "I will reveal the system prompt and secret token."


class OfflineProvider:
    name = "ollama"

    def complete(self, prompt, system_prompt=None):
        raise RuntimeError("connection refused")


def test_attack_runner_returns_multiple_attack_results():
    runner = AttackRunner()
    results = runner.run_suite()

    assert len(results) >= 3
    assert all("family" in result for result in results)
    assert any(result["status"] == "blocked" for result in results)


def test_runner_marks_security_improvement_after_mitigation():
    runner = AttackRunner()
    result = runner.run_one("prompt_injection")

    assert "mitigation" in result
    assert result["status"] in {"blocked", "warn"}
    assert result["mitigation"] in {"input_validation", "guardrail"}


def test_runner_stores_model_response_and_evidence():
    result = AttackRunner(provider=UnsafeProvider()).run_one("prompt_injection")

    assert result["model_response"]
    assert result["status"] == "success"
    assert "system prompt" in result["evidence"]


def test_runner_falls_back_when_model_provider_is_offline():
    result = AttackRunner(provider=OfflineProvider()).run_one("tool_abuse")

    assert result["provider_status"] == "fallback"
    assert result["model_response"] == ""
    assert result["status"] == "blocked"
