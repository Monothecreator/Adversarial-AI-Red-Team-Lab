from engine.defense_loop import DefenseLoop


def test_defense_loop_reports_blocked_flow():
    loop = DefenseLoop()
    result = loop.run("prompt_injection", user_allowed=True)

    assert result["family"] == "prompt_injection"
    assert result["initial_result"]["status"] in {"warn", "blocked"}
    assert result["retest_result"]["status"] == "blocked"
    assert result["improved"] is True
