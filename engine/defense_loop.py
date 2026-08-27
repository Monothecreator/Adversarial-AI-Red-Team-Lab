from attacks.registry import AttackCatalog
from defenses.controls import SecurityControls


class DefenseLoop:
    """Implements the attack -> detect -> defend -> retest loop."""

    def __init__(self):
        self.catalog = AttackCatalog()
        self.controls = SecurityControls()

    def run(self, family: str, user_allowed: bool = False):
        scenario = self.catalog.get(family)
        initial = self.controls.evaluate(scenario, user_allowed=user_allowed)
        retest = self.controls.evaluate(scenario, user_allowed=False)
        return {
            "attack": scenario.name,
            "family": scenario.family,
            "initial_result": initial,
            "retest_result": retest,
            "improved": initial["status"] != retest["status"] or initial["defense"] != retest["defense"],
        }
