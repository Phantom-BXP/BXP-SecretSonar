from enum import IntEnum
from bxp_secretsonar.core.models import Validated, ValidationResult

class AutonomyLevel(IntEnum):
    MANUAL = 0
    DISCOVERY_AUTO = 1
    LOW_IMPACT_AUTO = 2
    SAFE_EXPLOIT_AUTO = 3
    ROLLBACK_AUTO = 4
    FULL_AUTO = 5

class DecisionEngine:
    """Moteur de décision pour l'autonomie graduée (0=manuel, 5=full auto)."""
    def __init__(self, level: AutonomyLevel = AutonomyLevel.MANUAL):
        self.level = level
        self.action_log = []

    async def decide(self, validated: Validated) -> str:
        """Retourne 'EXECUTE', 'WAIT', ou 'SKIP'."""
        if self.level == AutonomyLevel.MANUAL:
            return "WAIT"

        if validated.result != ValidationResult.CONFIRMED:
            return "SKIP"
        if validated.risk_score and validated.risk_score.composite_score >= 0.7:
            return "SKIP"  # honeypot probable

        impact = validated.impact_score.impact_level.value if validated.impact_score else "low"

        if self.level >= AutonomyLevel.FULL_AUTO:
            return "EXECUTE"

        if self.level >= AutonomyLevel.ROLLBACK_AUTO:
            # Exécuter seulement les actions réversibles (read-only)
            reversible = validated.candidate.evidence.pattern_name in ("generic_api_key", "bearer_token", "stripe_key")
            return "EXECUTE" if reversible else "WAIT"

        if self.level >= AutonomyLevel.SAFE_EXPLOIT_AUTO:
            return "EXECUTE" if impact in ("low", "medium") else "WAIT"

        if self.level >= AutonomyLevel.LOW_IMPACT_AUTO:
            return "EXECUTE" if impact == "low" else "WAIT"

        return "WAIT"

    def set_level(self, level: AutonomyLevel):
        self.level = level

    def log_action(self, action: str, detail: str):
        self.action_log.append({"action": action, "detail": detail})
