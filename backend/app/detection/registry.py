"""RuleRegistry (M3).

Distinguishes:
- rule name  -> semantic/configured rule instance (e.g., BruteForceLogin)
- rule_type  -> fixed Python implementation class mapping (threshold -> BruteForceLoginRule)

No generic DSL.
"""

from typing import Optional

from app.detection.base import BaseRule


class RuleRegistry:
    """Registry for detection rule classes and instances."""

    def __init__(self):
        self._type_map: dict[str, type[BaseRule]] = {}
        self._instances: dict[str, BaseRule] = {}

    # ---- class registration (rule_type -> class) ----

    def register_class(self, rule_type: str, rule_class: type[BaseRule]) -> None:
        self._type_map[rule_type] = rule_class

    def get_class(self, rule_type: str) -> Optional[type[BaseRule]]:
        return self._type_map.get(rule_type)

    # ---- instance registration (name -> instance) ----

    def register_instance(self, name: str, rule: BaseRule) -> None:
        self._instances[name] = rule

    def get(self, name: str) -> Optional[BaseRule]:
        return self._instances.get(name)

    def get_all(self) -> list[BaseRule]:
        return list(self._instances.values())

    def get_all_names(self) -> list[str]:
        return list(self._instances.keys())

    def clear_instances(self) -> None:
        self._instances.clear()

    def clear_all(self) -> None:
        self._instances.clear()
        self._type_map.clear()


# Global singleton (populated at startup)
rule_registry = RuleRegistry()
