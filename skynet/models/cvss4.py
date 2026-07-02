"""
CVSS 4.0 漏洞评分系统
根据 FIRST CVSS v4.0 标准实现
参考：https://www.first.org/cvss/v4-0/
"""

from enum import Enum
from typing import Dict, Optional, Any
from dataclasses import dataclass


class AttackVector(Enum):
    NETWORK = ("N", 0.0, "网络")
    ADJACENT = ("A", 0.1, "相邻网络")
    LOCAL = ("L", 0.2, "本地")
    PHYSICAL = ("P", 0.3, "物理")


class AttackComplexity(Enum):
    LOW = ("L", 0.0, "低")
    HIGH = ("H", 0.1, "高")


class AttackRequirements(Enum):
    NONE = ("N", 0.0, "无")
    PRESENT = ("P", 0.1, "存在")


class PrivilegesRequired(Enum):
    NONE = ("N", 0.0, "无")
    LOW = ("L", 0.1, "低")
    HIGH = ("H", 0.2, "高")


class UserInteraction(Enum):
    NONE = ("N", 0.0, "无")
    PASSIVE = ("P", 0.1, "被动")
    ACTIVE = ("A", 0.2, "主动")


class VulnerableSystemImpact(Enum):
    HIGH = ("H", 0.0, "高")
    LOW = ("L", 0.1, "低")
    NONE = ("N", 0.2, "无")


class SubsequentSystemImpact(Enum):
    HIGH = ("H", 0.0, "高")
    LOW = ("L", 0.1, "低")
    NONE = ("N", 0.2, "无")


class SafetyImpact(Enum):
    NEGLIGIBLE = ("N", 0.0, "可忽略")
    PRESENT = ("P", 0.1, "存在")


class AutomationImpact(Enum):
    NO = ("N", 0.0, "否")
    YES = ("Y", 0.1, "是")


class RecoveryImpact(Enum):
    AUTOMATIC = ("A", 0.0, "自动")
    USER = ("U", 0.1, "用户")
    IRRECOVERABLE = ("I", 0.2, "不可恢复")


@dataclass
class CVSS4Metrics:
    attack_vector: AttackVector
    attack_complexity: AttackComplexity
    attack_requirements: AttackRequirements
    privileges_required: PrivilegesRequired
    user_interaction: UserInteraction
    vulnerable_confidentiality: VulnerableSystemImpact
    vulnerable_integrity: VulnerableSystemImpact
    vulnerable_availability: VulnerableSystemImpact
    subsequent_confidentiality: SubsequentSystemImpact
    subsequent_integrity: SubsequentSystemImpact
    subsequent_availability: SubsequentSystemImpact
    safety_impact: Optional[SafetyImpact] = None
    automation_impact: Optional[AutomationImpact] = None
    recovery_impact: Optional[RecoveryImpact] = None


class CVSS4Calculator:
    def calculate_base_score(self, metrics: CVSS4Metrics) -> float:
        exploitability = self._calculate_exploitability(metrics)
        impact = self._calculate_impact(metrics)
        if impact <= 0:
            return 0.0
        base_score = min(10.0, exploitability + impact)
        return round(base_score, 1)

    def _calculate_exploitability(self, metrics: CVSS4Metrics) -> float:
        av_values = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
        ac_values = {"L": 0.0, "H": 0.1}
        at_values = {"N": 0.0, "P": 0.1}
        pr_values = {"N": 0.0, "L": 0.1, "H": 0.2}
        ui_values = {"N": 0.0, "P": 0.1, "A": 0.2}
        av = av_values[metrics.attack_vector.value[0]]
        ac = ac_values[metrics.attack_complexity.value[0]]
        at = at_values[metrics.attack_requirements.value[0]]
        pr = pr_values[metrics.privileges_required.value[0]]
        ui = ui_values[metrics.user_interaction.value[0]]
        return 8.22 * (1 - av) * (1 - ac) * (1 - at) * (1 - pr) * (1 - ui)

    def _calculate_impact(self, metrics: CVSS4Metrics) -> float:
        impact_values = {"H": 0.0, "L": 0.1, "N": 0.2}
        vc = impact_values[metrics.vulnerable_confidentiality.value[0]]
        vi = impact_values[metrics.vulnerable_integrity.value[0]]
        va = impact_values[metrics.vulnerable_availability.value[0]]
        sc = impact_values[metrics.subsequent_confidentiality.value[0]]
        si = impact_values[metrics.subsequent_integrity.value[0]]
        sa = impact_values[metrics.subsequent_availability.value[0]]
        vulnerable_impact = 1 - ((1 - (1 - vc)) * (1 - (1 - vi)) * (1 - (1 - va)))
        subsequent_impact = 1 - ((1 - (1 - sc)) * (1 - (1 - si)) * (1 - (1 - sa)))
        if vulnerable_impact > 0 and subsequent_impact > 0:
            total_impact = max(vulnerable_impact, subsequent_impact) + 0.5 * min(vulnerable_impact, subsequent_impact)
        else:
            total_impact = max(vulnerable_impact, subsequent_impact)
        return min(6.0, total_impact * 6.0)

    def get_severity_rating(self, base_score: float) -> str:
        if base_score == 0.0:
            return "NONE"
        if base_score <= 3.9:
            return "LOW"
        if base_score <= 6.9:
            return "MEDIUM"
        if base_score <= 8.9:
            return "HIGH"
        if base_score <= 10.0:
            return "CRITICAL"
        return "UNKNOWN"

    def generate_vector_string(self, metrics: CVSS4Metrics) -> str:
        vector_parts = [
            "CVSS:4.0",
            f"AV:{metrics.attack_vector.value[0]}",
            f"AC:{metrics.attack_complexity.value[0]}",
            f"AT:{metrics.attack_requirements.value[0]}",
            f"PR:{metrics.privileges_required.value[0]}",
            f"UI:{metrics.user_interaction.value[0]}",
            f"VC:{metrics.vulnerable_confidentiality.value[0]}",
            f"VI:{metrics.vulnerable_integrity.value[0]}",
            f"VA:{metrics.vulnerable_availability.value[0]}",
            f"SC:{metrics.subsequent_confidentiality.value[0]}",
            f"SI:{metrics.subsequent_integrity.value[0]}",
            f"SA:{metrics.subsequent_availability.value[0]}",
        ]
        if metrics.safety_impact:
            vector_parts.append(f"S:{metrics.safety_impact.value[0]}")
        if metrics.automation_impact:
            vector_parts.append(f"AU:{metrics.automation_impact.value[0]}")
        if metrics.recovery_impact:
            vector_parts.append(f"R:{metrics.recovery_impact.value[0]}")
        return "/".join(vector_parts)

    def generate_detailed_assessment(self, metrics: CVSS4Metrics) -> Dict[str, Any]:
        base_score = self.calculate_base_score(metrics)
        return {
            "base_score": base_score,
            "severity": self.get_severity_rating(base_score),
            "vector_string": self.generate_vector_string(metrics),
            "cvss_version": "4.0",
        }
