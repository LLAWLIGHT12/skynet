"""为 merged findings 填充 CVSS 4.0 分数。"""

from __future__ import annotations

from typing import Optional

from skynet.merge.models import UnifiedFinding
from skynet.models.cvss4 import (
    AttackComplexity,
    AttackRequirements,
    AttackVector,
    CVSS4Calculator,
    CVSS4Metrics,
    PrivilegesRequired,
    SubsequentSystemImpact,
    UserInteraction,
    VulnerableSystemImpact,
)

_HIGH_SEVERITIES = frozenset({"critical", "high"})

_CWE_METRICS: dict[str, CVSS4Metrics] = {
    "CWE-89": CVSS4Metrics(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        attack_requirements=AttackRequirements.NONE,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        vulnerable_confidentiality=VulnerableSystemImpact.HIGH,
        vulnerable_integrity=VulnerableSystemImpact.HIGH,
        vulnerable_availability=VulnerableSystemImpact.NONE,
        subsequent_confidentiality=SubsequentSystemImpact.NONE,
        subsequent_integrity=SubsequentSystemImpact.NONE,
        subsequent_availability=SubsequentSystemImpact.NONE,
    ),
    "CWE-78": CVSS4Metrics(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        attack_requirements=AttackRequirements.NONE,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        vulnerable_confidentiality=VulnerableSystemImpact.HIGH,
        vulnerable_integrity=VulnerableSystemImpact.HIGH,
        vulnerable_availability=VulnerableSystemImpact.HIGH,
        subsequent_confidentiality=SubsequentSystemImpact.NONE,
        subsequent_integrity=SubsequentSystemImpact.NONE,
        subsequent_availability=SubsequentSystemImpact.NONE,
    ),
    "CWE-79": CVSS4Metrics(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        attack_requirements=AttackRequirements.NONE,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.ACTIVE,
        vulnerable_confidentiality=VulnerableSystemImpact.LOW,
        vulnerable_integrity=VulnerableSystemImpact.LOW,
        vulnerable_availability=VulnerableSystemImpact.NONE,
        subsequent_confidentiality=SubsequentSystemImpact.NONE,
        subsequent_integrity=SubsequentSystemImpact.NONE,
        subsequent_availability=SubsequentSystemImpact.NONE,
    ),
    "CWE-22": CVSS4Metrics(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        attack_requirements=AttackRequirements.NONE,
        privileges_required=PrivilegesRequired.LOW,
        user_interaction=UserInteraction.NONE,
        vulnerable_confidentiality=VulnerableSystemImpact.HIGH,
        vulnerable_integrity=VulnerableSystemImpact.LOW,
        vulnerable_availability=VulnerableSystemImpact.NONE,
        subsequent_confidentiality=SubsequentSystemImpact.NONE,
        subsequent_integrity=SubsequentSystemImpact.NONE,
        subsequent_availability=SubsequentSystemImpact.NONE,
    ),
}

_VTYPE_KEYWORDS: list[tuple[tuple[str, ...], str]] = [
    (("sql", "sqli"), "CWE-89"),
    (("command", "shell", "os command"), "CWE-78"),
    (("xss", "cross-site"), "CWE-79"),
    (("path traversal", "directory traversal"), "CWE-22"),
]

_calculator = CVSS4Calculator()


def _normalize_cwe(cwe_id: Optional[str]) -> str:
    if not cwe_id:
        return ""
    cwe = cwe_id.upper().strip()
    if cwe.isdigit():
        return f"CWE-{cwe}"
    if not cwe.startswith("CWE-"):
        return f"CWE-{cwe}"
    return cwe


def _infer_cwe_key(finding: UnifiedFinding) -> str:
    cwe = _normalize_cwe(finding.cwe_id)
    if cwe in _CWE_METRICS:
        return cwe
    text = f"{finding.vulnerability_type} {finding.title} {finding.description}".lower()
    for keywords, key in _VTYPE_KEYWORDS:
        if any(kw in text for kw in keywords):
            return key
    return ""


def metrics_for_finding(finding: UnifiedFinding) -> Optional[CVSS4Metrics]:
    key = _infer_cwe_key(finding)
    if key:
        return _CWE_METRICS.get(key)
    return None


def enrich_finding(finding: UnifiedFinding) -> UnifiedFinding:
    """为 high/critical 发现附加 cvss_score / cvss_vector。"""
    if finding.severity.lower() not in _HIGH_SEVERITIES:
        return finding
    metrics = metrics_for_finding(finding)
    if metrics is None:
        return finding
    assessment = _calculator.generate_detailed_assessment(metrics)
    finding.cvss_score = float(assessment["base_score"])
    finding.cvss_vector = str(assessment["vector_string"])
    if not finding.cwe_id and _infer_cwe_key(finding):
        finding.cwe_id = _infer_cwe_key(finding)
    return finding


def enrich_findings(findings: list[UnifiedFinding]) -> list[UnifiedFinding]:
    return [enrich_finding(f) for f in findings]
