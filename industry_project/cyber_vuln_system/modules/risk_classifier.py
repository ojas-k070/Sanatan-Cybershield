"""
Module 3: Risk Classification System
--------------------------------------
Aggregates all vulnerability findings and produces a structured
risk profile for the entire scanned file.

Responsibilities:
  - Count vulnerabilities by severity
  - Compute a weighted CVSS-inspired risk score
  - Assign an overall risk level
  - Prioritise findings for the report
  - Generate severity badges and colour codes
"""

from dataclasses import dataclass, field
from collections import Counter
from typing import Optional

from modules.ai_analyzer import AnalyzedVulnerability, AIAnalysisResult


# ─────────────────────────────────────────────
#  Severity weights (used for risk scoring)
# ─────────────────────────────────────────────

SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High":     7,
    "Medium":   4,
    "Low":      1,
}

SEVERITY_COLORS = {
    "Critical": "#FF1744",   # red
    "High":     "#FF6D00",   # deep orange
    "Medium":   "#FFD600",   # amber
    "Low":      "#00C853",   # green
}

SEVERITY_EMOJI = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🟢",
}


# ─────────────────────────────────────────────
#  Data structures
# ─────────────────────────────────────────────

@dataclass
class SeverityBreakdown:
    critical: int = 0
    high:     int = 0
    medium:   int = 0
    low:      int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low

    def as_dict(self) -> dict:
        return {
            "Critical": self.critical,
            "High":     self.high,
            "Medium":   self.medium,
            "Low":      self.low,
        }


@dataclass
class RiskProfile:
    """Complete risk assessment for a scanned file."""
    file_path: str
    language: str

    # Counts
    severity_breakdown: SeverityBreakdown
    category_breakdown: dict[str, int]          # {"SQL Injection": 3, ...}
    owasp_breakdown: dict[str, int]             # {"A03:2021": 2, ...}

    # Scoring
    risk_score: int                              # 0–100
    risk_level: str                              # Critical / High / Medium / Low
    risk_trend: str                              # "🔴 Urgent Action Required" etc.

    # Prioritised lists
    critical_findings: list[AnalyzedVulnerability]
    high_findings:     list[AnalyzedVulnerability]
    medium_findings:   list[AnalyzedVulnerability]
    low_findings:      list[AnalyzedVulnerability]
    all_findings:      list[AnalyzedVulnerability]

    # Metadata
    executive_summary: str
    top_priority_fixes: list[str]
    secure_code: str

    # Helpers
    severity_colors: dict[str, str] = field(
        default_factory=lambda: SEVERITY_COLORS.copy()
    )
    severity_emoji: dict[str, str] = field(
        default_factory=lambda: SEVERITY_EMOJI.copy()
    )


# ─────────────────────────────────────────────
#  Classifier class
# ─────────────────────────────────────────────

class RiskClassifier:
    """
    Consumes an AIAnalysisResult and produces a RiskProfile.

    Scoring algorithm:
      raw_score = Σ (weight[severity] × count[severity])
      capped at 100, then normalised with a logarithmic scale
      so that a single Critical finding is already ~40/100.
    """

    # ── public API ──────────────────────────────

    def classify(
        self, ai_result: AIAnalysisResult, file_path: str, language: str
    ) -> RiskProfile:
        all_findings = (
            ai_result.analyzed_vulnerabilities + ai_result.additional_findings
        )

        # Filter out high-confidence false positives
        confirmed = [
            v for v in all_findings
            if v.false_positive_likelihood != "HIGH"
        ]

        breakdown = self._count_severities(confirmed)
        category_breakdown = self._count_categories(confirmed)
        owasp_breakdown = self._count_owasp(confirmed)
        risk_score = self._compute_score(breakdown)
        risk_level = self._score_to_level(risk_score)
        risk_trend = self._risk_trend(risk_level)

        return RiskProfile(
            file_path=file_path,
            language=language,
            severity_breakdown=breakdown,
            category_breakdown=category_breakdown,
            owasp_breakdown=owasp_breakdown,
            risk_score=risk_score,
            risk_level=risk_level,
            risk_trend=risk_trend,
            critical_findings=[v for v in confirmed if v.severity == "Critical"],
            high_findings=[v for v in confirmed if v.severity == "High"],
            medium_findings=[v for v in confirmed if v.severity == "Medium"],
            low_findings=[v for v in confirmed if v.severity == "Low"],
            all_findings=confirmed,
            executive_summary=ai_result.executive_summary,
            top_priority_fixes=ai_result.top_priority_fixes,
            secure_code=ai_result.secure_code,
        )

    # ── internal helpers ─────────────────────────

    def _count_severities(self, findings: list[AnalyzedVulnerability]) -> SeverityBreakdown:
        bd = SeverityBreakdown()
        for v in findings:
            s = v.severity
            if s == "Critical":  bd.critical += 1
            elif s == "High":    bd.high     += 1
            elif s == "Medium":  bd.medium   += 1
            elif s == "Low":     bd.low      += 1
        return bd

    def _count_categories(self, findings: list[AnalyzedVulnerability]) -> dict[str, int]:
        return dict(Counter(v.category for v in findings))

    def _count_owasp(self, findings: list[AnalyzedVulnerability]) -> dict[str, int]:
        # Extract just the "AXX:2021" prefix
        cats = []
        for v in findings:
            owasp = v.owasp_category
            prefix = owasp.split(" - ")[0] if " - " in owasp else owasp
            cats.append(prefix)
        return dict(Counter(cats))

    def _compute_score(self, bd: SeverityBreakdown) -> int:
        """
        Weighted additive score capped at 100.
        Formula inspired by CVSS environmental scoring:
          score = min(100, Σ weight_i × count_i × decay_factor)
        Decay ensures that 50 low findings ≠ 1 critical finding.
        """
        import math
        raw = (
            bd.critical * SEVERITY_WEIGHTS["Critical"]
            + bd.high    * SEVERITY_WEIGHTS["High"]
            + bd.medium  * SEVERITY_WEIGHTS["Medium"]
            + bd.low     * SEVERITY_WEIGHTS["Low"]
        )
        if raw == 0:
            return 0
        # Logarithmic normalisation so single Critical → ~40, many → 100
        score = int(min(100, 20 * math.log1p(raw)))
        # Guarantee Critical findings always push score above 60
        if bd.critical > 0:
            score = max(score, 60 + min(40, bd.critical * 5))
        return min(score, 100)

    def _score_to_level(self, score: int) -> str:
        if score >= 75: return "Critical"
        if score >= 50: return "High"
        if score >= 25: return "Medium"
        return "Low"

    def _risk_trend(self, level: str) -> str:
        return {
            "Critical": "🔴 Urgent Action Required — Exploitable vulnerabilities present",
            "High":     "🟠 Action Required — Significant security weaknesses detected",
            "Medium":   "🟡 Review Recommended — Moderate risk requiring attention",
            "Low":      "🟢 Low Risk — Minor issues detected; best-practice hardening advised",
        }.get(level, "")