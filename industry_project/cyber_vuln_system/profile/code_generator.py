"""
Module 4: Secure Code Generator (Auto-Remediation)
----------------------------------------------------
Takes the AI-generated secure code from the analysis phase,
validates it, and writes it to disk with a clear diff summary.

The actual code transformation is driven by Claude (in ai_analyzer.py);
this module handles:
  - Saving the secure file
  - Generating a human-readable diff
  - Providing a per-vulnerability change log
"""

import difflib
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from modules.risk_classifier import RiskProfile


# ─────────────────────────────────────────────
#  Data structures
# ─────────────────────────────────────────────

@dataclass
class RemediationResult:
    """Output of the secure code generation step."""
    original_file: str
    secure_file: str
    diff_text: str            # Unified diff string
    changes_summary: list[str]   # Human-readable change descriptions
    line_count_original: int
    line_count_secure: int
    generated_at: str


# ─────────────────────────────────────────────
#  Generator class
# ─────────────────────────────────────────────

class SecureCodeGenerator:
    """
    Persists the AI-remediated source code and produces a diff.

    How it works:
    1. Receive the secure_code string from the RiskProfile.
    2. Build an output path (same dir, _secure suffix).
    3. Write the file.
    4. Compute a unified diff against the original.
    5. Build a change summary from the RiskProfile findings.
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    # ── public API ──────────────────────────────

    def generate(
        self,
        original_source: str,
        risk_profile: RiskProfile,
        output_path: Optional[str] = None,
    ) -> RemediationResult:
        """Write secure code to disk and return a RemediationResult."""
        secure_code = risk_profile.secure_code

        # Determine output file path
        if output_path is None:
            base, ext = os.path.splitext(risk_profile.file_path)
            filename = os.path.basename(base) + "_secure" + ext
            output_path = os.path.join(self.output_dir, filename)

        # Write secure file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(secure_code)

        # Compute diff
        diff_text = self._compute_diff(
            original_source, secure_code, risk_profile.file_path, output_path
        )

        # Build change summary
        changes = self._build_change_summary(risk_profile)

        return RemediationResult(
            original_file=risk_profile.file_path,
            secure_file=output_path,
            diff_text=diff_text,
            changes_summary=changes,
            line_count_original=len(original_source.splitlines()),
            line_count_secure=len(secure_code.splitlines()),
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

    # ── internal helpers ─────────────────────────

    def _compute_diff(
        self,
        original: str,
        secure: str,
        orig_path: str,
        secure_path: str,
    ) -> str:
        orig_lines = original.splitlines(keepends=True)
        secure_lines = secure.splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines,
            secure_lines,
            fromfile=f"ORIGINAL: {orig_path}",
            tofile=f"SECURE:   {secure_path}",
            lineterm="",
        )
        return "".join(diff)

    def _build_change_summary(self, profile: RiskProfile) -> list[str]:
        """Describe each remediation in plain English."""
        changes = []
        for v in profile.all_findings:
            emoji = profile.severity_emoji.get(v.severity, "•")
            changes.append(
                f"{emoji} [{v.severity}] {v.category} (line {v.line_number}): "
                f"{v.recommendation}"
            )
        return changes