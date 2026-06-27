"""
Module: Scan Service
--------------------
Bridge between the existing security-analysis pipeline and the new
database / lifecycle / audit subsystem.

Orchestrates:
    1. Static scanning  → AI analysis → Risk classification
    2. Secure-code generation  → HTML report generation
    3. Persisting results to the ``scans``, ``vulnerabilities``,
       and ``score_history`` tables
    4. Recording audit-log entries via :class:`AuditLogger`
    5. Managing lifecycle transitions via :class:`LifecycleManager`

All public methods return **camelCase** dicts for direct JSON
serialisation to the Flutter client.
"""

from __future__ import annotations

import os
import uuid
import shutil
from datetime import datetime, timezone
from typing import Optional

# Try to set the custom Git executable if it exists; otherwise fallback to system Git
custom_git_path = "D:\\hive\\git\\Git\\bin\\git.exe"
default_git_path = "C:\\Program Files\\Git\\bin\\git.exe"
if os.path.exists(custom_git_path):
    os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = custom_git_path
elif os.path.exists(default_git_path):
    os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = default_git_path
try:
    import git
    GIT_AVAILABLE = True
except Exception as e:
    print(f"[!] Warning: GitPython or Git executable not found in ScanService. GitHub repo scanning will be disabled. Error: {e}")
    GIT_AVAILABLE = False

from database import get_db
from modules.static_scanner import StaticVulnerabilityScanner
from modules.ai_analyzer import AISecurityAnalyzer
from modules.risk_classifier import RiskClassifier
from modules.lifecycle_manager import LifecycleManager
from modules.audit_logger import AuditLogger
from profile.code_generator import SecureCodeGenerator
from profile.report_generator import ReportGenerator


# ── Helpers ──────────────────────────────────────────────────────

def _lifecycle_status_from_score(score: int) -> str:
    """Map a numeric risk score to a lifecycle status label."""
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "Vulnerable"
    if score >= 25:
        return "Warning"
    return "Safe"


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


# ── Service class ────────────────────────────────────────────────

class ScanService:
    """High-level façade for running, storing, and querying scans."""

    def __init__(self) -> None:
        self.scanner = StaticVulnerabilityScanner()
        self.analyzer = AISecurityAnalyzer()
        self.classifier = RiskClassifier()
        self.lifecycle_manager = LifecycleManager()
        self.audit_logger = AuditLogger()

    # ── Language detection ───────────────────────────────────────

    @staticmethod
    def detect_language(code: str) -> str:
        """Detect programming language from a code snippet.

        Mirrors the heuristic in ``app.py``:
        * ``#include`` or ``int main(`` → **cpp**
        * ``const `` or ``let `` → **javascript**
        * Everything else → **python**
        """
        snippet = code.strip()[:500]
        if "#include" in snippet or "int main(" in snippet:
            return "cpp"
        if "const " in snippet or "let " in snippet:
            return "javascript"
        return "python"

    # ── Full scan pipeline ───────────────────────────────────────

    def run_scan(
        self,
        source_code: str,
        file_path: str,
        language: str,
        mode: str,
        user_id: str,
    ) -> dict:
        """Execute the security pipeline and persist all results.

        Steps:
            1. Run scanner → analyser → classifier → code-gen → report.
            2. Generate a UUID for the scan.
            3. Derive lifecycle status from the risk score.
            4. INSERT into ``scans``.
            5. INSERT each vulnerability into ``vulnerabilities``.
            6. INSERT the initial ``score_history`` entry.
            7. Create an audit-log entry.

        Returns:
            A camelCase dict with scan results, lifecycle info, and
            the list of vulnerabilities.
        """
        now = _now_iso()
        scan_id = str(uuid.uuid4())

        # ── 1. Run the existing pipeline -------------------------
        try:
            raw_vulns, _, _ = self.scanner.scan_file(file_path, language=language)
            ai_result = self.analyzer.analyze(source_code, file_path, language, raw_vulns)
            risk_profile = self.classifier.classify(ai_result, file_path, language)
        except Exception as exc:
            print(f"[ScanService] Pipeline error: {exc}")
            raise RuntimeError(f"Security analysis pipeline failed: {exc}") from exc

        reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "reports"))
        try:
            remediation = SecureCodeGenerator(output_dir=reports_dir).generate(source_code, risk_profile)
        except Exception:
            remediation = None

        try:
            full_report_path = ReportGenerator(output_dir=reports_dir).generate_html_report(
                risk_profile, remediation, source_code,
            )
            report_path = f"reports/{os.path.basename(full_report_path)}"
        except Exception:
            report_path = ""

        risk_score: int = risk_profile.risk_score
        risk_level: str = risk_profile.risk_level
        lifecycle_status: str = _lifecycle_status_from_score(risk_score)
        executive_summary: str = risk_profile.executive_summary

        # ── 2-6. Persist to database ----------------------------
        db = get_db()

        # 4. scans table
        db.execute(
            "INSERT INTO scans (id, file_path, language, mode, risk_score, "
            "risk_level, lifecycle_status, report_path, executive_summary, "
            "user_id, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id, file_path, language, mode, risk_score,
                risk_level, lifecycle_status, report_path,
                executive_summary, user_id, now, now,
            ),
        )

        # 5. vulnerabilities table
        vuln_dicts: list[dict] = []
        for v in ai_result.analyzed_vulnerabilities:
            vuln_id = str(uuid.uuid4())
            db.execute(
                "INSERT INTO vulnerabilities "
                "(id, scan_id, category, severity, line_number, line_content, "
                "cwe_id, owasp_category, ai_explanation, recommendation, "
                "status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    vuln_id, scan_id, v.category, v.severity,
                    v.line_number, v.line_content, v.cwe_id,
                    v.owasp_category, v.ai_explanation,
                    v.recommendation, "open", now,
                ),
            )
            vuln_dicts.append({
                "id": vuln_id,
                "scanId": scan_id,
                "category": v.category,
                "severity": v.severity,
                "lineNumber": v.line_number,
                "lineContent": v.line_content,
                "cweId": v.cwe_id,
                "owaspCategory": v.owasp_category,
                "aiExplanation": v.ai_explanation,
                "recommendation": v.recommendation,
                "status": "open",
                "createdAt": now,
            })

        # 6. Initial score_history entry
        db.execute(
            "INSERT INTO score_history "
            "(scan_id, score, lifecycle_status, changed_by, reason, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                scan_id, risk_score, lifecycle_status,
                user_id, "Initial scan", now,
            ),
        )

        db.commit()

        # ── 7. Audit log ----------------------------------------
        try:
            self.audit_logger.log_action(
                scan_id=scan_id,
                action="scan_created",
                performed_by=user_id,
                role="user",
                new_score=risk_score,
                new_status=lifecycle_status,
                severity_level=risk_level,
                details=f"Scan completed — score {risk_score} ({risk_level})",
            )
        except Exception as exc:
            print(f"[ScanService] Audit log error (non-fatal): {exc}")

        # ── Build response dict ----------------------------------
        return {
            "scanId": scan_id,
            "filePath": file_path,
            "language": language,
            "mode": mode,
            "riskScore": risk_score,
            "riskLevel": risk_level,
            "lifecycleStatus": lifecycle_status,
            "reportPath": report_path,
            "executiveSummary": executive_summary,
            "vulnerabilities": vuln_dicts,
            "createdAt": now,
        }

    # ── GitHub repository scan pipeline ──────────────────────────

    def run_repo_scan(
        self,
        repo_url: str,
        user_id: str,
    ) -> dict:
        """Clone a Git repository, scan all supported files, and aggregate results."""
        if not GIT_AVAILABLE:
            raise RuntimeError("Git is not installed or configured on the server.")

        now = _now_iso()
        scan_id = str(uuid.uuid4())
        repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_code", f"repo_{uuid.uuid4().hex[:6]}"))
        os.makedirs(os.path.dirname(repo_dir), exist_ok=True)
        
        print(f"[*] [ScanService] Cloning repository: {repo_url} to {repo_dir}")
        git.Repo.clone_from(repo_url, repo_dir)

        all_vulnerabilities = []
        max_risk_score = 0
        overall_risk_level = "Low"
        final_report_path = ""
        files_scanned = 0
        vuln_dicts: list[dict] = []
        # Debug logging to identify files cloned
        debug_log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "debug_clone.log"))
        try:
            all_walked_files = []
            for r, _, fs in os.walk(repo_dir):
                for f in fs:
                    all_walked_files.append(os.path.relpath(os.path.join(r, f), repo_dir))
            with open(debug_log_path, "w", encoding="utf-8") as debug_file:
                debug_file.write(f"Repo URL: {repo_url}\n")
                debug_file.write(f"Repo Dir: {repo_dir}\n")
                debug_file.write(f"Total Walked Files: {len(all_walked_files)}\n")
                debug_file.write("Files List:\n")
                for f in all_walked_files:
                    debug_file.write(f"  - {f}\n")
        except Exception as e:
            print(f"[ScanService] Debug logger write error: {e}")

        reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "reports"))
        try:
            for root, _, files in os.walk(repo_dir):
                for file_name in files:
                    if file_name.endswith(('.py', '.js', '.cpp')):
                        f_path = os.path.join(root, file_name)
                        try:
                            with open(f_path, "r", encoding="utf-8", errors="ignore") as f:
                                code = f.read()

                            lang = self.detect_language(code)
                            raw_vulns, _, _ = self.scanner.scan_file(f_path, language=lang)
                            ai_result = self.analyzer.analyze(code, f_path, lang, raw_vulns)
                            risk_profile = self.classifier.classify(ai_result, f_path, lang)
                            
                            try:
                                remediation = SecureCodeGenerator(output_dir=reports_dir).generate(code, risk_profile)
                            except Exception:
                                remediation = None

                            try:
                                full_report_path = ReportGenerator(output_dir=reports_dir).generate_html_report(
                                    risk_profile, remediation, code,
                                )
                                report_path = f"reports/{os.path.basename(full_report_path)}"
                            except Exception:
                                report_path = ""

                            # Store vulnerabilities in list to insert later
                            for v in ai_result.analyzed_vulnerabilities:
                                vuln_uuid = str(uuid.uuid4())
                                category_prefix = f"[{file_name}] {v.category}"
                                vuln_dicts.append({
                                    "id": vuln_uuid,
                                    "scanId": scan_id,
                                    "category": category_prefix,
                                    "severity": v.severity,
                                    "lineNumber": v.line_number,
                                    "lineContent": v.line_content,
                                    "cweId": v.cwe_id,
                                    "owaspCategory": v.owasp_category,
                                    "aiExplanation": v.ai_explanation,
                                    "recommendation": v.recommendation,
                                    "status": "open",
                                    "createdAt": now,
                                })

                            if risk_profile.risk_score >= max_risk_score:
                                max_risk_score = risk_profile.risk_score
                                overall_risk_level = risk_profile.risk_level
                                final_report_path = report_path

                            files_scanned += 1
                        except Exception as file_exc:
                            print(f"[!] Error analyzing file {file_name}: {file_exc}")
                            try:
                                with open(debug_log_path, "a", encoding="utf-8") as debug_file:
                                    debug_file.write(f"\nCRASH on {file_name}: {str(file_exc)}\n")
                                    import traceback
                                    traceback.print_exc(file=debug_file)
                            except Exception:
                                pass

            if files_scanned == 0:
                raise ValueError("No supported files found in the repository")

            lifecycle_status = _lifecycle_status_from_score(max_risk_score)
            
            # Now obtain connection and execute all queries in a single short transaction
            db = get_db()

            # Store scan record
            db.execute(
                "INSERT INTO scans (id, file_path, language, mode, risk_score, "
                "risk_level, lifecycle_status, report_path, executive_summary, "
                "user_id, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id, repo_url, "multi", "github", max_risk_score,
                    overall_risk_level, lifecycle_status, final_report_path,
                    f"Repository scan completed. Scanned {files_scanned} files.", user_id, now, now,
                ),
            )

            # Store vulnerabilities
            for v in vuln_dicts:
                db.execute(
                    "INSERT INTO vulnerabilities "
                    "(id, scan_id, category, severity, line_number, line_content, "
                    "cwe_id, owasp_category, ai_explanation, recommendation, "
                    "status, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        v["id"], v["scanId"], v["category"], v["severity"],
                        v["lineNumber"], v["lineContent"], v["cweId"],
                        v["owaspCategory"], v["aiExplanation"],
                        v["recommendation"], v["status"], v["createdAt"],
                    ),
                )

            # Store score history entry
            db.execute(
                "INSERT INTO score_history "
                "(scan_id, score, lifecycle_status, changed_by, reason, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    scan_id, max_risk_score, lifecycle_status,
                    user_id, "Initial repository scan", now,
                ),
            )

            db.commit()

            # Record audit log entry
            try:
                self.audit_logger.log_action(
                    scan_id=scan_id,
                    action="scan_created",
                    performed_by=user_id,
                    role="user",
                    new_score=max_risk_score,
                    new_status=lifecycle_status,
                    severity_level=overall_risk_level,
                    details=f"Repository scan completed — {files_scanned} files scanned. Risk score: {max_risk_score}",
                )
            except Exception as exc:
                print(f"[ScanService] Repository audit log error (non-fatal): {exc}")

        finally:
            # Clean up cloned repository
            if os.path.exists(repo_dir):
                print(f"[*] [ScanService] Cleaning up cloned repo folder: {repo_dir}")
                shutil.rmtree(repo_dir, ignore_errors=True)

        return {
            "scanId": scan_id,
            "filePath": repo_url,
            "language": "multi",
            "mode": "github",
            "riskScore": max_risk_score,
            "riskLevel": overall_risk_level,
            "lifecycleStatus": lifecycle_status,
            "reportPath": final_report_path,
            "executiveSummary": f"Repository scan completed. Scanned {files_scanned} files.",
            "vulnerabilities": vuln_dicts,
            "createdAt": now,
        }

    # ── Single scan retrieval ────────────────────────────────────

    def get_scan(self, scan_id: str) -> dict:
        """Fetch a scan and its vulnerabilities from the database.

        Args:
            scan_id: UUID of the scan.

        Returns:
            A camelCase dict, or ``None`` if the scan does not exist.

        Raises:
            ValueError: If the scan is not found.
        """
        db = get_db()

        scan_row = db.execute(
            "SELECT id, file_path, language, mode, risk_score, risk_level, "
            "lifecycle_status, report_path, executive_summary, user_id, created_at "
            "FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

        if scan_row is None:
            raise ValueError(f"Scan not found: {scan_id}")

        vuln_rows = db.execute(
            "SELECT id, scan_id, category, severity, line_number, line_content, "
            "cwe_id, owasp_category, ai_explanation, recommendation, "
            "status, created_at "
            "FROM vulnerabilities WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()

        return {
            "scanId": scan_row["id"],
            "filePath": scan_row["file_path"],
            "language": scan_row["language"],
            "mode": scan_row["mode"],
            "riskScore": scan_row["risk_score"],
            "riskLevel": scan_row["risk_level"],
            "lifecycleStatus": scan_row["lifecycle_status"],
            "reportPath": (scan_row["report_path"] or "").replace("\\", "/"),
            "executiveSummary": scan_row["executive_summary"],
            "userId": scan_row["user_id"],
            "vulnerabilities": [
                {
                    "id": vr["id"],
                    "scanId": vr["scan_id"],
                    "category": vr["category"],
                    "severity": vr["severity"],
                    "lineNumber": vr["line_number"],
                    "lineContent": vr["line_content"],
                    "cweId": vr["cwe_id"],
                    "owaspCategory": vr["owasp_category"],
                    "aiExplanation": vr["ai_explanation"],
                    "recommendation": vr["recommendation"],
                    "status": vr["status"],
                    "createdAt": vr["created_at"],
                }
                for vr in vuln_rows
            ],
            "createdAt": scan_row["created_at"],
        }

    # ── Paginated scan list ──────────────────────────────────────

    def get_scans(
        self,
        user_id: Optional[str] = None,
        page: int = 1,
        per_page: int = 20,
    ) -> dict:
        """Return a paginated list of scans.

        Args:
            user_id:  Optional filter by owner.
            page:     1-based page number.
            per_page: Number of scans per page (max 100).

        Returns:
            ``{"scans": [...], "pagination": {...}}``.
        """
        db = get_db()
        per_page = min(per_page, 100)
        offset = (max(page, 1) - 1) * per_page

        where_clause = ""
        params: tuple = ()
        if user_id is not None:
            where_clause = "WHERE user_id = ?"
            params = (user_id,)

        total_row = db.execute(
            f"SELECT COUNT(*) AS cnt FROM scans {where_clause}", params,
        ).fetchone()
        total: int = total_row["cnt"] or 0

        rows = db.execute(
            f"SELECT id, file_path, language, mode, risk_score, risk_level, "
            f"lifecycle_status, report_path, executive_summary, user_id, created_at "
            f"FROM scans {where_clause} "
            f"ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (*params, per_page, offset),
        ).fetchall()

        scans: list[dict] = [
            {
                "scanId": r["id"],
                "filePath": r["file_path"],
                "language": r["language"],
                "mode": r["mode"],
                "riskScore": r["risk_score"],
                "riskLevel": r["risk_level"],
                "lifecycleStatus": r["lifecycle_status"],
                "reportPath": (r["report_path"] or "").replace("\\", "/"),
                "executiveSummary": r["executive_summary"],
                "userId": r["user_id"],
                "createdAt": r["created_at"],
            }
            for r in rows
        ]

        total_pages = max(1, (total + per_page - 1) // per_page)

        return {
            "scans": scans,
            "pagination": {
                "page": page,
                "perPage": per_page,
                "totalItems": total,
                "totalPages": total_pages,
                "hasNext": page < total_pages,
                "hasPrevious": page > 1,
            },
        }

    # ── Vulnerability status update ──────────────────────────────

    def update_vulnerability_status(
        self,
        vuln_id: str,
        new_status: str,
        performed_by: str,
    ) -> dict:
        """Update a vulnerability's status and recalculate the scan score.

        When all vulnerabilities of a scan are marked as *fixed* or
        *accepted*, the scan's lifecycle transitions to **Resolved**.

        Args:
            vuln_id:      UUID of the vulnerability.
            new_status:   New status value (e.g. ``"fixed"``, ``"accepted"``).
            performed_by: User ID performing the action.

        Returns:
            A camelCase dict with the updated vulnerability and the
            recalculated scan-level data.

        Raises:
            ValueError: If the vulnerability is not found.
        """
        db = get_db()
        now = _now_iso()

        vuln_row = db.execute(
            "SELECT id, scan_id, category, severity, status "
            "FROM vulnerabilities WHERE id = ?",
            (vuln_id,),
        ).fetchone()

        if vuln_row is None:
            raise ValueError(f"Vulnerability not found: {vuln_id}")

        old_status = vuln_row["status"]
        scan_id = vuln_row["scan_id"]

        # Update vulnerability status
        db.execute(
            "UPDATE vulnerabilities SET status = ? WHERE id = ?",
            (new_status, vuln_id),
        )

        # Recalculate scan risk score based on remaining open vulns
        open_vulns = db.execute(
            "SELECT severity FROM vulnerabilities "
            "WHERE scan_id = ? AND status NOT IN ('fixed', 'accepted')",
            (scan_id,),
        ).fetchall()

        severity_weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
        if open_vulns:
            import math
            raw = sum(severity_weights.get(v["severity"], 1) for v in open_vulns)
            new_score = int(min(100, 20 * math.log1p(raw)))
            has_critical = any(v["severity"] == "Critical" for v in open_vulns)
            if has_critical:
                critical_count = sum(1 for v in open_vulns if v["severity"] == "Critical")
                new_score = max(new_score, 60 + min(40, critical_count * 5))
            new_score = min(new_score, 100)
        else:
            new_score = 0

        new_lifecycle = (
            "Resolved" if new_score == 0
            else _lifecycle_status_from_score(new_score)
        )

        # Update scan record
        db.execute(
            "UPDATE scans SET risk_score = ?, lifecycle_status = ? WHERE id = ?",
            (new_score, new_lifecycle, scan_id),
        )

        # Insert score_history entry
        db.execute(
            "INSERT INTO score_history "
            "(scan_id, score, lifecycle_status, changed_by, reason, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                scan_id, new_score, new_lifecycle,
                performed_by,
                f"Vulnerability {vuln_id} status changed: {old_status} → {new_status}",
                now,
            ),
        )

        db.commit()

        # Audit log
        try:
            self.audit_logger.log_action(
                scan_id=scan_id,
                action="vulnerability_status_changed",
                performed_by=performed_by,
                role="admin",
                old_status=old_status,
                new_status=new_status,
                vulnerability_status=new_status,
                severity_level=vuln_row["severity"],
                details=(
                    f"Vulnerability {vuln_id} changed from "
                    f"'{old_status}' to '{new_status}'. "
                    f"Scan score recalculated to {new_score}."
                ),
            )
        except Exception as exc:
            print(f"[ScanService] Audit log error (non-fatal): {exc}")

        return {
            "vulnerabilityId": vuln_id,
            "previousStatus": old_status,
            "newStatus": new_status,
            "scanId": scan_id,
            "recalculatedScore": new_score,
            "lifecycleStatus": new_lifecycle,
            "updatedAt": now,
        }
