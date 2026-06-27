#!/usr/bin/env python3
"""
AI-Based Cyber Vulnerability Analysis and Auto-Remediation System
==================================================================
Main entry point. Orchestrates the five-module pipeline.

Usage:
  python main.py <source_file> [--output-dir reports] [--no-ai]

Environment:
  OPENROUTER_API_KEY — required unless --no-ai flag is used [cite: 32, 33]
"""

import argparse
import os
import sys
import time
from datetime import datetime

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

# ── module imports ────────────────────
from modules.static_scanner import StaticVulnerabilityScanner
from modules.ai_analyzer import AISecurityAnalyzer
from modules.risk_classifier import RiskClassifier
from profile.code_generator import SecureCodeGenerator
from profile.report_generator import ReportGenerator

load_dotenv()
console = Console()

SEVERITY_STYLES = {
    "Critical": "bold red",
    "High": "bold yellow",
    "Medium": "yellow",
    "Low": "green",
}

BANNER = """
╔══════════════════════════════════════════════════════════╗
   🛡️  AI Cyber Vulnerability Analysis System  v1.0       
╚══════════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────────
#  Pipeline orchestrator
# ─────────────────────────────────────────────

def run_pipeline(file_path: str, output_dir: str, use_ai: bool) -> None:
    console.print(Panel(BANNER.strip(), style="bold cyan", border_style="cyan"))
    start_time = time.time()

    if not os.path.isfile(file_path):
        console.print(f"[bold red]✗ File not found:[/bold red] {file_path}")
        sys.exit(1)

    console.print(f"\n[bold]Target file:[/bold] {file_path}")
    console.print(f"[bold]Output dir:[/bold]  {output_dir}")
    console.print(f"[bold]AI analysis:[/bold] {'enabled (DeepSeek via OpenRouter)' if use_ai else 'disabled (--no-ai)'}\n")

    os.makedirs(output_dir, exist_ok=True)

    # ═══ PHASE 1: Static Scan ══════════════════
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as prog:
        task = prog.add_task("[cyan]Phase 1 — Static vulnerability scan...", total=None)
        scanner = StaticVulnerabilityScanner()
        raw_vulns, source_code, language = scanner.scan_file(file_path)
        prog.update(task, completed=True)

    # ═══ PHASE 2: AI Analysis ══════════════════
    if use_ai:
        api_key = os.environ.get("OPENROUTER_API_KEY", "") # Updated from ANTHROPIC_API_KEY [cite: 33]
        if not api_key:
            console.print(
                "[bold red]✗ OPENROUTER_API_KEY not set.[/bold red] "
                "Add it to .env or set the environment variable.\n"
            )
            sys.exit(1)

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console) as prog:
            task = prog.add_task("[cyan]Phase 2 — AI deep-analysis with DeepSeek...", total=None)
            analyzer = AISecurityAnalyzer(api_key=api_key)
            ai_result = analyzer.analyze(source_code, file_path, language, raw_vulns)
            prog.update(task, completed=True)

        console.print(f"[green]✓ AI analysis complete.[/green] "
                      f"Confirmed: {len(ai_result.analyzed_vulnerabilities)}, "
                      f"Additional: {len(ai_result.additional_findings)}")
        
        # PRINT INTEGRATED RESULTS (Static + AI Suggestions)
        _print_combined_results(ai_result, language)

    else:
        # Minimal AIAnalysisResult logic for --no-ai mode
        from modules.ai_analyzer import AIAnalysisResult, AnalyzedVulnerability

        def _raw_to_analyzed(v):
            return AnalyzedVulnerability(
                vuln_id=v.vuln_id,
                category=v.category,
                line_number=v.line_number,
                line_content=v.line_content,
                file_path=v.file_path,
                language=v.language,
                cwe_id=v.cwe_id,
                owasp_category=v.owasp_category,
                severity=v.raw_severity,
                confidence=v.confidence,
                ai_explanation=v.description,
                exploit_scenario="N/A",
                recommendation="Review the flagged line and apply secure coding best practices.",
                secure_code_snippet="",
                false_positive_likelihood="MEDIUM",
            )

        ai_result = AIAnalysisResult(
            analyzed_vulnerabilities=[_raw_to_analyzed(v) for v in raw_vulns],
            additional_findings=[],
            overall_risk_score=min(100, len(raw_vulns) * 10),
            overall_risk_level="High" if raw_vulns else "Low",
            executive_summary="Static analysis only.",
            top_priority_fixes=[],
            secure_code=source_code,
        )
        _print_combined_results(ai_result, language)

    # ═══ PHASE 3: Risk Classification ══════════
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as prog:
        task = prog.add_task("[cyan]Phase 3 — Risk classification...", total=None)
        classifier = RiskClassifier()
        risk_profile = classifier.classify(ai_result, file_path, language)
        prog.update(task, completed=True)

    _print_risk_summary(risk_profile)

    # ═══ PHASE 4 & 5 ══════════════════════════
    # (Remains largely the same as your original main.py)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as prog:
        task = prog.add_task("[cyan]Phase 4 — Generating secure code...", total=None)
        generator = SecureCodeGenerator(output_dir=output_dir)
        remediation = generator.generate(source_code, risk_profile)
        prog.update(task, completed=True)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as prog:
        task = prog.add_task("[cyan]Phase 5 — Generating HTML report...", total=None)
        reporter = ReportGenerator(output_dir=output_dir)
        report_path = reporter.generate_html_report(risk_profile, remediation, source_code)
        prog.update(task, completed=True)

    elapsed = time.time() - start_time
    _print_final_summary(risk_profile, remediation, report_path, elapsed)


# ─────────────────────────────────────────────
#  Console pretty-print helpers
# ─────────────────────────────────────────────

def _print_combined_results(ai_result, language: str) -> None:
    """Prints the table with the new AI Fix Suggestion column."""
    all_findings = ai_result.analyzed_vulnerabilities + ai_result.additional_findings
    
    if not all_findings:
        console.print("[green]✓ No vulnerabilities detected.[/green]")
        return

    table = Table(
        title=f"Security Analysis Results — {language.title()}",
        box=box.ROUNDED, show_lines=True, # Added lines for better readability with long AI text
        header_style="bold cyan",
    )
    table.add_column("ID", style="dim", width=10)
    table.add_column("Category", width=18)
    table.add_column("Line", justify="right", width=5)
    table.add_column("Severity", width=10)
    table.add_column("Snippet", width=30, overflow="ellipsis")
    table.add_column("AI Fix Suggestion", style="green", width=40) # NEW COLUMN

    for v in all_findings:
        sev_style = SEVERITY_STYLES.get(v.severity, "white")
        table.add_row(
            v.vuln_id,
            v.category,
            str(v.line_number),
            f"[{sev_style}]{v.severity}[/{sev_style}]",
            v.line_content.strip()[:60],
            v.recommendation # Populate from ai_analyzer.py
        )
    console.print(table)

def _print_risk_summary(profile) -> None:
    bd = profile.severity_breakdown
    
    # 1. Determine color based on score
    score_color = "red" if profile.risk_score >= 75 else "yellow" if profile.risk_score >= 50 else "green"
    
    # 2. Build the strings separately to avoid Rich Markup issues
    header = f"\n[bold]Risk Score:[/bold] [{score_color}]{profile.risk_score}/100 — {profile.risk_level}[/{score_color}]\n"
    stats = (
        f"  🔴 Critical: {bd.critical}  |  "
        f"🟠 High: {bd.high}  |  "
        f"🟡 Medium: {bd.medium}  |  "
        f"🟢 Low: {bd.low}  |  "
        f"📋 Total: {bd.total}"
    )
    
    # 3. Print the clean strings
    console.print(header)
    console.print(stats)
    console.print(f"  {profile.risk_trend}\n")

def _print_final_summary(profile, remediation, report_path: str, elapsed: float) -> None:
    console.print(
        Panel(
            f"[bold green]✅ Analysis Complete[/bold green]  ({elapsed:.1f}s)\n\n"
            f"  [bold]Report:[/bold]      {report_path}\n"
            f"  [bold]Secure code:[/bold] {remediation.secure_file}\n",
            title="🛡️ Done", border_style="green",
        )
    )

def main():
    parser = argparse.ArgumentParser(description="AI Cyber Vulnerability Analysis System")
    parser.add_argument("file", help="Source code file to analyze")
    parser.add_argument("--output-dir", default="reports")
    parser.add_argument("--no-ai", action="store_true")
    args = parser.parse_args()
    
    try:
        run_pipeline(args.file, args.output_dir, use_ai=not args.no_ai)
    except KeyboardInterrupt:
        console.print("\n[bold red]Process interrupted by user.[/bold red]")
        sys.exit(0)

if __name__ == "__main__":
    main()