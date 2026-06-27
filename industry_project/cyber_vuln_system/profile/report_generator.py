"""
Module 5: Report Generator
---------------------------
Produces a professional, self-contained HTML security report
that can be opened in any browser without external dependencies.
"""

import os
from datetime import datetime
from modules.risk_classifier import RiskProfile
from profile.code_generator import RemediationResult
from pygments import highlight
from pygments.lexers import get_lexer_by_name, TextLexer
from pygments.formatters import HtmlFormatter


LANGUAGE_MAP = {
    "python": "python",
    "javascript": "javascript",
    "php": "php",
    "java": "java",
    "c": "c",
    "unknown": "text",
}


class ReportGenerator:
    """
    Renders a complete HTML security report from a RiskProfile
    and a RemediationResult.
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_html_report(
        self,
        risk_profile: RiskProfile,
        remediation: RemediationResult,
        original_source: str,
        report_path: str | None = None,
    ) -> str:
        """Render the HTML report and write it to disk. Returns the file path."""
        if report_path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            base = os.path.basename(risk_profile.file_path).replace(".", "_")
            report_path = os.path.join(self.output_dir, f"security_report_{base}_{ts}.html")

        html = self._render(risk_profile, remediation, original_source)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)
        return report_path

    def _render(
        self,
        p: RiskProfile,
        r: RemediationResult,
        original_source: str,
    ) -> str:
        pygments_css = HtmlFormatter(style="one-dark").get_style_defs(".highlight")
        if not pygments_css:
            pygments_css = HtmlFormatter(style="monokai").get_style_defs(".highlight")

        lexer_name = LANGUAGE_MAP.get(p.language, "text")

        try:
            lexer = get_lexer_by_name(lexer_name)
        except Exception:
            lexer = TextLexer()

        original_hl = highlight(original_source, lexer, HtmlFormatter(style="one-dark", linenos=True))
        secure_hl = highlight(p.secure_code, lexer, HtmlFormatter(style="one-dark", linenos=True))
        diff_hl = highlight(r.diff_text if r else "", get_lexer_by_name("diff"), HtmlFormatter(style="one-dark"))

        findings_html = self._render_findings(p)
        chart_html = self._render_chart(p)
        owasp_html = self._render_owasp(p)
        priority_html = self._render_priority(p)

        gauge_pct = p.risk_score
        gauge_color = {
            "Critical": "#ef4444",
            "High": "#f97316",
            "Medium": "#eab308",
            "Low": "#10b981",
        }.get(p.risk_level, "#3b82f6")

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        secure_file_name = os.path.basename(r.secure_file) if r else "N/A"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Security Audit Report | {os.path.basename(p.file_path)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  :root {{
    --bg:       #0f1115;
    --surface:  #181b21;
    --border:   #272c36;
    --text:     #e2e8f0;
    --text-dim: #94a3b8;
    --accent:   #2563eb;
    --accent-hover: #1d4ed8;
    --crit:     #ef4444;
    --high:     #f97316;
    --med:      #eab308;
    --low:      #10b981;
    --radius:   6px;
  }}
  html {{ scroll-behavior: smooth; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    font-size: 14px;
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
  }}
  a {{ color: #3b82f6; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  pre {{ white-space: pre-wrap; word-break: break-all; font-family: 'JetBrains Mono', monospace; }}

  /* Layout */
  .page {{ max-width: 1280px; margin: 0 auto; padding: 40px 24px 80px; }}

  /* Header */
  .header {{
    border-bottom: 1px solid var(--border);
    padding-bottom: 24px;
    margin-bottom: 32px;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
  }}
  .header h1 {{ font-size: 1.75rem; font-weight: 700; color: #fff; letter-spacing: -0.02em; margin-bottom: 12px; }}
  .header-badge {{
    background: rgba(59,130,246,0.1);
    border: 1px solid rgba(59,130,246,0.3);
    color: #3b82f6;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    margin-left: 12px;
    vertical-align: middle;
  }}
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 8px 32px;
    font-size: 0.85rem;
    color: var(--text-dim);
  }}
  .meta-grid span {{ color: var(--text); font-weight: 500; }}

  /* Risk Gauge Container */
  .risk-overview {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 24px;
    text-align: right;
    min-width: 200px;
    display: flex;
    flex-direction: column;
    align-items: flex-end;
  }}
  .risk-value {{
    font-size: 3rem;
    font-weight: 700;
    line-height: 1;
    color: {gauge_color};
    margin-bottom: 8px;
  }}
  .risk-label {{
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 600;
    color: var(--text-dim);
  }}
  .risk-level-badge {{
    margin-top: 8px;
    padding: 4px 12px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: {gauge_color};
    border: 1px solid {gauge_color};
    background: {gauge_color}15;
  }}

  /* Summary cards */
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr)); gap: 16px; margin-bottom: 32px; }}
  .scard {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px;
    position: relative;
    overflow: hidden;
  }}
  .scard::before {{
    content: ''; position: absolute;
    top: 0; left: 0; bottom: 0; width: 3px;
  }}
  .scard.critical::before {{ background: var(--crit); }}
  .scard.high::before    {{ background: var(--high); }}
  .scard.medium::before  {{ background: var(--med);  }}
  .scard.low::before     {{ background: var(--low);  }}
  .scard .count {{
    font-size: 2rem; font-weight: 600; line-height: 1;
    margin-bottom: 8px;
    color: var(--text);
  }}
  .scard .label {{ font-size: 0.8rem; color: var(--text-dim); font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; }}

  /* Sections */
  .section {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 32px;
  }}
  .section-header {{
    padding: 16px 24px;
    border-bottom: 1px solid var(--border);
  }}
  .section-header h2 {{ font-size: 1rem; font-weight: 600; color: #fff; letter-spacing: 0.01em; }}
  .section-body {{ padding: 24px; }}

  /* Executive summary */
  .exec-summary {{
    font-size: 0.95rem;
    color: var(--text);
    margin-bottom: 16px;
    line-height: 1.6;
  }}
  .risk-trend {{
    font-weight: 600;
    font-size: 0.95rem;
    color: var(--text);
  }}

  /* Priority fixes */
  .priority-list {{ list-style: none; display: flex; flex-direction: column; gap: 8px; }}
  .priority-list li {{
    background: rgba(239,68,68,0.05);
    border-left: 3px solid var(--crit);
    padding: 12px 16px;
    font-size: 0.9rem;
    color: #f8fafc;
  }}

  /* Bar chart */
  .bar-chart {{ display: flex; flex-direction: column; gap: 12px; }}
  .bar-row {{ display: grid; grid-template-columns: 200px 1fr 40px; align-items: center; gap: 16px; font-size: 0.85rem; font-weight: 500; }}
  .bar-label {{ color: var(--text-dim); text-align: right; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .bar-track {{ background: #0f1115; border: 1px solid var(--border); height: 8px; overflow: hidden; border-radius: 2px; }}
  .bar-fill  {{ height: 100%; border-radius: 2px; }}
  .bar-val   {{ color: var(--text); font-size: 0.85rem; }}

  /* OWASP badges */
  .owasp-grid {{ display: flex; flex-wrap: wrap; gap: 8px; }}
  .owasp-badge {{
    background: #0f1115;
    border: 1px solid var(--border);
    color: var(--text-dim);
    padding: 4px 12px;
    font-size: 0.8rem;
    font-weight: 500;
    border-radius: 4px;
  }}
  .owasp-count {{
    background: var(--border);
    color: var(--text);
    padding: 0 6px;
    border-radius: 10px;
    font-size: 0.75rem;
    margin-left: 8px;
    font-weight: 600;
  }}

  /* Vulnerability cards */
  .vuln-card {{
    background: #0f1115;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 16px;
  }}
  .vuln-header {{
    display: grid;
    grid-template-columns: auto 1fr auto;
    align-items: center;
    gap: 16px;
    padding: 16px;
    cursor: pointer;
    user-select: none;
  }}
  .vuln-header:hover {{ background: #13161c; }}
  .sev-indicator {{
    width: 8px; height: 8px; border-radius: 50%;
  }}
  .sev-Critical {{ background: var(--crit); box-shadow: 0 0 5px var(--crit); }}
  .sev-High     {{ background: var(--high); box-shadow: 0 0 5px var(--high); }}
  .sev-Medium   {{ background: var(--med);  box-shadow: 0 0 5px var(--med); }}
  .sev-Low      {{ background: var(--low);  box-shadow: 0 0 5px var(--low); }}
  
  .vuln-title   {{ font-weight: 600; font-size: 0.95rem; color: #fff; }}
  .vuln-meta    {{ font-size: 0.8rem; color: var(--text-dim); margin-top: 4px; font-family: 'JetBrains Mono', monospace; }}
  .vuln-toggle  {{ color: var(--text-dim); }}
  details[open] .vuln-toggle {{ transform: rotate(180deg); color: #fff; }}

  .vuln-body {{ padding: 0 16px 24px; display: grid; gap: 20px; border-top: 1px solid var(--border); margin-top: 16px; padding-top: 24px; }}
  .vuln-section {{ font-size: 0.9rem; }}
  .vuln-section-title {{
    font-size: 0.75rem; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.05em;
    color: var(--text-dim); margin-bottom: 8px;
  }}
  .vuln-section p {{ color: var(--text); line-height: 1.6; }}

  .code-block {{
    background: #090a0c;
    border: 1px solid var(--border);
    border-radius: 4px;
    overflow-x: auto;
    font-size: 0.85rem;
  }}
  .code-block .highlight {{ background: transparent !important; padding: 16px; }}

  .tag-row {{ display: flex; flex-wrap: wrap; gap: 8px; }}
  .tag {{
    background: #181b21;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 0.75rem;
    color: var(--text-dim);
    font-family: 'JetBrains Mono', monospace;
  }}

  .rec-box {{
    background: rgba(16,185,129,0.05);
    border-left: 3px solid var(--low);
    padding: 12px 16px;
    font-size: 0.9rem;
    color: var(--text);
  }}

  /* Code tabs */
  .tabs {{ display: flex; border-bottom: 1px solid var(--border); background: #0f1115; }}
  .tab-btn {{
    padding: 12px 20px;
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--text-dim);
    font-size: 0.85rem;
    font-weight: 500;
    font-family: 'Inter', sans-serif;
    cursor: pointer;
  }}
  .tab-btn:hover {{ color: #fff; }}
  .tab-btn.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
  .tab-panel {{ display: none; padding: 0; }}
  .tab-panel.active {{ display: block; }}

  /* Diff colors */
  .diff-add {{ background: rgba(16,185,129,0.1); }}
  .diff-del {{ background: rgba(239,68,68,0.1); }}

  /* Footer */
  .footer {{
    text-align: right;
    color: var(--text-dim);
    font-size: 0.8rem;
    border-top: 1px solid var(--border);
    padding-top: 24px;
  }}

  /* Pygments overrides */
  {pygments_css}
  .highlight pre {{ margin: 0; font-family: 'JetBrains Mono', monospace; line-height: 1.5; }}
  .highlight .lineno {{ color: #475569; padding-right: 16px; border-right: 1px solid var(--border); margin-right: 16px; display: inline-block; user-select: none; }}
</style>
</head>
<body>
<div class="page">

  <!-- HEADER -->
  <div class="header">
    <div>
      <h1>AI Cyber Shield <span class="header-badge">Enterprise Report</span></h1>
      <div class="meta-grid">
        <div>Target: <span>{os.path.basename(p.file_path)}</span></div>
        <div>Language: <span>{p.language.title()}</span></div>
        <div>Generated: <span>{now}</span></div>
        <div>Total Findings: <span>{p.severity_breakdown.total}</span></div>
      </div>
    </div>
    <div class="risk-overview">
      <div class="risk-label">Aggregate Risk Score</div>
      <div class="risk-value">{gauge_pct}</div>
      <div class="risk-level-badge">{p.risk_level}</div>
    </div>
  </div>

  <!-- SEVERITY CARDS -->
  <div class="summary-grid">
    <div class="scard critical">
      <div class="count">{p.severity_breakdown.critical}</div>
      <div class="label">Critical Findings</div>
    </div>
    <div class="scard high">
      <div class="count">{p.severity_breakdown.high}</div>
      <div class="label">High Findings</div>
    </div>
    <div class="scard medium">
      <div class="count">{p.severity_breakdown.medium}</div>
      <div class="label">Medium Findings</div>
    </div>
    <div class="scard low">
      <div class="count">{p.severity_breakdown.low}</div>
      <div class="label">Low Findings</div>
    </div>
  </div>

  <!-- EXECUTIVE SUMMARY -->
  <div class="section">
    <div class="section-header"><h2>Executive Brief</h2></div>
    <div class="section-body">
      <div class="exec-summary">{p.executive_summary}</div>
      <div class="risk-trend">{p.risk_trend}</div>
    </div>
  </div>

  <!-- PRIORITY FIXES -->
  <div class="section">
    <div class="section-header"><h2>Immediate Action Required</h2></div>
    <div class="section-body">
      <ul class="priority-list">
        {"".join(f"<li>{fix}</li>" for fix in p.top_priority_fixes)}
      </ul>
    </div>
  </div>

  <!-- CHARTS -->
  <div class="section">
    <div class="section-header"><h2>Vulnerability Distribution</h2></div>
    <div class="section-body" style="display: grid; grid-template-columns: 1fr 1fr; gap: 48px;">
      <div>
        <h3 style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-dim);margin-bottom:16px;font-weight:600">By Category</h3>
        {chart_html}
      </div>
      <div>
        <h3 style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-dim);margin-bottom:16px;font-weight:600">OWASP Top 10 Mapping</h3>
        {owasp_html}
      </div>
    </div>
  </div>

  <!-- FINDINGS -->
  <div class="section">
    <div class="section-header"><h2>Detailed Findings ({p.severity_breakdown.total})</h2></div>
    <div class="section-body">{findings_html}</div>
  </div>

  <!-- CODE TABS -->
  <div class="section">
    <div class="section-header"><h2>Code Remediation Diff</h2></div>
    <div class="tabs">
      <button class="tab-btn active" onclick="switchTab(event,'diff')">Unified Diff</button>
      <button class="tab-btn" onclick="switchTab(event,'secure')">Secure Code</button>
      <button class="tab-btn" onclick="switchTab(event,'original')">Original Code</button>
    </div>
    <div class="section-body" style="padding:0">
      <div id="diff" class="tab-panel active">
        <div class="code-block" style="border:none; border-radius:0;">{diff_hl}</div>
      </div>
      <div id="secure" class="tab-panel">
        <div class="code-block" style="border:none; border-radius:0;">{secure_hl}</div>
      </div>
      <div id="original" class="tab-panel">
        <div class="code-block" style="border:none; border-radius:0;">{original_hl}</div>
      </div>
    </div>
  </div>

  <div class="footer">
    <div>AI Cyber Shield &bull; Security Audit Report</div>
  </div>
</div>

<script>
function switchTab(e, id) {{
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  e.target.classList.add('active');
  document.getElementById(id).classList.add('active');
}}
</script>
</body>
</html>"""

    def _render_findings(self, p: RiskProfile) -> str:
        if not p.all_findings:
            return '<div style="padding: 24px; text-align: center; color: var(--text-dim);">No vulnerabilities found. The codebase passed the static checks.</div>'

        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_findings = sorted(p.all_findings, key=lambda v: order.get(v.severity, 4))

        lexer_name = LANGUAGE_MAP.get(p.language, "text")
        try:
            lexer = get_lexer_by_name(lexer_name)
        except Exception:
            lexer = TextLexer()

        cards = []
        for i, v in enumerate(sorted_findings):
            snippet_hl = (
                highlight(v.secure_code_snippet, lexer, HtmlFormatter(style="one-dark"))
                if v.secure_code_snippet
                else ""
            )
            refs_html = (
                " ".join(
                    f'<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name={r}" target="_blank" class="tag">{r}</a>'
                    if r.startswith("CVE") else f'<a href="{r}" target="_blank" class="tag">{r}</a>'
                    for r in v.references
                )
                if v.references else ""
            )
            cards.append(f"""
<div class="vuln-card">
  <details>
    <summary style="list-style:none">
      <div class="vuln-header">
        <div class="sev-indicator sev-{v.severity}"></div>
        <div>
          <div class="vuln-title">{v.category}</div>
          <div class="vuln-meta">Line: {v.line_number} &nbsp;&bull;&nbsp; ID: {v.vuln_id} &nbsp;&bull;&nbsp; Severity: {v.severity}</div>
        </div>
        <span class="vuln-toggle"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg></span>
      </div>
    </summary>
    <div class="vuln-body">
      <div class="tag-row">
        <span class="tag">CWE: {v.cwe_id}</span>
        <span class="tag">OWASP: {v.owasp_category.split(' - ')[0] if ' - ' in v.owasp_category else v.owasp_category}</span>
        <span class="tag">Conf: {v.confidence}</span>
        <span class="tag">FP: {v.false_positive_likelihood}</span>
      </div>
      <div class="vuln-section">
        <div class="vuln-section-title">Vulnerable Code</div>
        <div class="code-block"><div class="highlight"><pre>{v.line_content}</pre></div></div>
      </div>
      <div class="vuln-section" style="display:grid; grid-template-columns: 1fr 1fr; gap: 32px;">
          <div>
            <div class="vuln-section-title">Technical Explanation</div>
            <p>{v.ai_explanation}</p>
          </div>
          <div>
            <div class="vuln-section-title">Exploit Scenario</div>
            <p>{v.exploit_scenario}</p>
          </div>
      </div>
      <div class="vuln-section">
        <div class="vuln-section-title">Recommended Remediation</div>
        <div class="rec-box">{v.recommendation}</div>
      </div>
      {"<div class='vuln-section'><div class='vuln-section-title'>Secure Snippet Demo</div><div class='code-block'>" + snippet_hl + "</div></div>" if snippet_hl else ""}
      {"<div class='vuln-section'><div class='vuln-section-title'>External References</div><div class='tag-row'>" + refs_html + "</div></div>" if refs_html else ""}
    </div>
  </details>
</div>""")
        return "\n".join(cards)

    def _render_chart(self, p: RiskProfile) -> str:
        if not p.category_breakdown:
            return ""
        max_val = max(p.category_breakdown.values(), default=1)
        bars = []
        colors = ["#ef4444", "#f97316", "#eab308", "#10b981", "#3b82f6",
                  "#6366f1", "#8b5cf6", "#d946ef", "#f43f5e", "#64748b"]
        for i, (cat, cnt) in enumerate(
            sorted(p.category_breakdown.items(), key=lambda x: -x[1])
        ):
            pct = int((cnt / max_val) * 100)
            color = colors[i % len(colors)]
            bars.append(f"""
<div class="bar-row">
  <span class="bar-label" title="{cat}">{cat}</span>
  <div class="bar-track">
    <div class="bar-fill" style="width:{pct}%;background:{color};"></div>
  </div>
  <span class="bar-val">{cnt}</span>
</div>""")
        return f'<div class="bar-chart">{"".join(bars)}</div>'

    def _render_owasp(self, p: RiskProfile) -> str:
        badges = []
        for cat, cnt in sorted(p.owasp_breakdown.items(), key=lambda x: -x[1]):
            badges.append(
                f'<span class="owasp-badge">{cat}<span class="owasp-count">{cnt}</span></span>'
            )
        return f'<div class="owasp-grid">{"".join(badges)}</div>'

    def _render_priority(self, p: RiskProfile) -> str:
        items = "".join(f"<li>{fix}</li>" for fix in p.top_priority_fixes)
        return f'<ul class="priority-list">{items}</ul>'