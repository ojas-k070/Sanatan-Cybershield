import json
import os
import re
import requests
from dataclasses import dataclass, field
from typing import Optional

from modules.static_scanner import RawVulnerability

@dataclass
class AnalyzedVulnerability:
    vuln_id: str
    category: str
    line_number: int
    line_content: str
    file_path: str
    language: str
    cwe_id: str
    owasp_category: str
    severity: str
    confidence: str
    ai_explanation: str
    exploit_scenario: str
    recommendation: str
    secure_code_snippet: str
    false_positive_likelihood: str
    references: list[str] = field(default_factory=list)

@dataclass
class AIAnalysisResult:
    analyzed_vulnerabilities: list[AnalyzedVulnerability]
    additional_findings: list[AnalyzedVulnerability]
    overall_risk_score: int
    overall_risk_level: str
    executive_summary: str
    top_priority_fixes: list[str]
    secure_code: str

SYSTEM_PROMPT = """First, identify the programming language of the provided code. You are a senior application security engineer. 
Return precise JSON analysis only. Ensure the 'recommendation' field is a one-sentence fix. 
Do not include any conversational text, only the JSON block."""

ANALYSIS_PROMPT_TEMPLATE = """Analyze this {language} source code.
SOURCE: {file_path}
CODE: {source_code}
FINDINGS: {scanner_findings}

Return JSON strictly in this format:
{{
  "analyzed_vulnerabilities": [],
  "additional_findings": [],
  "overall_risk_score": 0,
  "overall_risk_level": "Low",
  "executive_summary": "",
  "top_priority_fixes": [],
  "secure_code": ""
}}"""

class AISecurityAnalyzer:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY not set.")
        self.model = "openrouter/auto"

    def analyze(self, source_code, file_path, language, raw_vulns):
        prompt = self._build_prompt(source_code, file_path, language, raw_vulns)
        try:
            # 1. Get raw text from AI
            raw_response = self._call_ai(prompt)
            
            # 2. Extract JSON using Regex (Fixes the delimiter/char error)
            json_match = re.search(r'\{.*\}', raw_response, re.DOTALL)
            if json_match:
                clean_json = json_match.group(0)
                data = json.loads(clean_json)
            else:
                raise ValueError("AI response contained no valid JSON block.")

            return self._parse_response(data, file_path, language)
        except Exception as e:
            print(f"\n[!] AI Analysis failed: {e}")
            # Fallback to avoid '0 Score' on crash
            return self._get_empty_result(f"Analysis Error: {str(e)}")

    def _build_prompt(self, source_code, file_path, language, raw_vulns):
        findings = json.dumps([{"id": v.vuln_id, "line": v.line_number, "content": v.line_content} for v in raw_vulns])
        return ANALYSIS_PROMPT_TEMPLATE.format(
            language=language, file_path=file_path, source_code=source_code, scanner_findings=findings
        )

    def _call_ai(self, prompt: str) -> str:
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json={
                "model": self.model,
                "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}],
                "temperature": 0.1
            },
            timeout=60
        )
        if response.status_code != 200:
            raise RuntimeError(f"API Error {response.status_code}: {response.text}")

        result = response.json()
        return result["choices"][0]["message"]["content"].strip()

    def _parse_response(self, data, file_path, language):
        vulns_list = data.get("analyzed_vulnerabilities", [])
        
        # Determine score logic
        score = data.get("overall_risk_score")
        if score is None:
            score = 70 if vulns_list else 0

        def parse_v(v):
            return AnalyzedVulnerability(
                vuln_id="AI-VULN",
                category=v.get("category", "Security Flaw"),
                line_number=int(v.get("line_number", 0)),
                line_content=v.get("line_content", "Review code"),
                file_path=file_path,
                language=language,
                cwe_id="N/A", owasp_category="N/A",
                severity=v.get("severity", "High"),
                confidence="High",
                ai_explanation=v.get("explanation", "Potential security risk found."),
                exploit_scenario="",
                recommendation=v.get("recommendation", "Sanitize inputs and secure secrets."),
                secure_code_snippet="",
                false_positive_likelihood="Low"
            )

        return AIAnalysisResult(
            analyzed_vulnerabilities=[parse_v(v) for v in vulns_list],
            additional_findings=[],
            overall_risk_score=score,
            overall_risk_level=data.get("overall_risk_level", "High" if score > 50 else "Low"),
            executive_summary=data.get("executive_summary", "Audit finished."),
            top_priority_fixes=data.get("top_priority_fixes", []),
            secure_code=data.get("secure_code", "")
        )

    def _get_empty_result(self, msg):
        # Changed score to 50 to indicate a 'Warning' if analysis crashes
        return AIAnalysisResult([], [], 50, "Warning", msg, [], "")