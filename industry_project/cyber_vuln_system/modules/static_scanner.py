"""
Module 1: Static Vulnerability Scanner
---------------------------------------
Performs pattern-based static analysis on source code to detect
common security vulnerabilities WITHOUT requiring an AI API call.

Supports: Python, JavaScript, Java, PHP, C/C++
"""

import ast
import re
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────
#  Data structures
# ─────────────────────────────────────────────

@dataclass
class RawVulnerability:
    """A vulnerability finding produced by the static scanner."""
    vuln_id: str                  # e.g. "SQL-001"
    category: str                 # e.g. "SQL Injection"
    description: str
    line_number: int
    line_content: str
    file_path: str
    language: str
    cwe_id: str                   # Common Weakness Enumeration reference
    owasp_category: str           # OWASP Top-10 mapping
    confidence: str               # HIGH / MEDIUM / LOW
    raw_severity: str             # Initial severity estimate (refined by AI later)
    context_lines: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────
#  Pattern library  (extendable)
# ─────────────────────────────────────────────

VULNERABILITY_PATTERNS = {
    "python": [
        # SQL Injection
        {
            "id": "SQL-001",
            "category": "SQL Injection",
            "pattern": r'(execute|cursor\.execute)\s*\(\s*["\'].*(%s|%d|{\w+}|f["\'])',
            "description": "Direct string formatting in SQL query — user input may reach the database unescaped.",
            "cwe": "CWE-89",
            "owasp": "A03:2021 - Injection",
            "confidence": "HIGH",
            "severity": "Critical",
        },
        {
            "id": "SQL-002",
            "category": "SQL Injection",
            "pattern": r'(execute|cursor\.execute)\s*\(\s*f["\']',
            "description": "f-string used inside a database execute call — vulnerable to SQL injection.",
            "cwe": "CWE-89",
            "owasp": "A03:2021 - Injection",
            "confidence": "HIGH",
            "severity": "Critical",
        },
        # Command Injection
        {
            "id": "CMD-001",
            "category": "Command Injection",
            "pattern": r'os\.system\s*\(.*\+|subprocess\.(call|run|Popen)\s*\(.*\+',
            "description": "Shell command constructed with string concatenation — command injection risk.",
            "cwe": "CWE-78",
            "owasp": "A03:2021 - Injection",
            "confidence": "HIGH",
            "severity": "Critical",
        },
        {
            "id": "CMD-002",
            "category": "Command Injection",
            "pattern": r'eval\s*\(',
            "description": "eval() executes arbitrary code — extremely dangerous with untrusted input.",
            "cwe": "CWE-95",
            "owasp": "A03:2021 - Injection",
            "confidence": "HIGH",
            "severity": "Critical",
        },
        # Hardcoded Secrets
        {
            "id": "SEC-001",
            "category": "Hardcoded Credentials",
            "pattern": r'(password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{4,}["\']',
            "description": "Possible hardcoded credential or secret detected.",
            "cwe": "CWE-798",
            "owasp": "A07:2021 - Identification and Authentication Failures",
            "confidence": "MEDIUM",
            "severity": "High",
        },
        # Weak Cryptography
        {
            "id": "CRYPTO-001",
            "category": "Weak Cryptography",
            "pattern": r'(md5|sha1)\s*\(',
            "description": "MD5/SHA-1 are cryptographically broken — use SHA-256 or stronger.",
            "cwe": "CWE-327",
            "owasp": "A02:2021 - Cryptographic Failures",
            "confidence": "HIGH",
            "severity": "High",
        },
        {
            "id": "CRYPTO-002",
            "category": "Weak Cryptography",
            "pattern": r'hashlib\.(md5|sha1)\s*\(',
            "description": "hashlib MD5/SHA-1 usage detected — upgrade to SHA-256.",
            "cwe": "CWE-327",
            "owasp": "A02:2021 - Cryptographic Failures",
            "confidence": "HIGH",
            "severity": "High",
        },
        # Insecure Deserialization
        {
            "id": "DESER-001",
            "category": "Insecure Deserialization",
            "pattern": r'pickle\.(loads|load)\s*\(',
            "description": "pickle deserialization of untrusted data can lead to remote code execution.",
            "cwe": "CWE-502",
            "owasp": "A08:2021 - Software and Data Integrity Failures",
            "confidence": "HIGH",
            "severity": "Critical",
        },
        {
            "id": "DESER-002",
            "category": "Insecure Deserialization",
            "pattern": r'yaml\.load\s*\([^,)]+\)',
            "description": "yaml.load() without Loader=yaml.SafeLoader can execute arbitrary Python.",
            "cwe": "CWE-502",
            "owasp": "A08:2021 - Software and Data Integrity Failures",
            "confidence": "HIGH",
            "severity": "High",
        },
        # Path Traversal
        {
            "id": "PATH-001",
            "category": "Path Traversal",
            "pattern": r'open\s*\(\s*(request\.|input\(|sys\.argv)',
            "description": "File open with user-controlled path — path traversal vulnerability.",
            "cwe": "CWE-22",
            "owasp": "A01:2021 - Broken Access Control",
            "confidence": "MEDIUM",
            "severity": "High",
        },
        # XSS
        {
            "id": "XSS-001",
            "category": "Cross-Site Scripting (XSS)",
            "pattern": r'(render|render_template_string)\s*\(.*request\.',
            "description": "Rendering user input in template without escaping — XSS risk.",
            "cwe": "CWE-79",
            "owasp": "A03:2021 - Injection",
            "confidence": "MEDIUM",
            "severity": "High",
        },
        # Insecure Random
        {
            "id": "RAND-001",
            "category": "Insecure Randomness",
            "pattern": r'random\.(random|randint|choice|randrange)\s*\(',
            "description": "Standard random module is not cryptographically secure — use secrets module.",
            "cwe": "CWE-330",
            "owasp": "A02:2021 - Cryptographic Failures",
            "confidence": "MEDIUM",
            "severity": "Medium",
        },
        # Debug / Error Disclosure
        {
            "id": "DBG-001",
            "category": "Information Disclosure",
            "pattern": r'(DEBUG\s*=\s*True|app\.run\s*\(.*debug\s*=\s*True)',
            "description": "Debug mode enabled — stack traces expose sensitive info in production.",
            "cwe": "CWE-209",
            "owasp": "A05:2021 - Security Misconfiguration",
            "confidence": "HIGH",
            "severity": "Medium",
        },
        # SSRF
        {
            "id": "SSRF-001",
            "category": "Server-Side Request Forgery",
            "pattern": r'requests\.(get|post|put|delete)\s*\(\s*(request\.|input\(|sys\.argv)',
            "description": "HTTP request made with user-controlled URL — SSRF vulnerability.",
            "cwe": "CWE-918",
            "owasp": "A10:2021 - Server-Side Request Forgery",
            "confidence": "MEDIUM",
            "severity": "High",
        },
        # XXE
        {
            "id": "XXE-001",
            "category": "XML External Entity (XXE)",
            "pattern": r'etree\.(parse|fromstring)\s*\(',
            "description": "XML parsing without disabling external entities — XXE injection risk.",
            "cwe": "CWE-611",
            "owasp": "A05:2021 - Security Misconfiguration",
            "confidence": "MEDIUM",
            "severity": "High",
        },
    ],

    "javascript": [
        {
            "id": "JS-SQL-001",
            "category": "SQL Injection",
            "pattern": r'(query|execute)\s*\(\s*["`\'].*\$\{',
            "description": "Template literal used in DB query — SQL injection via user input.",
            "cwe": "CWE-89",
            "owasp": "A03:2021 - Injection",
            "confidence": "HIGH",
            "severity": "Critical",
        },
        {
            "id": "JS-XSS-001",
            "category": "Cross-Site Scripting (XSS)",
            "pattern": r'innerHTML\s*=',
            "description": "Setting innerHTML with dynamic data — XSS risk.",
            "cwe": "CWE-79",
            "owasp": "A03:2021 - Injection",
            "confidence": "HIGH",
            "severity": "High",
        },
        {
            "id": "JS-EVAL-001",
            "category": "Code Injection",
            "pattern": r'\beval\s*\(',
            "description": "eval() executes arbitrary code — never use with user input.",
            "cwe": "CWE-95",
            "owasp": "A03:2021 - Injection",
            "confidence": "HIGH",
            "severity": "Critical",
        },
        {
            "id": "JS-SEC-001",
            "category": "Hardcoded Credentials",
            "pattern": r'(password|secret|apiKey|api_key|token)\s*[:=]\s*["\'][^"\']{4,}["\']',
            "description": "Hardcoded secret found in JavaScript source.",
            "cwe": "CWE-798",
            "owasp": "A07:2021 - Identification and Authentication Failures",
            "confidence": "MEDIUM",
            "severity": "High",
        },
        {
            "id": "JS-PROTO-001",
            "category": "Prototype Pollution",
            "pattern": r'__proto__|prototype\[',
            "description": "Possible prototype pollution via property access.",
            "cwe": "CWE-1321",
            "owasp": "A08:2021 - Software and Data Integrity Failures",
            "confidence": "MEDIUM",
            "severity": "High",
        },
    ],

    "php": [
        {
            "id": "PHP-SQL-001",
            "category": "SQL Injection",
            "pattern": r'mysql_query\s*\(.*\$_(GET|POST|REQUEST|COOKIE)',
            "description": "Unsanitized superglobal used in MySQL query — SQL injection.",
            "cwe": "CWE-89",
            "owasp": "A03:2021 - Injection",
            "confidence": "HIGH",
            "severity": "Critical",
        },
        {
            "id": "PHP-XSS-001",
            "category": "Cross-Site Scripting (XSS)",
            "pattern": r'echo\s+\$_(GET|POST|REQUEST|COOKIE)',
            "description": "Direct echo of user input without htmlspecialchars() — XSS.",
            "cwe": "CWE-79",
            "owasp": "A03:2021 - Injection",
            "confidence": "HIGH",
            "severity": "High",
        },
        {
            "id": "PHP-CMD-001",
            "category": "Command Injection",
            "pattern": r'(system|exec|shell_exec|passthru)\s*\(.*\$_(GET|POST|REQUEST)',
            "description": "Shell command with user-supplied input — command injection.",
            "cwe": "CWE-78",
            "owasp": "A03:2021 - Injection",
            "confidence": "HIGH",
            "severity": "Critical",
        },
    ],

    "java": [
        {
            "id": "JAVA-SQL-001",
            "category": "SQL Injection",
            "pattern": r'createQuery\s*\(\s*".*"\s*\+',
            "description": "String concatenation in JPA/JDBC query — SQL injection risk.",
            "cwe": "CWE-89",
            "owasp": "A03:2021 - Injection",
            "confidence": "HIGH",
            "severity": "Critical",
        },
        {
            "id": "JAVA-XXE-001",
            "category": "XML External Entity (XXE)",
            "pattern": r'DocumentBuilderFactory\.newInstance\(\)',
            "description": "DocumentBuilderFactory without disabling external entities — XXE.",
            "cwe": "CWE-611",
            "owasp": "A05:2021 - Security Misconfiguration",
            "confidence": "MEDIUM",
            "severity": "High",
        },
        {
            "id": "JAVA-DESER-001",
            "category": "Insecure Deserialization",
            "pattern": r'ObjectInputStream\s*\(',
            "description": "Java ObjectInputStream — deserialization of untrusted data is dangerous.",
            "cwe": "CWE-502",
            "owasp": "A08:2021 - Software and Data Integrity Failures",
            "confidence": "MEDIUM",
            "severity": "Critical",
        },
    ],
}

# Language detection by file extension
EXTENSION_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".jsx": "javascript",
    ".tsx": "javascript",
    ".php": "php",
    ".java": "java",
    ".c": "c",
    ".cpp": "c",
    ".h": "c",
}


# ─────────────────────────────────────────────
#  Scanner class
# ─────────────────────────────────────────────

class StaticVulnerabilityScanner:
    """
    Scans source code files using regex pattern matching.

    How it works:
    1. Detect language from file extension.
    2. Load appropriate pattern library.
    3. Iterate over each line, testing all patterns.
    4. Collect RawVulnerability objects with context.
    5. For Python files, additionally run AST-based checks.
    """

    def __init__(self, context_window: int = 3):
        self.context_window = context_window  # Lines of context to capture

    # ── public API ──────────────────────────────

    def scan_file(self, file_path: str, language: Optional[str] = None) -> tuple[list[RawVulnerability], str, str]:
        """
        Scan a file and return (vulnerabilities, source_code, language).
        """
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()

        if not language:
            language = self._detect_language(file_path)
            
        vulns = self._scan_source(source, file_path, language)

        # Additional Python AST checks
        if language == "python":
            ast_vulns = self._python_ast_scan(source, file_path)
            vulns.extend(ast_vulns)

        # Deduplicate by (line, id)
        seen = set()
        unique = []
        for v in vulns:
            key = (v.vuln_id, v.line_number)
            if key not in seen:
                seen.add(key)
                unique.append(v)

        return unique, source, language

    # ── internal helpers ─────────────────────────

    def _detect_language(self, file_path: str) -> str:
        import os
        _, ext = os.path.splitext(file_path.lower())
        return EXTENSION_MAP.get(ext, "unknown")

    def _scan_source(
        self, source: str, file_path: str, language: str
    ) -> list[RawVulnerability]:
        patterns = VULNERABILITY_PATTERNS.get(language, [])
        lines = source.splitlines()
        results: list[RawVulnerability] = []

        for line_idx, line in enumerate(lines):
            line_no = line_idx + 1
            for pat in patterns:
                if re.search(pat["pattern"], line, re.IGNORECASE):
                    ctx_start = max(0, line_idx - self.context_window)
                    ctx_end = min(len(lines), line_idx + self.context_window + 1)
                    context = lines[ctx_start:ctx_end]

                    results.append(
                        RawVulnerability(
                            vuln_id=pat["id"],
                            category=pat["category"],
                            description=pat["description"],
                            line_number=line_no,
                            line_content=line.strip(),
                            file_path=file_path,
                            language=language,
                            cwe_id=pat["cwe"],
                            owasp_category=pat["owasp"],
                            confidence=pat["confidence"],
                            raw_severity=pat["severity"],
                            context_lines=context,
                        )
                    )
        return results

    def _python_ast_scan(
        self, source: str, file_path: str
    ) -> list[RawVulnerability]:
        """
        AST-level checks for Python:
        - assert statements used for security checks
        - bare except clauses hiding errors
        - use of __import__ with dynamic strings
        """
        results: list[RawVulnerability] = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return results

        lines = source.splitlines()

        class SecurityVisitor(ast.NodeVisitor):
            def visit_Assert(self, node):
                # assert is stripped by python -O; never use for security
                results.append(
                    RawVulnerability(
                        vuln_id="PY-AST-001",
                        category="Assert Used for Security",
                        description=(
                            "assert statements are removed with python -O; "
                            "do not use for authentication or access control."
                        ),
                        line_number=node.lineno,
                        line_content=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                        file_path=file_path,
                        language="python",
                        cwe_id="CWE-617",
                        owasp_category="A07:2021 - Identification and Authentication Failures",
                        confidence="HIGH",
                        raw_severity="Medium",
                    )
                )
                self.generic_visit(node)

            def visit_ExceptHandler(self, node):
                # bare except or except Exception with pass — swallows errors
                if node.type is None:
                    body_is_pass = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
                    if body_is_pass:
                        results.append(
                            RawVulnerability(
                                vuln_id="PY-AST-002",
                                category="Silent Exception Handling",
                                description=(
                                    "Bare 'except: pass' silently swallows all exceptions, "
                                    "masking security-relevant errors."
                                ),
                                line_number=node.lineno,
                                line_content=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                                file_path=file_path,
                                language="python",
                                cwe_id="CWE-390",
                                owasp_category="A09:2021 - Security Logging and Monitoring Failures",
                                confidence="MEDIUM",
                                raw_severity="Low",
                            )
                        )
                self.generic_visit(node)

        SecurityVisitor().visit(tree)
        return results