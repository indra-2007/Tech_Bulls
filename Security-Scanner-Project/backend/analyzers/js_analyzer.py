"""JavaScript / Text Analyzer
Analyzes JavaScript, HTML, CSS, JSON, and other text-based files.
Scans for API keys, secrets, code injection patterns, and security issues.
"""

import re
from typing import List, Dict
from analyzers.unified_rules import UnifiedRuleEngine


class JSAnalyzer:
    """Analyzes JavaScript and text-based files"""

    # JS/Web-specific patterns beyond the unified rules
    JS_PATTERNS = {
        'CRITICAL': {
            'eval() Code Execution': (
                r'\beval\s*\([^\)]*\)',
                'eval() executes arbitrary code. Major injection risk.',
                'Replace eval() with JSON.parse(), Function(), or template literals.',
            ),
            'innerHTML XSS': (
                r'\.innerHTML\s*=\s*(?![\'"]\s*[\'"])',
                'Direct innerHTML assignment. Cross-site scripting (XSS) risk.',
                'Use textContent or DOMPurify.sanitize() instead.',
            ),
            'document.write()': (
                r'document\.write\s*\(',
                'document.write() can inject arbitrary HTML. XSS risk.',
                'Use DOM manipulation APIs (createElement, appendChild) instead.',
            ),
            'Hardcoded JWT': (
                r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
                'JWT token hardcoded in file. Can be decoded to extract claims.',
                'Never hardcode JWTs. Generate server-side and use secure storage.',
            ),
        },
        'HIGH': {
            'Firebase Config Exposed': (
                r'(?:apiKey|authDomain|databaseURL|projectId|storageBucket|messagingSenderId|appId)\s*:\s*[\'"][^\'"]+[\'"]',
                'Firebase configuration exposed. Could allow unauthorized access.',
                'Move Firebase config to server-side. Restrict API keys in Firebase Console.',
            ),
            'Outgoing Fetch/XHR': (
                r'(?:fetch|XMLHttpRequest|axios|\.ajax)\s*\(\s*[\'"]http://[^\'"]+',
                'HTTP request to insecure endpoint detected.',
                'Use HTTPS for all API calls.',
            ),
            'Cookie Without Flags': (
                r'document\.cookie\s*=(?!.*(?:secure|httponly|samesite))',
                'Cookie set without security flags.',
                'Set Secure, HttpOnly, and SameSite flags on all cookies.',
            ),
            'localStorage for Sensitive Data': (
                r'localStorage\.setItem\s*\(\s*[\'"](?:token|password|secret|key|auth|session)',
                'Sensitive data stored in localStorage. Accessible to any script on the page.',
                'Use sessionStorage or HTTP-only cookies for sensitive data.',
            ),
            'Unsafe Regex': (
                r'new\s+RegExp\s*\(\s*(?:req|params|query|body|input|user)',
                'RegExp construction from user input. ReDoS attack risk.',
                'Validate and sanitize input before using in RegExp.',
            ),
        },
        'MEDIUM': {
            'Console.log with Data': (
                r'console\.log\s*\(.*(?:password|token|secret|key|auth|credential)',
                'Sensitive data may be logged to console.',
                'Remove console.log calls with sensitive data in production.',
            ),
            'Inline Event Handlers': (
                r'on(?:click|load|error|mouseover|submit|focus)\s*=\s*[\'"]',
                'Inline event handlers in HTML. May indicate XSS vectors.',
                'Use addEventListener() instead of inline handlers.',
            ),
            'postMessage without Origin Check': (
                r'window\.addEventListener\s*\(\s*[\'"]message[\'"](?!.*origin)',
                'postMessage listener without origin verification.',
                'Always verify event.origin in postMessage handlers.',
            ),
            'Hardcoded URL': (
                r'(?:https?://[a-zA-Z0-9][\w\-]*\.(?:com|io|net|org|dev|app|co)(?:/[^\s\'"]*)?)',
                'Hardcoded URL detected.',
                'Use environment variables for API endpoints.',
            ),
        },
    }

    # HTML-specific patterns
    HTML_PATTERNS = {
        'Inline Script': (
            r'<script\b[^>]*>(?![\s]*</script>)[\s\S]*?</script>',
            'HIGH',
            'Inline script block found. XSS risk if content is user-controlled.',
            'Use external script files with Content-Security-Policy.',
        ),
        'Insecure Form Action': (
            r'<form[^>]*action\s*=\s*[\'"]http://[^\'"]+[\'"]',
            'HIGH',
            'Form submits data over insecure HTTP.',
            'Use HTTPS for all form actions.',
        ),
        'External Resource HTTP': (
            r'(?:src|href)\s*=\s*[\'"]http://[^\'"]+[\'"]',
            'MEDIUM',
            'External resource loaded over HTTP. Mixed content risk.',
            'Use HTTPS for all external resources.',
        ),
        'Missing CSP Meta': (
            r'<meta[^>]*content-security-policy',
            'LOW',
            'Content-Security-Policy meta tag detected.',
            'Ensure CSP is properly configured.',
        ),
        'iframe without sandbox': (
            r'<iframe\b(?![^>]*sandbox)[^>]*>',
            'MEDIUM',
            'iframe without sandbox attribute. Could load malicious content.',
            'Add sandbox attribute to iframes.',
        ),
    }

    def analyze(self, file_path: str, file_type: str = 'JS') -> dict:
        """Full JS/text analysis pipeline"""
        all_findings = {}

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except Exception as e:
            return self._error_result(f'Cannot read file: {e}')

        filename = file_path.rsplit('/', 1)[-1].lower()

        # ── File Info ─────────────────────────────────────────────
        line_count = content.count('\n') + 1
        all_findings['File Info'] = {
            'category': 'File Info',
            'total_found': 1,
            'findings': [{
                'type': 'File Summary',
                'severity': 'LOW',
                'value': f'{file_type} file, {line_count} lines, {len(content)} characters',
                'source': file_type,
                'description': f'{file_type} file with {line_count} lines.',
                'recommendation': 'Review file for security issues.',
            }],
            'severity': 'LOW',
            'description': f'{file_type} file: {line_count} lines.',
        }

        # ── JS-specific patterns ──────────────────────────────────
        if file_type in ('JS', 'HTML', 'JSON'):
            try:
                js_findings = self._run_js_patterns(content)
                if js_findings['total_found'] > 0:
                    all_findings['JavaScript Security'] = js_findings
            except Exception as e:
                print(f'[!] JS pattern error: {e}')

        # ── HTML-specific patterns ────────────────────────────────
        if file_type in ('HTML', 'HTML'):
            try:
                html_findings = self._run_html_patterns(content)
                if html_findings['total_found'] > 0:
                    all_findings['HTML Security'] = html_findings
            except Exception as e:
                print(f'[!] HTML pattern error: {e}')

        # ── Minification/obfuscation detection ────────────────────
        try:
            obf_findings = self._detect_obfuscation(content, file_type)
            if obf_findings['total_found'] > 0:
                all_findings['Obfuscation Detection'] = obf_findings
        except Exception as e:
            print(f'[!] Obfuscation detection error: {e}')

        # ── Run unified rule engine ───────────────────────────────
        rule_findings = UnifiedRuleEngine.scan(
            content, file_type, 'source code'
        )
        all_findings.update(rule_findings)

        return all_findings

    def _run_js_patterns(self, content: str) -> dict:
        """Run JavaScript-specific patterns"""
        findings = []
        seen = set()

        for severity, patterns in self.JS_PATTERNS.items():
            for name, (pattern, desc, rec) in patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in set(matches[:5]):
                    dedup_key = (name, str(match)[:50])
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    findings.append({
                        'type': name,
                        'severity': severity,
                        'value': str(match)[:100],
                        'source': 'JS',
                        'description': desc,
                        'recommendation': rec,
                    })

        severities = [f['severity'] for f in findings]
        overall = 'SAFE'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'JavaScript Security',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'JavaScript security analysis: {len(findings)} finding(s).',
        }

    def _run_html_patterns(self, content: str) -> dict:
        """Run HTML-specific patterns"""
        findings = []
        seen = set()

        for name, (pattern, severity, desc, rec) in self.HTML_PATTERNS.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches and name not in seen:
                seen.add(name)
                findings.append({
                    'type': name,
                    'severity': severity,
                    'value': str(matches[0])[:100] if matches[0] else name,
                    'source': 'HTML',
                    'description': desc,
                    'recommendation': rec,
                })

        severities = [f['severity'] for f in findings]
        overall = 'SAFE'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'HTML Security',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'HTML security analysis: {len(findings)} finding(s).',
        }

    def _detect_obfuscation(self, content: str, file_type: str) -> dict:
        """Detect minified or obfuscated code"""
        findings = []

        if file_type not in ('JS', 'CSS'):
            return {'category': 'Obfuscation Detection', 'total_found': 0, 'findings': [], 'severity': 'SAFE', 'description': 'N/A.'}

        lines = content.split('\n')
        if not lines:
            return {'category': 'Obfuscation Detection', 'total_found': 0, 'findings': [], 'severity': 'SAFE', 'description': 'Empty file.'}

        # Check for minification (very long lines)
        max_line_length = max(len(line) for line in lines)
        avg_line_length = sum(len(line) for line in lines) / len(lines) if lines else 0

        if max_line_length > 5000 and len(lines) < 20:
            findings.append({
                'type': 'Minified Code',
                'severity': 'LOW',
                'value': f'Max line: {max_line_length} chars, {len(lines)} lines',
                'source': file_type,
                'description': 'Code appears to be minified. Analysis may miss some patterns.',
                'recommendation': 'Use source maps or beautified version for full analysis.',
            })

        # Check for obfuscation patterns
        hex_escape_count = len(re.findall(r'\\x[0-9a-fA-F]{2}', content))
        unicode_escape_count = len(re.findall(r'\\u[0-9a-fA-F]{4}', content))

        if hex_escape_count > 50 or unicode_escape_count > 50:
            findings.append({
                'type': 'Obfuscated Code',
                'severity': 'HIGH',
                'value': f'{hex_escape_count} hex escapes, {unicode_escape_count} unicode escapes',
                'source': file_type,
                'description': 'Heavy use of escape sequences indicates code obfuscation.',
                'recommendation': 'Deobfuscate code and review for malicious functionality.',
            })

        # Check for constructor-based execution (common obfuscation)
        if re.search(r'\[\s*[\'"]constructor[\'"]\s*\]', content):
            findings.append({
                'type': 'Constructor-based Execution',
                'severity': 'HIGH',
                'value': '[constructor] pattern detected',
                'source': file_type,
                'description': 'Constructor-based code execution. Common obfuscation technique.',
                'recommendation': 'Deobfuscate and review for malicious intent.',
            })

        severities = [f['severity'] for f in findings]
        overall = 'SAFE'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'Obfuscation Detection',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Obfuscation detection: {len(findings)} indicator(s).',
        }

    def _error_result(self, msg: str) -> dict:
        return {
            'JS Analysis Error': {
                'category': 'JS Analysis Error',
                'total_found': 1,
                'findings': [{
                    'type': 'Analysis Error',
                    'severity': 'MEDIUM',
                    'value': msg,
                    'source': 'JS',
                    'description': msg,
                    'recommendation': 'Ensure the file is readable.',
                }],
                'severity': 'MEDIUM',
                'description': msg,
            }
        }
