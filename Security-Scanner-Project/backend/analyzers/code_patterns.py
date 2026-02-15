"""Code Pattern Vulnerability Detector
Analyzes DEX method references and strings for:
- Weak cryptography (MD5, SHA1, DES, 3DES, RC4, ECB)
- Insecure randomness (java.util.Random in security context)
- WebView risks (addJavascriptInterface, setJavaScriptEnabled, setAllowFileAccess)
- SSL misconfiguration (TrustManager override, HostnameVerifier, disabled pinning)
- Sensitive data logging (Log.* with password/token/secret)
- Debug flags (BuildConfig.DEBUG, debuggable)
- Cleartext HTTP URLs
"""

import re
from typing import List, Dict


class CodePatternAnalyzer:
    """Detects code-level vulnerability patterns in DEX data"""

    # ── Weak Cryptography ─────────────────────────────────────────────
    WEAK_CRYPTO_CLASSES = {
        'java.security.MessageDigest': {
            'patterns': ['MD5', 'SHA-1', 'SHA1'],
            'severity': 'HIGH',
            'description': 'Weak hash algorithm. MD5 and SHA-1 are vulnerable to collision attacks.',
            'recommendation': 'Use SHA-256, SHA-384, or SHA-512 for hashing.',
        },
        'javax.crypto.Cipher': {
            'patterns': ['DES', '3DES', 'DESede', 'RC4', 'ARC4', 'Blowfish'],
            'severity': 'HIGH',
            'description': 'Weak encryption algorithm with known vulnerabilities.',
            'recommendation': 'Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption.',
        },
        'ECB': {
            'patterns': ['ECB', '/ECB/'],
            'severity': 'HIGH',
            'description': 'ECB mode does not provide semantic security. Identical plaintext blocks produce identical ciphertext.',
            'recommendation': 'Use CBC, CTR, or GCM mode instead of ECB.',
        },
    }

    WEAK_CRYPTO_STRINGS = [
        ('MD5', 'HIGH', 'Weak Hash: MD5', 'MD5 is cryptographically broken. Use SHA-256 or higher.'),
        ('SHA-1', 'HIGH', 'Weak Hash: SHA-1', 'SHA-1 is deprecated. Use SHA-256 or higher.'),
        ('SHA1', 'HIGH', 'Weak Hash: SHA1', 'SHA-1 is deprecated. Use SHA-256 or higher.'),
        ('DES', 'HIGH', 'Weak Cipher: DES', 'DES uses a 56-bit key and is easily brute-forced. Use AES-256.'),
        ('3DES', 'HIGH', 'Weak Cipher: 3DES', '3DES is deprecated. Use AES-256.'),
        ('DESede', 'HIGH', 'Weak Cipher: Triple DES', 'Triple DES is slow and deprecated. Use AES-256.'),
        ('RC4', 'CRITICAL', 'Weak Cipher: RC4', 'RC4 has critical biases. Use AES-GCM or ChaCha20.'),
        ('ECB', 'HIGH', 'Weak Mode: ECB', 'ECB mode leaks patterns. Use GCM or CBC mode.'),
        ('Blowfish', 'MEDIUM', 'Weak Cipher: Blowfish', 'Blowfish has a 64-bit block size. Use AES-256.'),
    ]

    # ── Insecure Randomness ───────────────────────────────────────────
    INSECURE_RANDOM_PATTERNS = [
        (r'java\.util\.Random', 'Insecure Random', 'HIGH',
         'java.util.Random is predictable and must not be used for security purposes (tokens, keys, nonces).',
         'Use java.security.SecureRandom for all security-sensitive random number generation.'),
        (r'Math\.random\(\)', 'Insecure Random (Math.random)', 'HIGH',
         'Math.random() is not cryptographically secure.',
         'Use SecureRandom for security-sensitive operations.'),
    ]

    # ── WebView Risks ─────────────────────────────────────────────────
    WEBVIEW_PATTERNS = [
        (r'addJavascriptInterface', 'WebView JavaScript Interface', 'HIGH',
         'addJavascriptInterface exposes Java objects to JavaScript. On Android < 4.2, this allows arbitrary code execution.',
         'Remove addJavascriptInterface or restrict to API level 17+ with @JavascriptInterface annotation.'),
        (r'setJavaScriptEnabled\s*\(\s*true\s*\)', 'WebView JavaScript Enabled', 'MEDIUM',
         'JavaScript is enabled in WebView, increasing XSS attack surface.',
         'Only enable JavaScript when strictly necessary. Validate all content loaded into WebViews.'),
        (r'setAllowFileAccess\s*\(\s*true\s*\)', 'WebView File Access Enabled', 'HIGH',
         'WebView can access local files, potentially leaking sensitive data.',
         'Set setAllowFileAccess(false) unless file access is absolutely required.'),
        (r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)', 'WebView Universal File Access', 'CRITICAL',
         'WebView allows file:// URLs to access content from any origin, enabling data theft.',
         'Never enable universal access from file URLs.'),
        (r'setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)', 'WebView Cross-File Access', 'HIGH',
         'WebView allows file:// URLs to access other file:// URLs.',
         'Disable file access from file URLs.'),
        (r'loadUrl\s*\(\s*["\']file://', 'WebView Loading Local File', 'MEDIUM',
         'WebView loads content from local file system.',
         'Validate file paths and ensure no user-controlled input reaches loadUrl.'),
    ]

    # ── SSL Misconfiguration ──────────────────────────────────────────
    SSL_PATTERNS = [
        (r'TrustManager', 'Custom TrustManager', 'CRITICAL',
         'Custom TrustManager detected. May accept all certificates, enabling MITM attacks.',
         'Never implement a TrustManager that trusts all certificates. Use the default system TrustManager.'),
        (r'X509TrustManager', 'Custom X509TrustManager', 'CRITICAL',
         'Custom X509TrustManager detected. This often disables certificate validation.',
         'Use the default X509TrustManager. If custom validation is needed, implement proper chain verification.'),
        (r'HostnameVerifier', 'Custom HostnameVerifier', 'CRITICAL',
         'Custom HostnameVerifier detected. May bypass hostname verification, enabling MITM attacks.',
         'Use the default HostnameVerifier. Never return true for all hostnames.'),
        (r'ALLOW_ALL_HOSTNAME_VERIFIER', 'Disabled Hostname Verification', 'CRITICAL',
         'Hostname verification is completely disabled.',
         'Remove ALLOW_ALL_HOSTNAME_VERIFIER. Use strict hostname verification.'),
        (r'SSLSocketFactory', 'Custom SSLSocketFactory', 'HIGH',
         'Custom SSLSocketFactory may disable SSL/TLS protections.',
         'Verify the custom SSLSocketFactory properly validates certificates.'),
        (r'setSSLSocketFactory', 'Custom SSL Socket Configuration', 'HIGH',
         'Custom SSL socket factory is being set, which may weaken TLS security.',
         'Ensure the custom SSL configuration maintains proper certificate validation.'),
        (r'checkServerTrusted', 'Server Trust Override', 'HIGH',
         'checkServerTrusted implementation detected. Empty implementation disables certificate checking.',
         'Ensure checkServerTrusted properly validates the certificate chain.'),
        (r'onReceivedSslError.*proceed', 'SSL Error Bypass in WebView', 'CRITICAL',
         'WebView SSL errors are being ignored, allowing connections to invalid certificates.',
         'Never call handler.proceed() in onReceivedSslError. Show an error to the user instead.'),
    ]

    # ── Sensitive Logging ─────────────────────────────────────────────
    SENSITIVE_LOG_KEYWORDS = ['password', 'token', 'secret', 'key', 'auth', 'credential', 'session', 'cookie', 'pin']

    # ── HTTP URL Pattern ──────────────────────────────────────────────
    HTTP_URL_PATTERN = r'http://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]+'

    def analyze(self, apk_result) -> dict:
        """
        Analyze DEX strings and method references for vulnerability patterns.

        Args:
            apk_result: APKParseResult from apk_parser

        Returns:
            dict with findings
        """
        findings = []

        dex_contexts = apk_result.dex_string_contexts
        all_text = apk_result.get_all_scannable_text()

        # 1. Weak Cryptography
        findings.extend(self._check_weak_crypto(dex_contexts, all_text))

        # 2. Insecure Randomness
        findings.extend(self._check_patterns(all_text, self.INSECURE_RANDOM_PATTERNS))

        # 3. WebView Risks
        findings.extend(self._check_patterns(all_text, self.WEBVIEW_PATTERNS))

        # 4. SSL Misconfiguration
        findings.extend(self._check_patterns(all_text, self.SSL_PATTERNS))

        # 5. Sensitive Data Logging
        findings.extend(self._check_sensitive_logging(dex_contexts))

        # 6. Cleartext HTTP URLs
        findings.extend(self._check_cleartext_urls(dex_contexts))

        # 7. Debug Flags
        findings.extend(self._check_debug_flags(dex_contexts, all_text))

        # Deduplicate
        findings = self._deduplicate(findings)

        return self._format_result(findings)

    def _check_weak_crypto(self, dex_contexts: List[Dict], all_text: str) -> List[Dict]:
        """Detect weak cryptographic algorithms"""
        findings = []
        found_algos = set()

        for algo, severity, issue_type, recommendation in self.WEAK_CRYPTO_STRINGS:
            # Search in DEX strings with context
            for ctx in dex_contexts:
                val = ctx['value']
                if algo in val:
                    # Avoid matching substrings like "SHA-256" when looking for "SHA-1"
                    if algo == 'SHA-1' and 'SHA-1' not in val:
                        continue
                    if algo == 'DES' and ('3DES' in val or 'DESede' in val or 'DES3' in val):
                        continue

                    if algo not in found_algos:
                        found_algos.add(algo)
                        findings.append({
                            'type': issue_type,
                            'severity': severity,
                            'value': algo,
                            'source': 'DEX',
                            'class_name': ctx.get('class_name'),
                            'method_name': ctx.get('method_name'),
                            'context': f"Class: {ctx.get('class_name', 'N/A')}, Method: {ctx.get('method_name', 'N/A')}",
                            'description': f'Weak cryptographic algorithm "{algo}" detected. {self.WEAK_CRYPTO_STRINGS[[x[0] for x in self.WEAK_CRYPTO_STRINGS].index(algo)][3] if algo in [x[0] for x in self.WEAK_CRYPTO_STRINGS] else ""}',
                            'recommendation': recommendation,
                        })
                        break  # Found this algo, move to next

        return findings

    def _check_patterns(self, text: str, patterns: list) -> List[Dict]:
        """Generic pattern checker against combined text"""
        findings = []
        for regex, issue_type, severity, description, recommendation in patterns:
            matches = re.finditer(regex, text, re.IGNORECASE)
            found = False
            for match in matches:
                if not found:
                    findings.append({
                        'type': issue_type,
                        'severity': severity,
                        'value': match.group()[:80],
                        'source': 'DEX',
                        'description': description,
                        'recommendation': recommendation,
                    })
                    found = True
        return findings

    def _check_sensitive_logging(self, dex_contexts: List[Dict]) -> List[Dict]:
        """Detect logging of sensitive data"""
        findings = []
        log_patterns = [
            r'Log\.[dviwe]\s*\(',
            r'System\.out\.println\s*\(',
            r'System\.err\.println\s*\(',
            r'android\.util\.Log',
        ]

        for ctx in dex_contexts:
            val = ctx['value'].lower()
            for keyword in self.SENSITIVE_LOG_KEYWORDS:
                if keyword in val:
                    # Check if it's in a logging context
                    for log_pat in log_patterns:
                        if re.search(log_pat, ctx['value'], re.IGNORECASE):
                            findings.append({
                                'type': f'Sensitive Data in Logs',
                                'severity': 'HIGH',
                                'value': f'Log statement containing "{keyword}"',
                                'source': 'DEX',
                                'class_name': ctx.get('class_name'),
                                'method_name': ctx.get('method_name'),
                                'context': f"Class: {ctx.get('class_name', 'N/A')}, keyword: {keyword}",
                                'description': f'Log statement potentially logging sensitive data ("{keyword}"). Logs can be read by any app with READ_LOGS permission.',
                                'recommendation': 'Remove or redact sensitive data from log statements. Use ProGuard to strip Log calls in release builds.',
                            })
                            break
                    break

        return findings

    def _check_cleartext_urls(self, dex_contexts: List[Dict]) -> List[Dict]:
        """Detect HTTP URLs (insecure cleartext transmission)"""
        findings = []
        found_urls = set()

        for ctx in dex_contexts:
            matches = re.finditer(self.HTTP_URL_PATTERN, ctx['value'])
            for match in matches:
                url = match.group()
                # Skip localhost (low severity, handled separately)
                if 'localhost' in url or '127.0.0.1' in url:
                    continue
                # Skip schema.org and XML namespaces
                if 'schema.org' in url or 'schemas.android.com' in url or 'www.w3.org' in url:
                    continue
                if 'xmlpull.org' in url or 'xml.org' in url:
                    continue

                if url not in found_urls:
                    found_urls.add(url)
                    findings.append({
                        'type': 'Cleartext HTTP URL',
                        'severity': 'HIGH',
                        'value': url[:100],
                        'source': 'DEX',
                        'class_name': ctx.get('class_name'),
                        'method_name': ctx.get('method_name'),
                        'context': f"Class: {ctx.get('class_name', 'N/A')}",
                        'description': 'Cleartext HTTP URL detected. Data transmitted over HTTP can be intercepted via man-in-the-middle attacks.',
                        'recommendation': 'Replace HTTP with HTTPS. Configure Network Security Config to block cleartext traffic.',
                    })

        return findings

    def _check_debug_flags(self, dex_contexts: List[Dict], all_text: str) -> List[Dict]:
        """Detect debug flags and development artifacts"""
        findings = []

        debug_patterns = [
            (r'BuildConfig\.DEBUG', 'BuildConfig.DEBUG Reference', 'MEDIUM',
             'BuildConfig.DEBUG is referenced. Ensure debug-only code paths are not reachable in release.',
             'Use ProGuard/R8 to strip debug code. Verify BuildConfig.DEBUG is false in release builds.'),
            (r'DEBUG\s*=\s*(?:true|True|1)', 'Debug Flag Enabled', 'HIGH',
             'Debug mode flag is set to true. This may expose verbose logging and development endpoints.',
             'Set DEBUG to false in production builds.'),
            (r'StrictMode', 'StrictMode Active', 'LOW',
             'StrictMode is referenced, which is a development tool.',
             'Remove StrictMode from production code as it impacts performance.'),
        ]

        for regex, issue_type, severity, description, recommendation in debug_patterns:
            if re.search(regex, all_text, re.IGNORECASE):
                findings.append({
                    'type': issue_type,
                    'severity': severity,
                    'value': issue_type,
                    'source': 'DEX',
                    'description': description,
                    'recommendation': recommendation,
                })

        return findings

    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        seen = set()
        unique = []
        for f in findings:
            key = (f['type'], f.get('value', ''))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _format_result(self, findings: List[Dict]) -> dict:
        severities = [f['severity'] for f in findings]
        overall = 'SAFE'
        if 'CRITICAL' in severities:
            overall = 'CRITICAL'
        elif 'HIGH' in severities:
            overall = 'HIGH'
        elif 'MEDIUM' in severities:
            overall = 'MEDIUM'
        elif 'LOW' in severities:
            overall = 'LOW'

        return {
            'category': 'Code Vulnerabilities',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Found {len(findings)} code-level vulnerability pattern(s) including crypto, WebView, SSL, and logging issues.'
        }
