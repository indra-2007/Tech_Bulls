"""Hardcoded Secret Detector
Detects API keys, credentials, tokens, cloud endpoints, PII, and sensitive
configuration in DEX strings and resource files.
Each match includes exact string, source (DEX/resource), class name, method name.
"""

import re
from typing import List, Dict


class SecretDetector:
    """Detects hardcoded secrets in structured DEX strings and resources"""

    # ── Cloud & API Key Patterns ──────────────────────────────────────
    API_KEY_PATTERNS = {
        # AWS
        'AWS Access Key': r'AKIA[0-9A-Z]{16}',
        'AWS Secret Key': r'(?:aws)?(?:.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]',
        # Google
        'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
        'Google OAuth Client ID': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        # Firebase
        'Firebase URL': r'https://[a-zA-Z0-9\-]+\.firebaseio\.com',
        'Firebase Storage': r'https://firebasestorage\.googleapis\.com/[^\s\'"]+',
        # Azure
        'Azure Storage Endpoint': r'https://[a-zA-Z0-9\-]+\.blob\.core\.windows\.net',
        'Azure Connection String': r'DefaultEndpointsProtocol=https;.*?(?:AccountKey|SharedAccessSignature)=[^\s\'"]+',
        # AWS S3
        'S3 Bucket URL': r'(?:https?://)?[a-zA-Z0-9.\-]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com',
        'S3 URI': r's3://[a-zA-Z0-9.\-_]+',
        # Google Cloud Storage
        'GCS Bucket URL': r'https?://storage\.googleapis\.com/[a-zA-Z0-9.\-_]+',
        'GCS URI': r'gs://[a-zA-Z0-9.\-_]+',
        # GitHub
        'GitHub Personal Access Token': r'ghp_[0-9a-zA-Z]{36}',
        'GitHub OAuth Token': r'gho_[0-9a-zA-Z]{36}',
        'GitHub App Token': r'(?:ghu|ghs)_[0-9a-zA-Z]{36}',
        'GitHub Refresh Token': r'ghr_[0-9a-zA-Z]{76}',
        # GitLab
        'GitLab PAT': r'glpat-[0-9a-zA-Z\-_]{20}',
        # Stripe
        'Stripe Secret Key': r'sk_(?:live|test)_[0-9a-zA-Z]{24,}',
        'Stripe Publishable Key': r'pk_(?:live|test)_[0-9a-zA-Z]{24,}',
        # Slack
        'Slack Token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}',
        'Slack Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
        # Twilio
        'Twilio API Key': r'SK[a-z0-9]{32}',
        # SendGrid
        'SendGrid API Key': r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',
        # OpenAI
        'OpenAI API Key': r'sk-[a-zA-Z0-9]{48}',
        # Shopify
        'Shopify Access Token': r'shpat_[a-fA-F0-9]{32}',
    }

    # ── Auth Token Patterns ───────────────────────────────────────────
    TOKEN_PATTERNS = {
        'JWT Token': r'eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*',
        'Bearer Token': r'[Bb]earer\s+[A-Za-z0-9\-_\.~\+\/]+=*',
        'OAuth Client Secret': r'(?:client_secret|CLIENT_SECRET)\s*[:=]\s*[\'"][a-zA-Z0-9\-_]{20,}[\'"]',
        'Generic API Key': r'(?:api[_-]?key|apikey)\s*[:=]\s*[\'"][a-zA-Z0-9\-_]{20,}[\'"]',
        'Generic Secret': r'(?:secret|SECRET)\s*[:=]\s*[\'"][a-zA-Z0-9\-_]{20,}[\'"]',
        'Generic Token': r'(?:token|TOKEN)\s*[:=]\s*[\'"][a-zA-Z0-9\-_]{20,}[\'"]',
    }

    # ── Credential Patterns ───────────────────────────────────────────
    CREDENTIAL_PATTERNS = {
        'Hardcoded Password': r'(?:password|passwd|pwd)\s*[:=]\s*[\'"][^\'"]{4,}[\'"]',
        'Hardcoded Username': r'(?:username|user_name|userId|user_id)\s*[:=]\s*[\'"][^\'"]{3,}[\'"]',
        'Admin Password': r'(?:admin_password|admin_pass|root_password|root_pass)\s*[:=]\s*[\'"][^\'"]{4,}[\'"]',
        'Admin Flag': r'(?:is_admin|isAdmin|admin_mode|adminMode)\s*[:=]\s*(?:true|True|1)',
        'Database Password': r'(?:db_password|db_pass|database_password|DB_PASSWORD)\s*[:=]\s*[\'"][^\'"]{4,}[\'"]',
        'Database URL': r'(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|mssql|sqlserver)://[^\s\'"]+',
        'Private Key': r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
        'Auth Credentials': r'(?:auth|AUTH)\s*[:=]\s*[\'"][^\'"]{4,}[\'"]',
    }

    # ── PII Patterns ──────────────────────────────────────────────────
    PII_PATTERNS = {
        'Email Address': r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b',
        'Private IP Address (10.x)': r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        'Private IP Address (172.x)': r'\b172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b',
        'Private IP Address (192.168.x)': r'\b192\.168\.\d{1,3}\.\d{1,3}\b',
        'Phone Number Pattern': r'(?:\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
    }

    # ── Sensitive Config ──────────────────────────────────────────────
    CONFIG_PATTERNS = {
        'Debug URL': r'https?://(?:debug|staging|dev|test|qa|uat)\.[a-zA-Z0-9.\-]+',
        'Localhost URL': r'https?://(?:localhost|127\.0\.0\.1)(?::\d+)?(?:/[^\s\'"]*)?',
        'Internal Domain': r'\b[a-zA-Z0-9\-]+\.(?:local|internal|intranet|corp)\b',
        'Staging Domain': r'\b(?:staging|stage|dev|test)\.[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b',
    }

    def analyze(self, apk_result) -> dict:
        """
        Scan DEX strings and resources for hardcoded secrets.

        Args:
            apk_result: APKParseResult from apk_parser

        Returns:
            dict with findings
        """
        findings = []

        # Build combined pattern groups
        all_pattern_groups = [
            ('Cloud & API Secrets', self.API_KEY_PATTERNS, 'CRITICAL'),
            ('Authentication Tokens', self.TOKEN_PATTERNS, 'CRITICAL'),
            ('Hardcoded Credentials', self.CREDENTIAL_PATTERNS, 'CRITICAL'),
            ('PII Exposure', self.PII_PATTERNS, 'MEDIUM'),
            ('Sensitive Configuration', self.CONFIG_PATTERNS, 'MEDIUM'),
        ]

        # ── Scan DEX strings with class/method context ─────────────
        dex_contexts = apk_result.dex_string_contexts
        for ctx in dex_contexts:
            string_val = ctx['value']
            if len(string_val) < 6:
                continue

            for group_name, patterns, default_severity in all_pattern_groups:
                for pattern_name, regex in patterns.items():
                    try:
                        matches = list(re.finditer(regex, string_val, re.IGNORECASE))
                        for match in matches:
                            matched_val = match.group()
                            # Skip very short matches for generic patterns
                            if len(matched_val) < 6:
                                continue

                            # Determine severity
                            severity = default_severity
                            if 'Password' in pattern_name or 'Private Key' in pattern_name:
                                severity = 'CRITICAL'
                            elif 'Email' in pattern_name or 'Phone' in pattern_name:
                                severity = 'LOW'
                            elif 'Localhost' in pattern_name:
                                severity = 'LOW'

                            findings.append({
                                'type': pattern_name,
                                'severity': severity,
                                'value': self._truncate(matched_val, 80),
                                'source': 'DEX',
                                'class_name': ctx.get('class_name', 'Unknown'),
                                'method_name': ctx.get('method_name', 'Unknown'),
                                'context': f"Class: {ctx.get('class_name', 'N/A')}, Method: {ctx.get('method_name', 'N/A')}",
                                'description': f'{pattern_name} detected in DEX code. Hardcoded secrets can be extracted by decompiling the APK.',
                                'recommendation': self._get_recommendation(pattern_name),
                            })
                    except Exception:
                        continue

        # ── Scan resource files ────────────────────────────────────
        for res in apk_result.resource_strings:
            res_text = res['value']
            res_file = res.get('filename', 'unknown')

            for group_name, patterns, default_severity in all_pattern_groups:
                for pattern_name, regex in patterns.items():
                    try:
                        matches = list(re.finditer(regex, res_text, re.IGNORECASE))
                        for match in matches:
                            matched_val = match.group()
                            if len(matched_val) < 6:
                                continue

                            severity = default_severity
                            if 'Password' in pattern_name or 'Private Key' in pattern_name:
                                severity = 'CRITICAL'
                            elif 'Email' in pattern_name or 'Phone' in pattern_name:
                                severity = 'LOW'
                            elif 'Localhost' in pattern_name:
                                severity = 'LOW'

                            findings.append({
                                'type': pattern_name,
                                'severity': severity,
                                'value': self._truncate(matched_val, 80),
                                'source': 'resource',
                                'class_name': None,
                                'method_name': None,
                                'context': f"Resource file: {res_file}",
                                'description': f'{pattern_name} found in resource file "{res_file}". Resource files are easily readable from APK.',
                                'recommendation': self._get_recommendation(pattern_name),
                            })
                    except Exception:
                        continue

        # Deduplicate
        findings = self._deduplicate(findings)

        return self._format_result(findings)

    def _truncate(self, value: str, max_len: int) -> str:
        if len(value) > max_len:
            return value[:max_len] + '...'
        return value

    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings based on type + value"""
        seen = set()
        unique = []
        for f in findings:
            key = (f['type'], f['value'])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _get_recommendation(self, pattern_name: str) -> str:
        recommendations = {
            'AWS Access Key': 'Remove AWS credentials from code. Use AWS IAM roles or environment variables.',
            'AWS Secret Key': 'Remove AWS secret key. Use AWS Secrets Manager or IAM roles.',
            'Google API Key': 'Restrict API key in Google Cloud Console. Use Android-specific key restrictions.',
            'Firebase URL': 'Ensure Firebase Security Rules are properly configured to restrict data access.',
            'S3 Bucket URL': 'Verify S3 bucket permissions. Enable bucket policies for least-privilege access.',
            'Hardcoded Password': 'Never hardcode passwords. Use Android Keystore or a secure credential manager.',
            'Hardcoded Username': 'Avoid hardcoding usernames. Use secure credential storage.',
            'Admin Password': 'Remove admin credentials immediately. Use environment-specific configuration.',
            'Admin Flag': 'Admin flags should not be hardcoded. Use server-side role verification.',
            'Database URL': 'Move database connection strings to secure server-side configuration.',
            'Database Password': 'Never store database passwords in client-side code.',
            'Private Key': 'CRITICAL: Private keys must never be embedded in client applications.',
            'JWT Token': 'JWTs should be generated server-side and stored securely, not hardcoded.',
            'Bearer Token': 'Bearer tokens should be obtained dynamically, not hardcoded.',
            'Email Address': 'Consider removing developer email addresses from production builds.',
            'Private IP Address (10.x)': 'Remove internal IP addresses to prevent infrastructure exposure.',
            'Private IP Address (172.x)': 'Remove internal IP addresses to prevent infrastructure exposure.',
            'Private IP Address (192.168.x)': 'Remove internal IP addresses to prevent infrastructure exposure.',
            'Debug URL': 'Remove debug/staging URLs from production builds.',
            'Localhost URL': 'Localhost URLs should be configurable, not hardcoded.',
        }
        return recommendations.get(pattern_name,
            f'Remove {pattern_name} from code. Use environment variables or a secrets management system.')

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
            'category': 'Hardcoded Secrets',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Found {len(findings)} potential hardcoded secret(s), credential(s), or sensitive data exposure(s).'
        }
