"""Unified Rule Engine
Common rule engine that all file-type analyzers pass extracted strings through.
Provides consistent detection across all formats.

Categories:
- Secret Exposure (API keys, tokens, credentials)
- Insecure Configuration (debug flags, weak crypto references)
- Suspicious Behavior (shell commands, code injection, eval patterns)
- Embedded Executable (PE/ELF inside PDF/ZIP)
- Dangerous Capability (network calls, file system access, privilege escalation)

Each finding includes: file_type, file_section, matched_string, rule_name, severity
"""

import re
import math
from collections import Counter
from typing import List, Dict, Optional


class UnifiedRuleEngine:
    """Common rule engine for all file type analyzers"""

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 1: SECRET EXPOSURE
    # ═══════════════════════════════════════════════════════════════════
    SECRET_RULES = {
        # Cloud & API
        'AWS Access Key': (r'AKIA[0-9A-Z]{16}', 'CRITICAL'),
        'AWS Secret Key': (r'(?:aws)?(?:.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]', 'CRITICAL'),
        'Google API Key': (r'AIza[0-9A-Za-z\-_]{35}', 'CRITICAL'),
        'Firebase URL': (r'https://[a-zA-Z0-9\-]+\.firebaseio\.com', 'HIGH'),
        'Firebase Storage': (r'https://firebasestorage\.googleapis\.com/[^\s\'"]+', 'HIGH'),
        'S3 Bucket URL': (r'(?:https?://)?[a-zA-Z0-9.\-]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com', 'HIGH'),
        'GCS Bucket URL': (r'https?://storage\.googleapis\.com/[a-zA-Z0-9.\-_]+', 'HIGH'),
        'Azure Storage': (r'https://[a-zA-Z0-9\-]+\.blob\.core\.windows\.net', 'HIGH'),
        # Auth Tokens
        'JWT Token': (r'eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*', 'CRITICAL'),
        'Bearer Token': (r'[Bb]earer\s+[A-Za-z0-9\-_\.~\+\/]+=*', 'CRITICAL'),
        'GitHub Token': (r'gh[ps]_[0-9a-zA-Z]{36}', 'CRITICAL'),
        'GitLab PAT': (r'glpat-[0-9a-zA-Z\-_]{20}', 'CRITICAL'),
        'Stripe Key': (r'[srpk]k_(?:live|test)_[0-9a-zA-Z]{24,}', 'CRITICAL'),
        'Slack Token': (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}', 'CRITICAL'),
        'SendGrid Key': (r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}', 'CRITICAL'),
        'Twilio Key': (r'SK[a-z0-9]{32}', 'HIGH'),
        'OpenAI Key': (r'sk-[a-zA-Z0-9]{48}', 'CRITICAL'),
        # Credentials
        'Hardcoded Password': (r'(?:password|passwd|pwd)\s*[:=]\s*[\'"][^\'"]{4,}[\'"]', 'CRITICAL'),
        'Hardcoded Username': (r'(?:username|user_name|userId)\s*[:=]\s*[\'"][^\'"]{3,}[\'"]', 'MEDIUM'),
        'Database URL': (r'(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|mssql)://[^\s\'"]+', 'CRITICAL'),
        'Private Key': (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', 'CRITICAL'),
        'Generic API Key': (r'(?:api[_-]?key|apikey)\s*[:=]\s*[\'"][a-zA-Z0-9\-_]{20,}[\'"]', 'HIGH'),
        'Generic Secret': (r'(?:secret|SECRET)\s*[:=]\s*[\'"][a-zA-Z0-9\-_]{20,}[\'"]', 'HIGH'),
        # PII
        'Email Address': (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b', 'LOW'),
        'Private IP (10.x)': (r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'MEDIUM'),
        'Private IP (172.x)': (r'\b172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b', 'MEDIUM'),
        'Private IP (192.168.x)': (r'\b192\.168\.\d{1,3}\.\d{1,3}\b', 'MEDIUM'),
    }

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 2: INSECURE CONFIGURATION
    # ═══════════════════════════════════════════════════════════════════
    CONFIG_RULES = {
        'Debug Mode Enabled': (r'(?:DEBUG|debug)\s*[:=]\s*(?:true|True|1|yes)', 'HIGH'),
        'Weak Hash MD5': (r'\bMD5\b', 'HIGH'),
        'Weak Hash SHA1': (r'\bSHA-?1\b', 'HIGH'),
        'Weak Cipher DES': (r'\bDES(?:ede)?\b', 'HIGH'),
        'Weak Cipher RC4': (r'\bRC4\b', 'CRITICAL'),
        'ECB Mode': (r'ECB', 'HIGH'),
        'Cleartext HTTP URL': (r'http://(?!localhost|127\.0\.0\.1|schemas\.android|www\.w3\.org|xmlpull\.org|xml\.org|schema\.org)[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]+', 'HIGH'),
        'Insecure WebSocket': (r'ws://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]+', 'HIGH'),
        'SSL Verification Disabled': (r'(?:verify\s*=\s*False|CERT_NONE|InsecureRequestWarning)', 'CRITICAL'),
        'TrustManager Override': (r'TrustManager|X509TrustManager|HostnameVerifier', 'CRITICAL'),
    }

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 3: SUSPICIOUS BEHAVIOR
    # ═══════════════════════════════════════════════════════════════════
    BEHAVIOR_RULES = {
        # Shell / Command execution
        'Shell Execution': (r'(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder|subprocess\.(?:call|run|Popen)|os\.system|exec\(|shell_exec|system\()', 'CRITICAL'),
        'PowerShell Command': (r'(?:powershell|pwsh)\s+(?:-enc|-EncodedCommand|-e\s)', 'CRITICAL'),
        'Base64 Encoded Command': (r'(?:-enc|-EncodedCommand)\s+[A-Za-z0-9+/=]{20,}', 'CRITICAL'),
        # Code injection
        'eval() Usage': (r'\beval\s*\(', 'HIGH'),
        'document.write()': (r'document\.write\s*\(', 'HIGH'),
        'innerHTML Assignment': (r'\.innerHTML\s*=', 'MEDIUM'),
        'Dynamic Import': (r'(?:__import__|importlib\.import_module|Class\.forName|loadClass)', 'MEDIUM'),
        # Deserialization
        'Java Deserialization': (r'ObjectInputStream|readObject\(\)|XMLDecoder|readUnshared', 'HIGH'),
        'Pickle Deserialization': (r'pickle\.(?:load|loads)|cPickle\.(?:load|loads)', 'HIGH'),
        'YAML Unsafe Load': (r'yaml\.(?:load|unsafe_load)\(', 'HIGH'),
        # Reflection
        'Java Reflection': (r'java\.lang\.reflect|Method\.invoke|getDeclaredMethod|setAccessible\(true\)', 'MEDIUM'),
    }

    # ═══════════════════════════════════════════════════════════════════
    # CATEGORY 4: DANGEROUS CAPABILITY
    # ═══════════════════════════════════════════════════════════════════
    CAPABILITY_RULES = {
        'File System Access': (r'(?:FileOutputStream|FileWriter|fopen|open\s*\([\'"][^\'")]+[\'"],\s*[\'"]w)', 'MEDIUM'),
        'Network Socket': (r'(?:Socket\(|ServerSocket\(|DatagramSocket|URLConnection|HttpURLConnection)', 'LOW'),
        'Crypto Operation': (r'(?:Cipher\.getInstance|KeyGenerator|SecretKeyFactory|MessageDigest)', 'LOW'),
        'Registry Access': (r'(?:RegOpenKey|RegSetValue|RegQueryValue|HKEY_)', 'MEDIUM'),
        'Process Manipulation': (r'(?:VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtCreateThread)', 'CRITICAL'),
        'Privilege Escalation': (r'(?:setuid|setgid|sudo|SeDebugPrivilege|AdjustTokenPrivileges)', 'CRITICAL'),
        'Keylogging Indicators': (r'(?:GetAsyncKeyState|SetWindowsHookEx|GetKeyState|RegisterRawInputDevices)', 'CRITICAL'),
    }

    # ═══════════════════════════════════════════════════════════════════
    # MAIN SCAN METHOD
    # ═══════════════════════════════════════════════════════════════════

    @classmethod
    def scan(cls, text: str, file_type: str, section: str = 'full_file',
             context: Optional[str] = None) -> Dict[str, dict]:
        """
        Scan text through all rule categories.
        Secret rules run first; matched values are excluded from entropy scan
        so identified API keys don't also appear as generic 'High Entropy String'.

        Args:
            text: The extracted text/strings to scan
            file_type: The detected file type (EXE, SO, JAR, etc.)
            section: Which section of the file (e.g., '.rdata', 'META-INF')
            context: Additional context string

        Returns:
            Dict with category_name -> {category, findings, severity, ...}
        """
        all_findings = {}

        # 1. Secret rules run FIRST — collect matched values for dedup
        secret_findings = cls._run_rules(
            cls.SECRET_RULES, text, file_type, section, 'Secret Exposure',
            'Hardcoded secrets, credentials, and API keys detected in file content.'
        )
        if secret_findings['total_found'] > 0:
            all_findings['Secret Exposure'] = secret_findings

        # Collect all secret-matched values to exclude from entropy
        secret_matched_values = set()
        for f in secret_findings.get('findings', []):
            val = f.get('value', '')
            if val.endswith('...'):
                val = val[:-3]
            secret_matched_values.add(val)

        # 2. Other rule categories
        config_findings = cls._run_rules(
            cls.CONFIG_RULES, text, file_type, section, 'Insecure Configuration',
            'Weak security configurations and deprecated algorithms detected.'
        )
        if config_findings['total_found'] > 0:
            all_findings['Insecure Configuration'] = config_findings

        behavior_findings = cls._run_rules(
            cls.BEHAVIOR_RULES, text, file_type, section, 'Suspicious Behavior',
            'Potentially dangerous code patterns and behaviors detected.'
        )
        if behavior_findings['total_found'] > 0:
            all_findings['Suspicious Behavior'] = behavior_findings

        capability_findings = cls._run_rules(
            cls.CAPABILITY_RULES, text, file_type, section, 'Dangerous Capability',
            'System-level capabilities that could be used maliciously.'
        )
        if capability_findings['total_found'] > 0:
            all_findings['Dangerous Capability'] = capability_findings

        # 3. Entropy analysis — exclude strings already identified as secrets
        entropy_findings = cls.scan_entropy(text, file_type, section,
                                            exclude_values=secret_matched_values)
        if entropy_findings['total_found'] > 0:
            all_findings['High Entropy Strings'] = entropy_findings

        return all_findings

    @classmethod
    def _run_rules(cls, rules: dict, text: str, file_type: str,
                   section: str, category_name: str, category_desc: str) -> dict:
        """Run a set of regex rules against text"""
        findings = []
        seen = set()

        for rule_name, (pattern, severity) in rules.items():
            try:
                matches = list(re.finditer(pattern, text, re.IGNORECASE))
                for match in matches:
                    matched = match.group()
                    if len(matched) < 3:
                        continue
                    truncated = matched[:100] + '...' if len(matched) > 100 else matched

                    dedup_key = (rule_name, truncated)
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    findings.append({
                        'type': rule_name,
                        'severity': severity,
                        'value': truncated,
                        'source': file_type,
                        'context': f'Section: {section}',
                        'description': cls._get_description(rule_name, file_type),
                        'recommendation': cls._get_recommendation(rule_name),
                    })
            except Exception:
                continue

        # Limit per category to reduce noise
        findings = findings[:50]

        severities = [f['severity'] for f in findings]
        overall = 'SAFE'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if s in severities:
                overall = s
                break

        return {
            'category': category_name,
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': category_desc,
        }

    @classmethod
    def scan_entropy(cls, text: str, file_type: str, section: str = 'full_file',
                     min_length: int = 20, threshold: float = 4.5,
                     exclude_values: Optional[set] = None) -> dict:
        """Scan for high-entropy strings, excluding those already identified as secrets"""
        findings = []
        seen = set()
        excludes = exclude_values or set()

        # Split text into lines/words and check each
        words = re.findall(r'[A-Za-z0-9+/=\-_]{20,}', text)
        for word in words:
            if word in seen:
                continue
            seen.add(word)

            if len(word) < min_length:
                continue

            # Skip if this word overlaps with an already-identified secret
            is_secret = False
            for secret_val in excludes:
                if secret_val and len(secret_val) >= 10 and (
                    secret_val in word or word in secret_val
                ):
                    is_secret = True
                    break
            if is_secret:
                continue

            entropy = cls._shannon_entropy(word)
            if entropy >= threshold:
                severity = 'HIGH' if entropy >= 5.5 else 'MEDIUM' if entropy >= 5.0 else 'LOW'
                truncated = word[:50] + '...' if len(word) > 50 else word
                findings.append({
                    'type': 'High Entropy String',
                    'severity': severity,
                    'value': truncated,
                    'entropy': round(entropy, 2),
                    'length': len(word),
                    'source': file_type,
                    'context': f'Section: {section}',
                    'description': f'String with high randomness (entropy: {entropy:.2f}). May indicate encoded secret, encrypted data, or obfuscated token.',
                    'recommendation': 'Verify if this is a hardcoded secret. Move sensitive data to environment variables or a secrets manager.',
                })

        # Limit to top 20 by entropy
        findings.sort(key=lambda f: f.get('entropy', 0), reverse=True)
        findings = findings[:20]

        severities = [f['severity'] for f in findings]
        overall = 'SAFE'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'High Entropy Strings',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Found {len(findings)} high-entropy string(s) (Shannon entropy ≥ {threshold}) that may contain hidden secrets.',
        }

    @staticmethod
    def _shannon_entropy(string: str) -> float:
        """Calculate Shannon entropy"""
        if not string:
            return 0.0
        counts = Counter(string)
        length = len(string)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _get_description(rule_name: str, file_type: str) -> str:
        """Get human-readable description for a rule"""
        descs = {
            'AWS Access Key': 'AWS access key found in file. Can be used to access AWS resources.',
            'Google API Key': 'Google API key exposed. May allow unauthorized API usage.',
            'JWT Token': 'JSON Web Token found. Contains encoded authentication data.',
            'Hardcoded Password': 'Password is hardcoded in the file. Can be extracted by anyone with file access.',
            'Database URL': 'Database connection string with credentials exposed.',
            'Private Key': 'Private cryptographic key embedded in file. Critical security risk.',
            'Shell Execution': 'Code executes OS commands. Could be used for command injection.',
            'PowerShell Command': 'Encoded PowerShell command detected. Common malware technique.',
            'eval() Usage': 'Dynamic code execution via eval(). Enables code injection attacks.',
            'Process Manipulation': 'Low-level process manipulation. Common in malware for code injection.',
            'Keylogging Indicators': 'API calls associated with keystroke capture.',
            'SSL Verification Disabled': 'SSL certificate verification is disabled, enabling MITM attacks.',
            'Debug Mode Enabled': 'Debug mode is active. May expose verbose errors and internal state.',
            'Cleartext HTTP URL': 'Unencrypted HTTP URL. Data can be intercepted.',
        }
        return descs.get(rule_name, f'{rule_name} detected in {file_type} file.')

    @staticmethod
    def _get_recommendation(rule_name: str) -> str:
        """Get remediation recommendation"""
        recs = {
            'AWS Access Key': 'Remove AWS keys from code. Use IAM roles or environment variables.',
            'Google API Key': 'Restrict API key in Google Cloud Console. Use server-side key management.',
            'JWT Token': 'Never hardcode JWTs. Generate dynamically on the server.',
            'Hardcoded Password': 'Use a secrets manager or environment variables for credentials.',
            'Database URL': 'Move connection strings to server-side configuration.',
            'Private Key': 'Never embed private keys. Use a key management service (KMS).',
            'Shell Execution': 'Avoid dynamic command execution. Use parameterized APIs instead.',
            'PowerShell Command': 'Investigate encoded PowerShell commands for malicious intent.',
            'eval() Usage': 'Replace eval() with safer alternatives like JSON.parse().',
            'Process Manipulation': 'Investigate process manipulation APIs for malicious behavior.',
            'SSL Verification Disabled': 'Enable SSL certificate verification for all connections.',
            'Debug Mode Enabled': 'Disable debug mode in production builds.',
            'Cleartext HTTP URL': 'Use HTTPS for all network communication.',
            'Weak Hash MD5': 'Replace MD5 with SHA-256 or higher.',
            'Weak Hash SHA1': 'Replace SHA-1 with SHA-256 or higher.',
            'Weak Cipher DES': 'Replace DES with AES-256-GCM.',
            'Weak Cipher RC4': 'Replace RC4 with AES-256-GCM or ChaCha20.',
        }
        return recs.get(rule_name, f'Review and remediate {rule_name} finding.')
