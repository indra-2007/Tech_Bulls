"""JAR Analyzer
Analyzes Java Archive files (ZIP with .class files + META-INF).
Extracts strings from class files, scans META-INF/MANIFEST.MF,
detects deserialization, reflection, and hardcoded secrets.
"""

import zipfile
import re
from typing import List, Dict
from analyzers.unified_rules import UnifiedRuleEngine


class JARAnalyzer:
    """Analyzes Java Archive (JAR) files"""

    # Java-specific patterns
    JAVA_PATTERNS = {
        'CRITICAL': {
            'Deserialization Risk': (
                r'ObjectInputStream|readObject\(\)|readUnshared|XMLDecoder|XStream|'
                r'ObjectMapper\.enableDefaultTyping|JsonTypeInfo\.Id\.CLASS',
                'Unsafe deserialization detected. Can lead to Remote Code Execution (RCE).',
                'Use allow-lists for deserialized types. Avoid ObjectInputStream with untrusted data.',
            ),
            'JNDI Injection Risk': (
                r'InitialContext\.lookup|javax\.naming|ldap://|rmi://|jndi:',
                'JNDI lookup detected. Potential for Log4Shell-style RCE attacks.',
                'Validate JNDI lookup strings. Disable remote class loading.',
            ),
            'SQL Injection Risk': (
                r'Statement\.execute|createStatement|prepareStatement.*\+.*[\'"]',
                'Dynamic SQL construction detected. Potential SQL injection.',
                'Use PreparedStatement with parameterized queries.',
            ),
        },
        'HIGH': {
            'Reflection Usage': (
                r'Class\.forName|getDeclaredMethod|getDeclaredField|setAccessible\(true\)|'
                r'Method\.invoke|Constructor\.newInstance',
                'Java reflection detected. Can bypass access controls.',
                'Minimize reflection usage. Validate inputs to reflection calls.',
            ),
            'Runtime Execution': (
                r'Runtime\.getRuntime\(\)\.exec|ProcessBuilder|'
                r'ProcessBuilder\.command|Process\.getInputStream',
                'OS command execution detected.',
                'Avoid direct command execution. Use parameterized APIs.',
            ),
            'Weak Cryptography': (
                r'Cipher\.getInstance\s*\(\s*[\'"](?:DES|DESede|RC4|Blowfish|RC2)[\'"]|'
                r'MessageDigest\.getInstance\s*\(\s*[\'"](?:MD5|SHA-1)[\'"]|'
                r'SecretKeySpec.*"DES"',
                'Weak cryptographic algorithm detected.',
                'Use AES-256-GCM for encryption and SHA-256+ for hashing.',
            ),
            'Hardcoded Credentials': (
                r'password\s*=\s*[\'"][^\'"]{4,}[\'"]|'
                r'passwd\s*=\s*[\'"][^\'"]{4,}[\'"]|'
                r'\.setPassword\s*\([\'"]',
                'Hardcoded password found in class file.',
                'Use a secrets manager or environment variables for credentials.',
            ),
        },
        'MEDIUM': {
            'File I/O Operations': (
                r'FileOutputStream|FileWriter|FileInputStream|BufferedWriter|PrintWriter',
                'File I/O operations may handle sensitive data.',
                'Ensure file operations are properly validated and sanitized.',
            ),
            'Network Operations': (
                r'HttpURLConnection|URLConnection|Socket\(|ServerSocket|DatagramSocket|'
                r'OkHttpClient|HttpClient\.newHttpClient',
                'Network operations detected.',
                'Ensure all connections use HTTPS with proper certificate validation.',
            ),
        },
    }

    def analyze(self, file_path: str) -> dict:
        """Full JAR analysis pipeline"""
        all_findings = {}

        try:
            zf = zipfile.ZipFile(file_path, 'r')
        except Exception as e:
            return self._error_result(f'Cannot open JAR: {e}')

        try:
            file_list = zf.namelist()

            # ── JAR Structure info ────────────────────────────────
            try:
                jar_info = self._analyze_structure(zf, file_list)
                all_findings['JAR Structure'] = jar_info
            except Exception as e:
                print(f'[!] JAR structure error: {e}')

            # ── Manifest analysis ─────────────────────────────────
            try:
                manifest_findings = self._analyze_manifest(zf)
                if manifest_findings['total_found'] > 0:
                    all_findings['Manifest Analysis'] = manifest_findings
            except Exception as e:
                print(f'[!] Manifest analysis error: {e}')

            # ── Extract strings from all class files ──────────────
            extracted_text = self._extract_class_strings(zf, file_list)

            # ── Extract strings from config files ─────────────────
            config_text = self._extract_config_strings(zf, file_list)
            extracted_text += '\n' + config_text

            # ── Java-specific patterns ────────────────────────────
            try:
                java_findings = self._run_java_patterns(extracted_text)
                if java_findings['total_found'] > 0:
                    all_findings['Java Security Patterns'] = java_findings
            except Exception as e:
                print(f'[!] Java pattern analysis error: {e}')

            # ── Run unified rule engine ───────────────────────────
            if extracted_text:
                rule_findings = UnifiedRuleEngine.scan(
                    extracted_text, 'JAR', 'class files + resources'
                )
                all_findings.update(rule_findings)

        finally:
            zf.close()

        return all_findings

    def _analyze_structure(self, zf: zipfile.ZipFile, file_list: List[str]) -> dict:
        """Analyze JAR structure"""
        findings = []

        class_files = [f for f in file_list if f.endswith('.class')]
        config_files = [f for f in file_list if f.endswith(('.properties', '.xml', '.yml', '.yaml', '.json', '.cfg'))]
        native_libs = [f for f in file_list if f.endswith(('.so', '.dll', '.dylib'))]

        findings.append({
            'type': 'JAR Contents',
            'severity': 'LOW',
            'value': f'{len(class_files)} class files, {len(config_files)} config files, {len(native_libs)} native libs',
            'source': 'JAR',
            'description': f'JAR contains {len(file_list)} total entries.',
            'recommendation': 'Review native libraries and config files for embedded secrets.',
        })

        if native_libs:
            findings.append({
                'type': 'Embedded Native Libraries',
                'severity': 'MEDIUM',
                'value': ', '.join(native_libs[:5]),
                'source': 'JAR',
                'description': f'JAR contains {len(native_libs)} native library file(s). These bypass Java security model.',
                'recommendation': 'Review native libraries for malicious functionality.',
            })

        severities = [f['severity'] for f in findings]
        overall = 'LOW'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'JAR Structure',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'JAR structure: {len(class_files)} class files, {len(file_list)} total entries.',
        }

    def _analyze_manifest(self, zf: zipfile.ZipFile) -> dict:
        """Analyze META-INF/MANIFEST.MF"""
        findings = []

        try:
            manifest = zf.read('META-INF/MANIFEST.MF').decode('utf-8', errors='replace')
        except KeyError:
            return {
                'category': 'Manifest Analysis',
                'total_found': 1,
                'findings': [{
                    'type': 'Missing Manifest',
                    'severity': 'MEDIUM',
                    'value': 'META-INF/MANIFEST.MF not found',
                    'source': 'JAR',
                    'description': 'JAR has no manifest. May indicate repackaging.',
                    'recommendation': 'Verify JAR integrity.',
                }],
                'severity': 'MEDIUM',
                'description': 'No manifest found in JAR.',
            }

        # Check for main class
        if 'Main-Class:' in manifest:
            main_class = re.search(r'Main-Class:\s*(.+)', manifest)
            if main_class:
                findings.append({
                    'type': 'Executable Main Class',
                    'severity': 'LOW',
                    'value': main_class.group(1).strip(),
                    'source': 'JAR',
                    'description': f'JAR has an executable main class: {main_class.group(1).strip()}',
                    'recommendation': 'Review main class for security implications.',
                })

        # Check signing info
        signed_entries = [n for n in zf.namelist() if n.startswith('META-INF/') and n.endswith(('.SF', '.RSA', '.DSA', '.EC'))]
        if not signed_entries:
            findings.append({
                'type': 'Unsigned JAR',
                'severity': 'MEDIUM',
                'value': 'JAR is not digitally signed',
                'source': 'JAR',
                'description': 'JAR has no digital signature. Code integrity cannot be verified.',
                'recommendation': 'Sign JARs with a trusted certificate for distribution.',
            })

        # Check for suspicious permissions in manifest
        if 'Permissions:' in manifest:
            if 'all-permissions' in manifest.lower():
                findings.append({
                    'type': 'All Permissions Requested',
                    'severity': 'HIGH',
                    'value': 'Permissions: all-permissions',
                    'source': 'JAR',
                    'description': 'JAR requests all permissions. Can access system resources unrestricted.',
                    'recommendation': 'Restrict permissions to only what is needed.',
                })

        severities = [f['severity'] for f in findings]
        overall = 'LOW'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'Manifest Analysis',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Manifest analysis: {len(findings)} finding(s).',
        }

    def _extract_class_strings(self, zf: zipfile.ZipFile, file_list: List[str], min_length: int = 6) -> str:
        """Extract printable strings from .class files"""
        all_strings = []

        class_files = [f for f in file_list if f.endswith('.class')]
        for cf in class_files[:200]:  # Limit to avoid huge JARs
            try:
                data = zf.read(cf)
                strings = self._extract_printable(data, min_length)
                all_strings.extend(strings)
            except Exception:
                continue

        return '\n'.join(all_strings)

    def _extract_config_strings(self, zf: zipfile.ZipFile, file_list: List[str]) -> str:
        """Extract text from config files in JAR"""
        texts = []
        config_exts = ('.properties', '.xml', '.yml', '.yaml', '.json', '.cfg', '.ini', '.txt')

        for name in file_list:
            if name.lower().endswith(config_exts):
                try:
                    data = zf.read(name)
                    text = data.decode('utf-8', errors='replace')
                    texts.append(text)
                except Exception:
                    continue

        return '\n'.join(texts)

    def _extract_printable(self, data: bytes, min_length: int = 6) -> List[str]:
        """Extract printable ASCII strings from binary data"""
        strings = []
        current = []
        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if current and len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        if current and len(current) >= min_length:
            strings.append(''.join(current))
        return strings

    def _run_java_patterns(self, text: str) -> dict:
        """Run Java-specific security patterns"""
        findings = []
        seen = set()

        for severity, patterns in self.JAVA_PATTERNS.items():
            for name, (pattern, desc, rec) in patterns.items():
                matches = re.findall(pattern, text)
                for match in set(matches[:5]):
                    dedup_key = (name, match[:50])
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    findings.append({
                        'type': name,
                        'severity': severity,
                        'value': match[:100],
                        'source': 'JAR',
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
            'category': 'Java Security Patterns',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Java-specific pattern analysis: {len(findings)} finding(s).',
        }

    def _error_result(self, msg: str) -> dict:
        return {
            'JAR Analysis Error': {
                'category': 'JAR Analysis Error',
                'total_found': 1,
                'findings': [{
                    'type': 'Analysis Error',
                    'severity': 'MEDIUM',
                    'value': msg,
                    'source': 'JAR',
                    'description': msg,
                    'recommendation': 'Ensure JAR file is valid.',
                }],
                'severity': 'MEDIUM',
                'description': msg,
            }
        }
