"""IPA Analyzer
Analyzes iOS Application Packages (IPA files).
Extracts Info.plist, scans embedded binaries (Mach-O),
detects insecure configurations and secrets.
"""

import zipfile
import re
import plistlib
from typing import List, Dict
from analyzers.unified_rules import UnifiedRuleEngine


class IPAAnalyzer:
    """Analyzes iOS Application (IPA) files"""

    def analyze(self, file_path: str) -> dict:
        """Full IPA analysis pipeline"""
        all_findings = {}

        try:
            zf = zipfile.ZipFile(file_path, 'r')
        except Exception as e:
            return self._error_result(f'Cannot open IPA: {e}')

        try:
            file_list = zf.namelist()

            # Find the .app directory inside Payload/
            app_dir = self._find_app_dir(file_list)

            # ── IPA Structure ─────────────────────────────────────
            try:
                structure = self._analyze_structure(zf, file_list, app_dir)
                all_findings['IPA Structure'] = structure
            except Exception as e:
                print(f'[!] IPA structure error: {e}')

            # ── Info.plist analysis ───────────────────────────────
            try:
                plist_findings = self._analyze_info_plist(zf, app_dir)
                if plist_findings['total_found'] > 0:
                    all_findings['Info.plist Security'] = plist_findings
            except Exception as e:
                print(f'[!] Info.plist analysis error: {e}')

            # ── Embedded provisioning profile ─────────────────────
            try:
                provision_findings = self._analyze_provisioning(zf, app_dir)
                if provision_findings['total_found'] > 0:
                    all_findings['Provisioning Profile'] = provision_findings
            except Exception as e:
                print(f'[!] Provisioning analysis error: {e}')

            # ── Extract strings from all files ────────────────────
            extracted_text = self._extract_all_strings(zf, file_list, app_dir)

            # ── iOS-specific patterns ─────────────────────────────
            try:
                ios_findings = self._detect_ios_patterns(extracted_text)
                if ios_findings['total_found'] > 0:
                    all_findings['iOS Security Patterns'] = ios_findings
            except Exception as e:
                print(f'[!] iOS pattern error: {e}')

            # ── Run unified rule engine ───────────────────────────
            if extracted_text:
                rule_findings = UnifiedRuleEngine.scan(
                    extracted_text, 'IPA', 'app bundle'
                )
                all_findings.update(rule_findings)

        finally:
            zf.close()

        return all_findings

    def _find_app_dir(self, file_list: List[str]) -> str:
        """Find the Payload/*.app/ directory"""
        for name in file_list:
            if name.startswith('Payload/') and '.app/' in name:
                parts = name.split('/')
                if len(parts) >= 2:
                    return f'{parts[0]}/{parts[1]}/'
        return 'Payload/'

    def _analyze_structure(self, zf: zipfile.ZipFile, file_list: List[str], app_dir: str) -> dict:
        """Analyze IPA structure"""
        findings = []

        # Categorize files
        binary_files = [f for f in file_list if not f.endswith(('.plist', '.nib', '.storyboardc', '.png', '.jpg', '.car', '.strings'))]
        framework_dirs = set()
        for name in file_list:
            if '/Frameworks/' in name:
                parts = name.split('/Frameworks/')
                if len(parts) > 1:
                    fw = parts[1].split('/')[0]
                    framework_dirs.add(fw)

        findings.append({
            'type': 'IPA Contents',
            'severity': 'LOW',
            'value': f'{len(file_list)} files, {len(framework_dirs)} frameworks',
            'source': 'IPA',
            'description': f'IPA bundle contains {len(file_list)} files and {len(framework_dirs)} embedded framework(s).',
            'recommendation': 'Review embedded frameworks for known vulnerabilities.',
        })

        # Check for embedded certificates
        certs = [f for f in file_list if f.endswith(('.cer', '.p12', '.pfx', '.pem'))]
        if certs:
            findings.append({
                'type': 'Embedded Certificates',
                'severity': 'HIGH',
                'value': ', '.join(certs[:5]),
                'source': 'IPA',
                'description': f'{len(certs)} certificate file(s) embedded in IPA. May contain private keys.',
                'recommendation': 'Never bundle certificate files. Use the iOS Keychain.',
            })

        severities = [f['severity'] for f in findings]
        overall = 'LOW'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'IPA Structure',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'IPA structure: {len(file_list)} files, {len(framework_dirs)} frameworks.',
        }

    def _analyze_info_plist(self, zf: zipfile.ZipFile, app_dir: str) -> dict:
        """Analyze Info.plist for security settings"""
        findings = []

        plist_path = f'{app_dir}Info.plist'
        try:
            plist_data = zf.read(plist_path)
            plist = plistlib.loads(plist_data)
        except KeyError:
            # Try alternative paths
            plist = None
            for name in zf.namelist():
                if name.endswith('Info.plist') and 'Payload/' in name:
                    try:
                        plist_data = zf.read(name)
                        plist = plistlib.loads(plist_data)
                        break
                    except Exception:
                        continue
            if plist is None:
                return {'category': 'Info.plist Security', 'total_found': 0, 'findings': [], 'severity': 'SAFE', 'description': 'Info.plist not found.'}
        except Exception:
            return {'category': 'Info.plist Security', 'total_found': 0, 'findings': [], 'severity': 'SAFE', 'description': 'Cannot parse Info.plist.'}

        # ── App Transport Security ────────────────────────────────
        ats = plist.get('NSAppTransportSecurity', {})
        if ats.get('NSAllowsArbitraryLoads', False):
            findings.append({
                'type': 'ATS Disabled',
                'severity': 'CRITICAL',
                'value': 'NSAllowsArbitraryLoads = true',
                'source': 'IPA',
                'description': 'App Transport Security (ATS) is disabled. App can make insecure HTTP connections.',
                'recommendation': 'Enable ATS. Only add exceptions for specific domains.',
            })

        ats_exceptions = ats.get('NSExceptionDomains', {})
        if ats_exceptions:
            for domain, config in ats_exceptions.items():
                if config.get('NSExceptionAllowsInsecureHTTPLoads', False):
                    findings.append({
                        'type': 'ATS Exception',
                        'severity': 'HIGH',
                        'value': f'Insecure HTTP allowed for: {domain}',
                        'source': 'IPA',
                        'description': f'ATS exception allows insecure HTTP to {domain}.',
                        'recommendation': f'Use HTTPS for {domain}. Remove ATS exception.',
                    })

        # ── URL Schemes ───────────────────────────────────────────
        url_types = plist.get('CFBundleURLTypes', [])
        for url_type in url_types:
            schemes = url_type.get('CFBundleURLSchemes', [])
            for scheme in schemes:
                severity = 'MEDIUM'
                if scheme.lower() in ('http', 'https'):
                    severity = 'HIGH'
                findings.append({
                    'type': 'Custom URL Scheme',
                    'severity': severity,
                    'value': f'{scheme}://',
                    'source': 'IPA',
                    'description': f'App registers custom URL scheme: {scheme}. Could be exploited for URL hijacking.',
                    'recommendation': 'Validate all data received via URL schemes. Use Universal Links instead.',
                })

        # ── Background modes ──────────────────────────────────────
        bg_modes = plist.get('UIBackgroundModes', [])
        suspicious_modes = {'voip', 'location', 'audio', 'fetch', 'remote-notification'}
        active_suspicious = [m for m in bg_modes if m in suspicious_modes]
        if active_suspicious:
            findings.append({
                'type': 'Background Modes',
                'severity': 'LOW',
                'value': ', '.join(active_suspicious),
                'source': 'IPA',
                'description': f'App uses background modes: {", ".join(active_suspicious)}.',
                'recommendation': 'Ensure background modes are necessary. Location tracking in background raises privacy concerns.',
            })

        # ── Debug / development flags ─────────────────────────────
        if plist.get('UIFileSharingEnabled', False):
            findings.append({
                'type': 'File Sharing Enabled',
                'severity': 'MEDIUM',
                'value': 'UIFileSharingEnabled = true',
                'source': 'IPA',
                'description': 'App Documents folder is visible in iTunes/Finder. May expose sensitive data.',
                'recommendation': 'Disable file sharing unless required. Don\'t store sensitive data in Documents.',
            })

        severities = [f['severity'] for f in findings]
        overall = 'SAFE'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'Info.plist Security',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Info.plist security analysis: {len(findings)} finding(s).',
        }

    def _analyze_provisioning(self, zf: zipfile.ZipFile, app_dir: str) -> dict:
        """Analyze embedded provisioning profile"""
        findings = []

        prov_path = f'{app_dir}embedded.mobileprovision'
        try:
            prov_data = zf.read(prov_path)
            prov_text = prov_data.decode('utf-8', errors='replace')

            if 'get-task-allow' in prov_text.lower():
                # Check if get-task-allow is true (development build)
                if '<key>get-task-allow</key>\n\t\t<true/>' in prov_text or '<key>get-task-allow</key><true/>' in prov_text:
                    findings.append({
                        'type': 'Development Build',
                        'severity': 'HIGH',
                        'value': 'get-task-allow = true',
                        'source': 'IPA',
                        'description': 'This is a development/debug build. Debugger can attach to the app.',
                        'recommendation': 'Use a distribution provisioning profile for release.',
                    })

            if 'ProvisisioningType: development' in prov_text or 'ProvisioningType: development' in prov_text:
                findings.append({
                    'type': 'Development Profile',
                    'severity': 'MEDIUM',
                    'value': 'Development provisioning profile detected',
                    'source': 'IPA',
                    'description': 'App uses a development profile. Not suitable for distribution.',
                    'recommendation': 'Use a distribution profile for release builds.',
                })

        except KeyError:
            pass
        except Exception:
            pass

        severities = [f['severity'] for f in findings]
        overall = 'SAFE'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'Provisioning Profile',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Provisioning profile analysis: {len(findings)} finding(s).',
        }

    def _extract_all_strings(self, zf: zipfile.ZipFile, file_list: List[str], app_dir: str, min_length: int = 6) -> str:
        """Extract strings from all relevant files in the IPA"""
        all_strings = []

        for name in file_list:
            try:
                data = zf.read(name)

                # Text files: decode directly
                if name.endswith(('.plist', '.strings', '.json', '.xml', '.txt', '.html', '.js', '.css')):
                    try:
                        text = data.decode('utf-8', errors='replace')
                        all_strings.append(text)
                        continue
                    except Exception:
                        pass

                # Binary files: extract printable strings
                if len(data) > 0 and not name.endswith(('.png', '.jpg', '.jpeg', '.gif', '.car', '.nib', '.storyboardc')):
                    strings = self._extract_printable(data, min_length)
                    all_strings.extend(strings)

            except Exception:
                continue

        return '\n'.join(all_strings[:10000])  # Cap to prevent massive output

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

    def _detect_ios_patterns(self, text: str) -> dict:
        """Detect iOS-specific security patterns"""
        findings = []

        patterns = [
            (r'kSecAttrAccessibleAlways', 'Insecure Keychain Access', 'HIGH',
             'Keychain item accessible even when device is locked.',
             'Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly.'),
            (r'NSLog\s*\(.*@?".*(?:password|token|secret|key|cred)', 'Sensitive Data Logging', 'HIGH',
             'Sensitive data may be logged via NSLog.',
             'Remove sensitive data logging. Use os_log with privacy annotations.'),
            (r'canOpenURL.*(?:cydia|sileo|zebra)', 'Jailbreak Detection', 'LOW',
             'App checks for jailbreak indicators.',
             'Ensure jailbreak detection is robust if required.'),
            (r'UIPasteboard', 'Clipboard Access', 'MEDIUM',
             'App accesses system clipboard. Sensitive data may be exposed.',
             'Avoid storing sensitive data on clipboard. Clear after use.'),
            (r'SecTrustSetAnchorCertificates|SSLSetPeerDomainName', 'Certificate Pinning', 'LOW',
             'Certificate pinning implementation detected.',
             'Ensure pinning implementation is robust and has backup pins.'),
        ]

        for pattern, name, severity, desc, rec in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                findings.append({
                    'type': name,
                    'severity': severity,
                    'value': matches[0][:100],
                    'source': 'IPA',
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
            'category': 'iOS Security Patterns',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'iOS-specific pattern detection: {len(findings)} finding(s).',
        }

    def _error_result(self, msg: str) -> dict:
        return {
            'IPA Analysis Error': {
                'category': 'IPA Analysis Error',
                'total_found': 1,
                'findings': [{
                    'type': 'Analysis Error',
                    'severity': 'MEDIUM',
                    'value': msg,
                    'source': 'IPA',
                    'description': msg,
                    'recommendation': 'Ensure the file is a valid IPA.',
                }],
                'severity': 'MEDIUM',
                'description': msg,
            }
        }
