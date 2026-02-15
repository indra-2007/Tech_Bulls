"""Certificate Analyzer
Extracts and analyzes APK signing certificate for:
- Debug certificate detection (CN=Android Debug)
- Expired certificate detection
- Certificate details (issuer, subject, validity period)
"""

from datetime import datetime, timezone
from typing import List, Dict


class CertificateAnalyzer:
    """Analyzes APK signing certificate for security issues"""

    def analyze(self, apk_result) -> dict:
        """
        Extract and analyze signing certificate.

        Args:
            apk_result: APKParseResult from apk_parser

        Returns:
            dict with findings
        """
        findings = []
        a = apk_result.apk

        try:
            # Get certificates from APK
            certs = a.get_certificates()
            if not certs:
                findings.append({
                    'type': 'Missing Signing Certificate',
                    'severity': 'CRITICAL',
                    'value': 'No signing certificate found',
                    'source': 'APK',
                    'description': 'The APK has no signing certificate. Unsigned APKs cannot be installed on Android.',
                    'recommendation': 'Sign the APK with a properly generated signing key.',
                })
                return self._format_result(findings)

            for i, cert in enumerate(certs):
                try:
                    # Extract certificate details
                    subject = self._get_dn_string(cert.subject)
                    issuer = self._get_dn_string(cert.issuer)

                    # Validity period
                    not_before = cert.not_valid_before
                    not_after = cert.not_valid_after

                    # Ensure timezone-aware comparison
                    now = datetime.now(timezone.utc)
                    if not_before.tzinfo is None:
                        not_before = not_before.replace(tzinfo=timezone.utc)
                    if not_after.tzinfo is None:
                        not_after = not_after.replace(tzinfo=timezone.utc)

                    # Check for debug certificate
                    is_debug = self._is_debug_cert(subject, issuer)
                    if is_debug:
                        findings.append({
                            'type': 'Debug Signing Certificate',
                            'severity': 'CRITICAL',
                            'value': f'Subject: {subject}',
                            'source': 'APK Certificate',
                            'description': (
                                'The APK is signed with a debug certificate (CN=Android Debug). '
                                'Debug-signed APKs should NEVER be distributed to users. '
                                'They indicate a development build.'
                            ),
                            'recommendation': 'Sign the APK with a production release key stored securely.',
                        })

                    # Check expiry
                    if now > not_after:
                        days_expired = (now - not_after).days
                        findings.append({
                            'type': 'Expired Signing Certificate',
                            'severity': 'HIGH',
                            'value': f'Expired {days_expired} days ago ({not_after.strftime("%Y-%m-%d")})',
                            'source': 'APK Certificate',
                            'description': f'The signing certificate expired on {not_after.strftime("%Y-%m-%d")}. Android may reject updates signed with expired certificates.',
                            'recommendation': 'Generate a new signing key with a long validity period (25+ years). Migrate using APK Signature Scheme v3 key rotation.',
                        })
                    elif (not_after - now).days < 365:
                        days_remaining = (not_after - now).days
                        findings.append({
                            'type': 'Certificate Expiring Soon',
                            'severity': 'MEDIUM',
                            'value': f'Expires in {days_remaining} days ({not_after.strftime("%Y-%m-%d")})',
                            'source': 'APK Certificate',
                            'description': f'The signing certificate expires in {days_remaining} days.',
                            'recommendation': 'Plan certificate rotation using APK Signature Scheme v3.',
                        })

                    # Certificate info (informational)
                    validity_years = (not_after - not_before).days / 365
                    findings.append({
                        'type': 'Certificate Details',
                        'severity': 'LOW',
                        'value': f'Subject: {subject}',
                        'source': 'APK Certificate',
                        'context': f'Issuer: {issuer}',
                        'description': (
                            f'Signing certificate details — '
                            f'Valid: {not_before.strftime("%Y-%m-%d")} to {not_after.strftime("%Y-%m-%d")} '
                            f'({validity_years:.0f} years). '
                            f'{"Debug" if is_debug else "Release"} certificate.'
                        ),
                        'recommendation': 'Ensure the signing key is stored securely and backed up.',
                    })

                except Exception:
                    continue

        except Exception as e:
            findings.append({
                'type': 'Certificate Analysis Error',
                'severity': 'LOW',
                'value': f'Could not analyze certificates: {str(e)[:80]}',
                'source': 'APK',
                'description': 'Unable to extract signing certificate information.',
                'recommendation': 'The APK may use an unsupported signature scheme.',
            })

        return self._format_result(findings)

    def _is_debug_cert(self, subject: str, issuer: str) -> bool:
        """Check if certificate is a debug certificate"""
        debug_markers = [
            'android debug', 'cn=android debug',
        ]
        combined = f'{subject} {issuer}'.lower()
        return any(marker in combined for marker in debug_markers)

    def _get_dn_string(self, dn) -> str:
        """Convert certificate distinguished name to readable string"""
        try:
            return dn.human_friendly
        except Exception:
            try:
                parts = []
                for attr in dn:
                    for name_attr in attr:
                        parts.append(f'{name_attr.oid._name}={name_attr.value}')
                return ', '.join(parts)
            except Exception:
                return str(dn)

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
            'category': 'Certificate Security',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Signing certificate analysis: {len(findings)} finding(s).'
        }
