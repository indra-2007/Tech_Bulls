"""Permission-Risk Correlation Analyzer
Correlates Android permission combinations to detect
data exfiltration, surveillance, and spam risk vectors.
"""

from typing import List, Dict


class PermissionRiskAnalyzer:
    """Detects dangerous permission combinations that indicate data exfiltration risk"""

    # ── Risk Correlation Rules ────────────────────────────────────────
    # Each rule: (required_permissions, risk_name, severity, description, recommendation)
    RISK_RULES = [
        # Data Exfiltration
        (
            ['android.permission.READ_SMS', 'android.permission.INTERNET'],
            'SMS Data Exfiltration Risk',
            'CRITICAL',
            'App can read SMS messages and transmit them over the internet. '
            'This combination is commonly used in banking trojans and spyware.',
            'Unless this app is an SMS client, remove READ_SMS permission. '
            'Verify the app does not upload SMS content to remote servers.',
        ),
        (
            ['android.permission.READ_CONTACTS', 'android.permission.INTERNET'],
            'Contact Exfiltration Risk',
            'HIGH',
            'App can read the contact list and send it over the internet. '
            'This enables harvesting of personal contact information.',
            'Verify that contact access is essential. Minimize data sent to servers.',
        ),
        (
            ['android.permission.READ_CALL_LOG', 'android.permission.INTERNET'],
            'Call Log Exfiltration Risk',
            'HIGH',
            'App can access call history and transmit it remotely. '
            'Call logs contain sensitive communication metadata.',
            'Remove READ_CALL_LOG unless absolutely needed for core functionality.',
        ),
        (
            ['android.permission.ACCESS_FINE_LOCATION', 'android.permission.INTERNET'],
            'Location Tracking Risk',
            'HIGH',
            'App can track precise GPS location and transmit it to a server. '
            'This enables real-time location surveillance.',
            'Use ACCESS_COARSE_LOCATION if precise location is not needed. '
            'Implement location access only when the app is in foreground.',
        ),

        # Surveillance
        (
            ['android.permission.CAMERA', 'android.permission.RECORD_AUDIO', 'android.permission.INTERNET'],
            'Surveillance Risk (Camera + Microphone)',
            'CRITICAL',
            'App can capture photos/video, record audio, and upload to a remote server. '
            'This combination enables full audio-visual surveillance.',
            'Verify camera and microphone access are core to app functionality. '
            'Ensure explicit user consent for each recording session.',
        ),
        (
            ['android.permission.RECORD_AUDIO', 'android.permission.INTERNET'],
            'Audio Surveillance Risk',
            'HIGH',
            'App can record audio from the microphone and transmit remotely.',
            'Remove RECORD_AUDIO unless needed for core features like voice calls or voice input.',
        ),
        (
            ['android.permission.CAMERA', 'android.permission.INTERNET'],
            'Camera Surveillance Risk',
            'MEDIUM',
            'App can capture photos/video and upload to a remote server.',
            'Ensure camera use is clearly visible to the user with an indicator.',
        ),

        # Spam / Fraud
        (
            ['android.permission.READ_CONTACTS', 'android.permission.SEND_SMS'],
            'SMS Spam Risk',
            'CRITICAL',
            'App can read contacts and send SMS messages. '
            'This enables SMS spam to the user\'s entire contact list.',
            'This permission combination is extremely dangerous. '
            'Remove SEND_SMS or READ_CONTACTS unless absolutely required.',
        ),
        (
            ['android.permission.SEND_SMS', 'android.permission.INTERNET'],
            'Premium SMS Fraud Risk',
            'HIGH',
            'App can send SMS and has internet access. '
            'Could be used for premium SMS fraud (sending to paid numbers).',
            'Verify SEND_SMS is essential. Monitor for unauthorized premium SMS charges.',
        ),

        # Financial Risk
        (
            ['android.permission.READ_SMS', 'android.permission.READ_PHONE_STATE'],
            'OTP Interception Risk',
            'CRITICAL',
            'App can read SMS (including OTPs) and phone state. '
            'This enables interception of two-factor authentication codes.',
            'SMS-based OTP reading should use the SMS Retriever API instead of READ_SMS.',
        ),

        # App Installation
        (
            ['android.permission.REQUEST_INSTALL_PACKAGES', 'android.permission.INTERNET'],
            'Sideloading Risk',
            'HIGH',
            'App can download and install other APKs from the internet. '
            'This enables silent installation of malware.',
            'Remove REQUEST_INSTALL_PACKAGES unless this is an app store or updater.',
        ),

        # Overlay Attacks
        (
            ['android.permission.SYSTEM_ALERT_WINDOW', 'android.permission.INTERNET'],
            'Overlay Attack Risk',
            'HIGH',
            'App can draw overlays on other apps (tapjacking) and has internet access. '
            'This enables credential phishing through overlay windows.',
            'Remove SYSTEM_ALERT_WINDOW. Use standard notifications or in-app dialogs.',
        ),

        # Storage + Network
        (
            ['android.permission.READ_EXTERNAL_STORAGE', 'android.permission.INTERNET'],
            'File Exfiltration Risk',
            'MEDIUM',
            'App can read ALL files on external storage and send them over the internet.',
            'Use Scoped Storage (Android 10+) to limit file access to app-specific directories.',
        ),
    ]

    # ── Excessive Privilege Threshold ─────────────────────────────────
    EXCESSIVE_PERMISSION_THRESHOLD = 10  # Dangerous permissions

    def analyze(self, apk_result) -> dict:
        """
        Analyze permission combinations for correlated risk.

        Args:
            apk_result: APKParseResult from apk_parser

        Returns:
            dict with findings
        """
        findings = []
        a = apk_result.apk

        try:
            permissions = set(a.get_permissions())
        except Exception:
            return self._format_result(findings)

        # 1. Check each risk rule
        for required_perms, risk_name, severity, description, recommendation in self.RISK_RULES:
            if all(perm in permissions for perm in required_perms):
                perm_short = [p.split('.')[-1] for p in required_perms]
                findings.append({
                    'type': risk_name,
                    'severity': severity,
                    'value': ' + '.join(perm_short),
                    'source': 'Permission Correlation',
                    'context': f'Permissions: {", ".join(perm_short)}',
                    'description': description,
                    'recommendation': recommendation,
                })

        # 2. Check for excessive permissions
        from analyzers.manifest_analyzer import ManifestAnalyzer
        dangerous_perms = [p for p in permissions if p in ManifestAnalyzer.DANGEROUS_PERMISSIONS]
        if len(dangerous_perms) >= self.EXCESSIVE_PERMISSION_THRESHOLD:
            perm_short = [p.split('.')[-1] for p in dangerous_perms]
            findings.append({
                'type': 'Excessive Permissions',
                'severity': 'HIGH',
                'value': f'{len(dangerous_perms)} dangerous permissions requested',
                'source': 'Permission Correlation',
                'context': f'Permissions: {", ".join(perm_short[:10])}...',
                'description': (
                    f'The app requests {len(dangerous_perms)} dangerous permissions, which is '
                    f'significantly more than most apps need. This increases the attack surface '
                    f'and the potential impact of any vulnerability.'
                ),
                'recommendation': 'Apply the principle of least privilege. Remove all permissions not strictly required.',
            })

        return self._format_result(findings)

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
            'category': 'Permission Risk Correlation',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Permission correlation analysis: {len(findings)} risk vector(s) detected from permission combinations.'
        }
