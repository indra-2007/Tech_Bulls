"""Manifest Analyzer
Structured analysis of AndroidManifest.xml via Androguard APK object.
Detects dangerous permissions, risky application flags, and exported components.
"""

import xml.etree.ElementTree as ET
from typing import List, Dict, Optional


class ManifestAnalyzer:
    """Analyzes AndroidManifest.xml for security issues using Androguard APK object"""

    # Dangerous permissions with severity and category
    DANGEROUS_PERMISSIONS = {
        'android.permission.READ_SMS': {'severity': 'HIGH', 'category': 'SMS', 'risk': 'Can read all SMS messages'},
        'android.permission.SEND_SMS': {'severity': 'HIGH', 'category': 'SMS', 'risk': 'Can send SMS (potential premium SMS fraud)'},
        'android.permission.RECEIVE_SMS': {'severity': 'HIGH', 'category': 'SMS', 'risk': 'Can intercept incoming SMS'},
        'android.permission.READ_CONTACTS': {'severity': 'HIGH', 'category': 'Contacts', 'risk': 'Can read contact list'},
        'android.permission.WRITE_CONTACTS': {'severity': 'HIGH', 'category': 'Contacts', 'risk': 'Can modify contacts'},
        'android.permission.GET_ACCOUNTS': {'severity': 'MEDIUM', 'category': 'Contacts', 'risk': 'Can enumerate device accounts'},
        'android.permission.ACCESS_FINE_LOCATION': {'severity': 'HIGH', 'category': 'Location', 'risk': 'Precise GPS location tracking'},
        'android.permission.ACCESS_COARSE_LOCATION': {'severity': 'MEDIUM', 'category': 'Location', 'risk': 'Approximate location tracking'},
        'android.permission.RECORD_AUDIO': {'severity': 'HIGH', 'category': 'Microphone', 'risk': 'Can record audio from microphone'},
        'android.permission.CAMERA': {'severity': 'HIGH', 'category': 'Camera', 'risk': 'Can capture photos/video'},
        'android.permission.READ_PHONE_STATE': {'severity': 'MEDIUM', 'category': 'Phone', 'risk': 'Can read IMEI, phone number, carrier'},
        'android.permission.READ_PHONE_NUMBERS': {'severity': 'MEDIUM', 'category': 'Phone', 'risk': 'Can read phone numbers'},
        'android.permission.CALL_PHONE': {'severity': 'MEDIUM', 'category': 'Phone', 'risk': 'Can make phone calls without user interaction'},
        'android.permission.READ_CALL_LOG': {'severity': 'HIGH', 'category': 'Phone', 'risk': 'Can read call history'},
        'android.permission.WRITE_CALL_LOG': {'severity': 'HIGH', 'category': 'Phone', 'risk': 'Can modify call history'},
        'android.permission.READ_CALENDAR': {'severity': 'MEDIUM', 'category': 'Calendar', 'risk': 'Can read calendar events'},
        'android.permission.WRITE_CALENDAR': {'severity': 'MEDIUM', 'category': 'Calendar', 'risk': 'Can modify calendar events'},
        'android.permission.BODY_SENSORS': {'severity': 'MEDIUM', 'category': 'Sensors', 'risk': 'Can access body sensor data'},
        'android.permission.READ_EXTERNAL_STORAGE': {'severity': 'MEDIUM', 'category': 'Storage', 'risk': 'Can read all files on storage'},
        'android.permission.WRITE_EXTERNAL_STORAGE': {'severity': 'MEDIUM', 'category': 'Storage', 'risk': 'Can write/modify files on storage'},
        'android.permission.SYSTEM_ALERT_WINDOW': {'severity': 'HIGH', 'category': 'System', 'risk': 'Can draw overlays on other apps (tapjacking)'},
        'android.permission.WRITE_SETTINGS': {'severity': 'MEDIUM', 'category': 'System', 'risk': 'Can modify system settings'},
        'android.permission.REQUEST_INSTALL_PACKAGES': {'severity': 'HIGH', 'category': 'System', 'risk': 'Can install other APKs silently'},
        'android.permission.QUERY_ALL_PACKAGES': {'severity': 'MEDIUM', 'category': 'System', 'risk': 'Can enumerate all installed apps'},
        'android.permission.PROCESS_OUTGOING_CALLS': {'severity': 'MEDIUM', 'category': 'Phone', 'risk': 'Can intercept outgoing calls'},
        'android.permission.RECEIVE_MMS': {'severity': 'MEDIUM', 'category': 'SMS', 'risk': 'Can intercept MMS messages'},
        'android.permission.RECEIVE_WAP_PUSH': {'severity': 'MEDIUM', 'category': 'SMS', 'risk': 'Can receive WAP push messages'},
        'android.permission.ADD_VOICEMAIL': {'severity': 'LOW', 'category': 'Phone', 'risk': 'Can add voicemail'},
        'android.permission.USE_SIP': {'severity': 'LOW', 'category': 'Phone', 'risk': 'Can use SIP calls'},
        'android.permission.INTERNET': {'severity': 'LOW', 'category': 'Network', 'risk': 'Can access the internet'},
        'android.permission.ACCESS_NETWORK_STATE': {'severity': 'LOW', 'category': 'Network', 'risk': 'Can check network connectivity'},
        'android.permission.ACCESS_WIFI_STATE': {'severity': 'LOW', 'category': 'Network', 'risk': 'Can check WiFi state'},
    }

    def analyze(self, apk_result) -> dict:
        """
        Full manifest analysis.

        Args:
            apk_result: APKParseResult from apk_parser

        Returns:
            dict with findings_by_category structure
        """
        findings = []
        a = apk_result.apk

        # 1. Application flags
        findings.extend(self._check_application_flags(a))

        # 2. Dangerous permissions
        findings.extend(self._check_permissions(a))

        # 3. Exported components
        findings.extend(self._check_exported_components(a))

        return self._format_result(findings)

    def _check_application_flags(self, apk) -> List[Dict]:
        """Check dangerous application flags in manifest"""
        findings = []

        try:
            manifest_xml = apk.get_android_manifest_axml().get_xml()
        except Exception:
            manifest_xml = ""

        # android:debuggable
        try:
            if apk.get_element('application', 'debuggable') == 'true':
                findings.append({
                    'type': 'Debuggable Application',
                    'severity': 'CRITICAL',
                    'value': 'android:debuggable="true"',
                    'source': 'AndroidManifest.xml',
                    'description': 'Application is built in debug mode. Attackers can attach a debugger, inspect memory, and extract sensitive data at runtime.',
                    'recommendation': 'Set android:debuggable="false" in the release build. This should be handled by your build system (release vs debug variants).',
                })
        except Exception:
            # Fallback: check raw XML
            if 'debuggable="true"' in manifest_xml or "debuggable='true'" in manifest_xml:
                findings.append({
                    'type': 'Debuggable Application',
                    'severity': 'CRITICAL',
                    'value': 'android:debuggable="true"',
                    'source': 'AndroidManifest.xml',
                    'description': 'Application is built in debug mode.',
                    'recommendation': 'Set android:debuggable="false" for release builds.',
                })

        # android:allowBackup
        try:
            if apk.get_element('application', 'allowBackup') == 'true':
                findings.append({
                    'type': 'Backup Allowed',
                    'severity': 'HIGH',
                    'value': 'android:allowBackup="true"',
                    'source': 'AndroidManifest.xml',
                    'description': 'Application data can be backed up via ADB. An attacker with physical access can extract app data including databases, shared preferences, and files.',
                    'recommendation': 'Set android:allowBackup="false" unless backup functionality is explicitly needed and data is encrypted.',
                })
        except Exception:
            if 'allowBackup="true"' in manifest_xml:
                findings.append({
                    'type': 'Backup Allowed',
                    'severity': 'HIGH',
                    'value': 'android:allowBackup="true"',
                    'source': 'AndroidManifest.xml',
                    'description': 'Application data can be backed up via ADB.',
                    'recommendation': 'Set android:allowBackup="false" for sensitive applications.',
                })

        # android:usesCleartextTraffic
        try:
            if apk.get_element('application', 'usesCleartextTraffic') == 'true':
                findings.append({
                    'type': 'Cleartext Traffic Allowed',
                    'severity': 'HIGH',
                    'value': 'android:usesCleartextTraffic="true"',
                    'source': 'AndroidManifest.xml',
                    'description': 'Application allows unencrypted HTTP traffic. Data transmitted over HTTP can be intercepted by attackers via man-in-the-middle attacks.',
                    'recommendation': 'Set android:usesCleartextTraffic="false" and use HTTPS for all network communication.',
                })
        except Exception:
            if 'usesCleartextTraffic="true"' in manifest_xml:
                findings.append({
                    'type': 'Cleartext Traffic Allowed',
                    'severity': 'HIGH',
                    'value': 'android:usesCleartextTraffic="true"',
                    'source': 'AndroidManifest.xml',
                    'description': 'Application allows unencrypted HTTP traffic.',
                    'recommendation': 'Set android:usesCleartextTraffic="false".',
                })

        # android:networkSecurityConfig — check if missing
        try:
            nsc = apk.get_element('application', 'networkSecurityConfig')
            if not nsc:
                findings.append({
                    'type': 'Missing Network Security Config',
                    'severity': 'MEDIUM',
                    'value': 'No android:networkSecurityConfig defined',
                    'source': 'AndroidManifest.xml',
                    'description': 'No custom network security configuration. The app relies on platform defaults which may vary across Android versions.',
                    'recommendation': 'Add a network_security_config.xml to explicitly define trusted CAs and certificate pinning.',
                })
        except Exception:
            pass

        return findings

    def _check_permissions(self, apk) -> List[Dict]:
        """Detect dangerous permissions"""
        findings = []

        try:
            permissions = apk.get_permissions()
        except Exception:
            return findings

        for perm in permissions:
            perm_str = str(perm)
            if perm_str in self.DANGEROUS_PERMISSIONS:
                info = self.DANGEROUS_PERMISSIONS[perm_str]
                perm_short = perm_str.split('.')[-1]
                findings.append({
                    'type': f'Dangerous Permission: {perm_short}',
                    'severity': info['severity'],
                    'value': perm_str,
                    'source': 'AndroidManifest.xml',
                    'context': f"Category: {info['category']}",
                    'description': info['risk'],
                    'recommendation': f'Verify that {perm_short} is essential for core app functionality. Remove if not strictly needed.',
                })

        return findings

    def _check_exported_components(self, apk) -> List[Dict]:
        """Check for exported components without permission protection"""
        findings = []
        manifest_xml = ""
        try:
            manifest_xml = apk.get_android_manifest_axml().get_xml()
        except Exception:
            pass

        component_types = {
            'activity': ('get_activities', 'Activity'),
            'service': ('get_services', 'Service'),
            'receiver': ('get_receivers', 'Receiver'),
            'provider': ('get_providers', 'Provider'),
        }

        for comp_type, (getter_name, label) in component_types.items():
            try:
                getter = getattr(apk, getter_name, None)
                if not getter:
                    continue
                components = getter()
                for comp_name in components:
                    # Check if exported
                    is_exported = False
                    has_intent_filter = False
                    has_permission = False
                    is_launcher = False

                    # Parse from manifest XML
                    try:
                        root = ET.fromstring(manifest_xml)
                        ns = {'android': 'http://schemas.android.com/apk/res/android'}

                        for elem in root.iter(comp_type):
                            name = elem.get('{http://schemas.android.com/apk/res/android}name', '')
                            if name == comp_name or name.endswith(comp_name.split('.')[-1]):
                                exported_attr = elem.get('{http://schemas.android.com/apk/res/android}exported')
                                permission_attr = elem.get('{http://schemas.android.com/apk/res/android}permission')

                                if exported_attr == 'true':
                                    is_exported = True
                                if permission_attr:
                                    has_permission = True

                                # Check intent-filters
                                intent_filters = elem.findall('intent-filter')
                                if intent_filters:
                                    has_intent_filter = True
                                    # Components with intent-filters are implicitly exported
                                    if exported_attr is None:
                                        is_exported = True

                                    # Check if launcher
                                    for if_elem in intent_filters:
                                        for action in if_elem.findall('action'):
                                            action_name = action.get('{http://schemas.android.com/apk/res/android}name', '')
                                            if action_name == 'android.intent.action.MAIN':
                                                for cat in if_elem.findall('category'):
                                                    cat_name = cat.get('{http://schemas.android.com/apk/res/android}name', '')
                                                    if cat_name == 'android.intent.category.LAUNCHER':
                                                        is_launcher = True
                                break
                    except Exception:
                        pass

                    if is_exported and not is_launcher:
                        if not has_permission:
                            severity = 'HIGH'
                            desc = (
                                f'Exported {label} "{comp_name.split(".")[-1]}" has no permission protection. '
                                f'Any app on the device can interact with this component, potentially leading to '
                                f'data leaks or unauthorized actions.'
                            )
                        else:
                            severity = 'LOW'
                            desc = (
                                f'Exported {label} "{comp_name.split(".")[-1]}" is protected by a permission. '
                                f'Verify the permission level is appropriate.'
                            )

                        findings.append({
                            'type': f'Exported {label}',
                            'severity': severity,
                            'value': comp_name,
                            'source': 'AndroidManifest.xml',
                            'context': f'intent-filter: {has_intent_filter}, permission-protected: {has_permission}',
                            'description': desc,
                            'recommendation': f'Add android:exported="false" or protect with a signature-level permission if this {label.lower()} should not be accessible to other apps.',
                        })

            except Exception:
                continue

        return findings

    def _format_result(self, findings: List[Dict]) -> dict:
        """Format results for the report generator"""
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
            'category': 'Manifest Security',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Found {len(findings)} manifest security issue(s) including permissions, flags, and exported components.'
        }
