"""Component Exposure Risk Scorer
Scores exported Android components (Activities, Services, Receivers, Providers)
based on their exposure level, permission protection, and intent-filter configuration.
"""

import xml.etree.ElementTree as ET
from typing import List, Dict


class ComponentExposureAnalyzer:
    """Scores exported components for exposure risk"""

    def analyze(self, apk_result) -> dict:
        """
        Analyze exported components for exposure risk.

        Args:
            apk_result: APKParseResult from apk_parser

        Returns:
            dict with findings
        """
        findings = []
        a = apk_result.apk

        try:
            manifest_xml = a.get_android_manifest_axml().get_xml()
        except Exception:
            return self._format_result(findings)

        try:
            root = ET.fromstring(manifest_xml)
        except Exception:
            return self._format_result(findings)

        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        android_ns = '{http://schemas.android.com/apk/res/android}'

        # Track totals for summary
        total_components = 0
        exported_count = 0
        unprotected_count = 0

        component_tags = ['activity', 'service', 'receiver', 'provider']

        for comp_tag in component_tags:
            for elem in root.iter(comp_tag):
                total_components += 1
                comp_name = elem.get(f'{android_ns}name', 'Unknown')
                short_name = comp_name.split('.')[-1]
                exported_attr = elem.get(f'{android_ns}exported')
                permission_attr = elem.get(f'{android_ns}permission')

                # Check intent-filters
                intent_filters = elem.findall('intent-filter')
                has_intent_filter = len(intent_filters) > 0

                # Determine if exported
                is_exported = False
                if exported_attr == 'true':
                    is_exported = True
                elif exported_attr is None and has_intent_filter:
                    # Implicitly exported (pre-Android 12 behavior)
                    is_exported = True

                if not is_exported:
                    continue

                exported_count += 1

                # Check if launcher activity (expected to be exported)
                is_launcher = False
                for if_elem in intent_filters:
                    actions = [a.get(f'{android_ns}name', '') for a in if_elem.findall('action')]
                    categories = [c.get(f'{android_ns}name', '') for c in if_elem.findall('category')]
                    if ('android.intent.action.MAIN' in actions and
                        'android.intent.category.LAUNCHER' in categories):
                        is_launcher = True
                        break

                if is_launcher:
                    # Launcher is expected to be exported, no finding needed
                    continue

                # Calculate risk score for this component
                risk_score = 0
                risk_factors = []

                if not permission_attr:
                    risk_score += 40
                    risk_factors.append('No permission protection')
                    unprotected_count += 1
                else:
                    risk_score += 10
                    risk_factors.append(f'Protected by: {permission_attr}')

                if has_intent_filter:
                    risk_score += 20
                    risk_factors.append('Has intent-filter (broadens attack surface)')

                if exported_attr is None and has_intent_filter:
                    risk_score += 15
                    risk_factors.append('Implicitly exported (no explicit exported attribute)')

                if comp_tag == 'provider':
                    risk_score += 25
                    risk_factors.append('Content Provider (may expose data)')
                elif comp_tag == 'service':
                    risk_score += 15
                    risk_factors.append('Service (may perform privileged operations)')
                elif comp_tag == 'receiver':
                    risk_score += 10
                    risk_factors.append('Broadcast Receiver (can receive intents)')

                # Determine severity from risk score
                if risk_score >= 60:
                    severity = 'HIGH'
                elif risk_score >= 40:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'

                comp_label = comp_tag.capitalize()
                findings.append({
                    'type': f'Exposed {comp_label}: {short_name}',
                    'severity': severity,
                    'value': comp_name,
                    'source': 'AndroidManifest.xml',
                    'context': f'Risk score: {risk_score}/100. Factors: {", ".join(risk_factors)}',
                    'description': (
                        f'Exported {comp_label} "{short_name}" is accessible to other apps on the device. '
                        f'Risk factors: {"; ".join(risk_factors)}.'
                    ),
                    'recommendation': (
                        f'Set android:exported="false" if this {comp_label.lower()} should not be accessible '
                        f'to other applications. If it must be exported, protect it with a signature-level '
                        f'custom permission.'
                    ),
                })

        # Summary finding
        if exported_count > 0:
            findings.append({
                'type': 'Component Exposure Summary',
                'severity': 'MEDIUM' if unprotected_count > 0 else 'LOW',
                'value': f'{exported_count} exported, {unprotected_count} unprotected (of {total_components} total)',
                'source': 'AndroidManifest.xml',
                'description': (
                    f'Of {total_components} total components, {exported_count} are exported and '
                    f'{unprotected_count} lack permission protection.'
                ),
                'recommendation': 'Minimize exported components. Protect all exported components with appropriate permissions.',
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
            'category': 'Component Exposure',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Component exposure analysis: {len(findings)} finding(s) about exported component risk.'
        }
