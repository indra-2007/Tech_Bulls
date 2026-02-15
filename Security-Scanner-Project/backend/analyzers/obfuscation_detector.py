"""Obfuscation Detector
Analyzes DEX class name patterns to determine if the app uses
ProGuard/R8 obfuscation, DexGuard, or no obfuscation.
"""

import re
from collections import Counter
from typing import List, Dict


class ObfuscationDetector:
    """Detects code obfuscation by analyzing class name patterns"""

    # ProGuard default mapping: single lowercase letter class names
    PROGUARD_PATTERN = re.compile(r'^[a-z]{1,2}(\.[a-z]{1,2})*$')

    # Known obfuscator markers
    OBFUSCATOR_MARKERS = {
        'ProGuard': [
            re.compile(r'^[a-z]{1,2}\.[a-z]{1,2}\.[a-z]{1,2}$'),  # a.b.c
            re.compile(r'\$\d+$'),  # Class$1 (anonymous inner class)
        ],
        'DexGuard': [
            re.compile(r'^[oO0]+$'),  # oOo0O patterns
            re.compile(r'^[Il1]+$'),  # IlIl patterns
        ],
        'R8': [
            re.compile(r'^[a-z]\.[a-z]\.[a-z]{1,3}$'),  # Similar to ProGuard but from R8
        ],
    }

    # Known non-obfuscated prefixes (framework, libraries)
    FRAMEWORK_PREFIXES = [
        'android.', 'java.', 'javax.', 'kotlin.', 'kotlinx.',
        'com.google.android.', 'com.google.firebase.',
        'androidx.', 'org.apache.', 'org.json.',
        'dalvik.', 'sun.', 'com.sun.',
    ]

    def analyze(self, apk_result) -> dict:
        """
        Analyze class names to detect obfuscation level.

        Args:
            apk_result: APKParseResult from apk_parser

        Returns:
            dict with findings
        """
        findings = []

        # Get internal class names only
        class_names = []
        try:
            for c in apk_result.analysis.get_classes():
                if not c.is_external():
                    name = str(c.name).replace('/', '.').strip('L;')
                    # Skip framework/library classes
                    if not any(name.startswith(prefix) for prefix in self.FRAMEWORK_PREFIXES):
                        class_names.append(name)
        except Exception:
            return self._format_result(findings)

        if not class_names:
            return self._format_result(findings)

        total_classes = len(class_names)

        # Analyze naming patterns
        short_name_count = 0  # 1-2 char segment names
        proguard_count = 0
        dexguard_count = 0
        normal_count = 0

        for name in class_names:
            segments = name.split('.')
            last_segment = segments[-1] if segments else name

            # Check for ProGuard-style short names
            if len(last_segment) <= 2 and last_segment.isalpha() and last_segment.islower():
                short_name_count += 1
                proguard_count += 1
            elif any(p.match(last_segment) for p in self.OBFUSCATOR_MARKERS.get('DexGuard', [])):
                dexguard_count += 1
            elif self.PROGUARD_PATTERN.match(name):
                proguard_count += 1
            else:
                normal_count += 1

        # Calculate obfuscation ratio
        obfuscated_count = short_name_count + proguard_count + dexguard_count
        # Avoid double counting
        obfuscated_count = min(obfuscated_count, total_classes)
        obfuscation_ratio = obfuscated_count / total_classes if total_classes > 0 else 0

        # Determine obfuscation level
        if obfuscation_ratio >= 0.7:
            level = 'Heavily Obfuscated'
            severity = 'LOW'
            description = (
                f'{obfuscation_ratio*100:.0f}% of classes ({obfuscated_count}/{total_classes}) have obfuscated names. '
                f'The app uses strong code obfuscation (likely ProGuard/R8), making reverse engineering harder. '
                f'This is a GOOD security practice.'
            )
            recommendation = 'Obfuscation is properly applied. Ensure ProGuard rules don\'t exclude security-critical classes.'
        elif obfuscation_ratio >= 0.3:
            level = 'Partially Obfuscated'
            severity = 'MEDIUM'
            description = (
                f'{obfuscation_ratio*100:.0f}% of classes ({obfuscated_count}/{total_classes}) are obfuscated. '
                f'The app has partial obfuscation — some code is protected but significant portions remain readable.'
            )
            recommendation = 'Improve ProGuard/R8 configuration to obfuscate all non-public API classes.'
        else:
            level = 'Not Obfuscated'
            severity = 'MEDIUM'
            description = (
                f'Only {obfuscation_ratio*100:.0f}% of classes ({obfuscated_count}/{total_classes}) appear obfuscated. '
                f'The app code is largely unprotected and can be easily decompiled and read.'
            )
            recommendation = 'Enable ProGuard/R8 in your Gradle build. Add minifyEnabled true and R8 rules.'

        findings.append({
            'type': f'Obfuscation Level: {level}',
            'severity': severity,
            'value': f'{obfuscation_ratio*100:.0f}% obfuscated ({obfuscated_count}/{total_classes} classes)',
            'source': 'DEX',
            'description': description,
            'recommendation': recommendation,
        })

        # Detect specific obfuscator
        detected_obfuscator = 'Unknown'
        if proguard_count > dexguard_count:
            detected_obfuscator = 'ProGuard/R8'
        elif dexguard_count > 0:
            detected_obfuscator = 'DexGuard'

        if obfuscation_ratio >= 0.3:
            findings.append({
                'type': 'Obfuscator Detected',
                'severity': 'LOW',
                'value': detected_obfuscator,
                'source': 'DEX',
                'description': f'Likely obfuscation tool: {detected_obfuscator}. Detected based on class naming patterns.',
                'recommendation': 'Consider using DexGuard for advanced obfuscation (string encryption, control flow obfuscation) beyond basic ProGuard.',
            })

        # Show sample class names
        sample_short = [n for n in class_names if len(n.split('.')[-1]) <= 2][:5]
        sample_normal = [n for n in class_names if len(n.split('.')[-1]) > 2][:5]

        if sample_short:
            findings.append({
                'type': 'Sample Obfuscated Classes',
                'severity': 'LOW',
                'value': ', '.join(sample_short),
                'source': 'DEX',
                'description': f'Example obfuscated class names found in the APK.',
                'recommendation': 'These short names indicate ProGuard/R8 obfuscation is applied.',
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
            'category': 'Code Obfuscation',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Obfuscation analysis: {len(findings)} finding(s) about code protection level.'
        }
