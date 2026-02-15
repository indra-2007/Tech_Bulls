"""Shannon Entropy Analyzer
Calculates Shannon entropy of DEX strings to detect high-entropy values
that may indicate encrypted data, encoded secrets, or obfuscated tokens.
Only operates on structured DEX strings — NOT raw binary.
"""

import math
from collections import Counter
from typing import List, Dict


class EntropyAnalyzer:
    """Detects high-entropy strings in DEX that may contain secrets"""

    # Minimum string length to analyze
    MIN_STRING_LENGTH = 20

    # Entropy thresholds (Shannon entropy on ASCII: 0-8 scale)
    HIGH_ENTROPY_THRESHOLD = 4.5
    VERY_HIGH_ENTROPY_THRESHOLD = 5.5

    # Exclusion patterns — common high-entropy non-secrets
    EXCLUSION_SUBSTRINGS = [
        'http://', 'https://', 'file://', 'content://',
        'android.', 'com.android.', 'java.', 'javax.',
        'org.apache.', 'org.json.', 'org.xml.',
        'res/', 'drawable', 'layout/', 'values/',
        '.png', '.jpg', '.xml', '.dex',
    ]

    def analyze(self, apk_result, exclude_values: set = None) -> dict:
        """
        Calculate Shannon entropy on all DEX strings.
        Flag strings with entropy >= threshold as potential secrets.
        Strings already identified by SecretDetector are excluded.

        Args:
            apk_result: APKParseResult from apk_parser
            exclude_values: Set of string values already identified as secrets

        Returns:
            dict with findings
        """
        findings = []
        analyzed_count = 0
        seen_values = set()
        excludes = exclude_values or set()

        for ctx in apk_result.dex_string_contexts:
            string_value = ctx['value']

            # Skip short strings
            if len(string_value) < self.MIN_STRING_LENGTH:
                continue

            # Skip known non-secret patterns
            if self._should_exclude(string_value):
                continue

            # Skip duplicates
            if string_value in seen_values:
                continue
            seen_values.add(string_value)

            # Skip strings already identified as secrets by SecretDetector
            is_known_secret = False
            for secret_val in excludes:
                if secret_val and len(secret_val) >= 10 and (
                    secret_val in string_value or string_value in secret_val
                ):
                    is_known_secret = True
                    break
            if is_known_secret:
                continue

            analyzed_count += 1

            # Calculate Shannon entropy
            entropy = self._calculate_shannon_entropy(string_value)

            if entropy >= self.HIGH_ENTROPY_THRESHOLD:
                # Determine severity based on entropy level
                if entropy >= self.VERY_HIGH_ENTROPY_THRESHOLD:
                    severity = 'HIGH'
                    level = 'very high'
                elif entropy >= 5.0:
                    severity = 'MEDIUM'
                    level = 'high'
                else:
                    severity = 'LOW'
                    level = 'elevated'

                truncated = string_value[:50] + '...' if len(string_value) > 50 else string_value

                findings.append({
                    'type': 'High Entropy String',
                    'severity': severity,
                    'value': truncated,
                    'entropy': round(entropy, 2),
                    'length': len(string_value),
                    'source': 'DEX',
                    'class_name': ctx.get('class_name'),
                    'method_name': ctx.get('method_name'),
                    'context': f"Class: {ctx.get('class_name', 'N/A')}, Method: {ctx.get('method_name', 'N/A')}",
                    'description': (
                        f'String with {level} randomness (Shannon entropy: {round(entropy, 2)}). '
                        f'High-entropy strings may indicate encrypted data, base64-encoded secrets, '
                        f'cryptographic keys, or obfuscated tokens.'
                    ),
                    'recommendation': (
                        'Verify if this is a hardcoded secret, API key, or encryption key. '
                        'If yes, move to Android Keystore, environment variables, or a server-side secrets manager.'
                    ),
                })

        return self._format_result(findings, analyzed_count)

    @staticmethod
    def _calculate_shannon_entropy(string: str) -> float:
        """
        Calculate Shannon entropy of a string.

        Shannon entropy formula: H = -Σ(p(x) * log2(p(x)))
        where p(x) is the probability of character x.

        Returns:
            Entropy value (0 = no randomness, ~8 = maximum for byte values)
        """
        if not string:
            return 0.0

        char_counts = Counter(string)
        length = len(string)

        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _should_exclude(self, string: str) -> bool:
        """Check if string matches known non-secret patterns"""
        lower = string.lower()

        # Skip known package/path patterns
        for excl in self.EXCLUSION_SUBSTRINGS:
            if excl in lower:
                return True

        # Skip strings that are mostly whitespace or newlines
        printable_ratio = sum(1 for c in string if c.isalnum()) / len(string) if string else 0
        if printable_ratio < 0.5:
            return True

        # Skip single-character repeated strings
        if len(set(string)) < 4:
            return True

        return False

    def _format_result(self, findings: List[Dict], analyzed_count: int) -> dict:
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
            'category': 'High Entropy Strings',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': (
                f'Analyzed {analyzed_count} strings. Found {len(findings)} high-entropy string(s) '
                f'(Shannon entropy ≥ {self.HIGH_ENTROPY_THRESHOLD}) that may contain hidden secrets.'
            )
        }
