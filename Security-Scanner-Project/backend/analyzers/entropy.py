"""Shannon Entropy Analyzer
Detects high-entropy strings that may indicate secrets, encrypted data, or encoded values
"""

import re
import math
from collections import Counter

class EntropyAnalyzer:
    """Analyzes strings for high Shannon entropy"""
    
    # Minimum string length to analyze
    MIN_STRING_LENGTH = 20
    
    # Entropy threshold (0-8 scale, where 8 is maximum randomness)
    HIGH_ENTROPY_THRESHOLD = 4.5
    
    # Patterns to exclude (common high-entropy non-secrets)
    EXCLUSION_PATTERNS = [
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',  # UUID
        r'^/[a-zA-Z0-9/_\-\.]+$',  # File paths
        r'^https?://[^\s]+$',  # URLs
        r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64 (we want to catch these but validate)
    ]
    
    def analyze(self, content: str, filename: str = '') -> dict:
        """
        Analyze content for high-entropy strings
        
        Args:
            content: String content to analyze
            filename: Name of file being analyzed
            
        Returns:
            dict with findings, count, and severity
        """
        findings = []
        
        # Extract potential string literals (between quotes)
        string_patterns = [
            r'"([^"]{%d,})"' % self.MIN_STRING_LENGTH,
            r"'([^']{%d,})'" % self.MIN_STRING_LENGTH,
        ]
        
        potential_secrets = set()
        
        for pattern in string_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                string_value = match.group(1)
                
                # Skip if matches exclusion patterns
                if self._should_exclude(string_value):
                    continue
                
                # Calculate entropy
                entropy = self._calculate_entropy(string_value)
                
                if entropy >= self.HIGH_ENTROPY_THRESHOLD:
                    # Avoid duplicates
                    if string_value not in potential_secrets:
                        potential_secrets.add(string_value)
                        
                        # Determine severity based on entropy level
                        if entropy >= 5.5:
                            severity = 'HIGH'
                        elif entropy >= 5.0:
                            severity = 'MEDIUM'
                        else:
                            severity = 'LOW'
                        
                        findings.append({
                            'type': 'High Entropy String',
                            'value': string_value[:50] + '...' if len(string_value) > 50 else string_value,
                            'entropy': round(entropy, 2),
                            'length': len(string_value),
                            'severity': severity,
                            'description': f'String with high randomness (entropy: {round(entropy, 2)}). May indicate encrypted data, base64-encoded secrets, or cryptographic keys.',
                            'recommendation': 'Verify if this is a hardcoded secret. If yes, move to environment variables or secret management system.'
                        })
        
        return {
            'category': 'High Entropy Strings',
            'total_found': len(findings),
            'findings': findings,
            'severity': self._calculate_overall_severity(findings),
            'description': f'Found {len(findings)} high-entropy string(s) that may contain secrets.'
        }
    
    def _calculate_entropy(self, string: str) -> float:
        """
        Calculate Shannon entropy of a string
        
        Shannon entropy formula: H = -Σ(p(x) * log2(p(x)))
        where p(x) is the probability of character x
        
        Returns value between 0 (no randomness) and 8 (maximum randomness for byte values)
        """
        if not string:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(string)
        length = len(string)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _should_exclude(self, string: str) -> bool:
        """Check if string matches exclusion patterns"""
        for pattern in self.EXCLUSION_PATTERNS:
            if re.match(pattern, string):
                return True
        return False
    
    def _calculate_overall_severity(self, findings: list) -> str:
        """Calculate overall severity from findings"""
        if not findings:
            return 'SAFE'
        
        severities = [f['severity'] for f in findings]
        if 'CRITICAL' in severities:
            return 'CRITICAL'
        elif 'HIGH' in severities:
            return 'HIGH'
        elif 'MEDIUM' in severities:
            return 'MEDIUM'
        else:
            return 'LOW'
