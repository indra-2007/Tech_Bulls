"""Cryptography Analyzer
Detects weak or deprecated cryptographic practices
"""

import re

class CryptoAnalyzer:
    """Analyzes content for weak cryptography"""
    
    # Deprecated or weak algorithms
    WEAK_ALGORITHMS = {
        'MD5': {'severity': 'HIGH', 'type': 'Hash Algorithm'},
        'SHA-1': {'severity': 'HIGH', 'type': 'Hash Algorithm'},
        'SHA1': {'severity': 'HIGH', 'type': 'Hash Algorithm'},
        'DES': {'severity': 'CRITICAL', 'type': 'Encryption Algorithm'},
        '3DES': {'severity': 'HIGH', 'type': 'Encryption Algorithm'},
        'RC4': {'severity': 'CRITICAL', 'type': 'Stream Cipher'},
        'ECB': {'severity': 'HIGH', 'type': 'Block Cipher Mode'},
    }
    
    def analyze(self, content: str, filename: str = '') -> dict:
        """
        Analyze content for weak cryptography
        
        Args:
            content: String content to analyze
            filename: Name of file being analyzed
            
        Returns:
            dict with findings, count, and severity
        """
        findings = []
        
        # Check for weak algorithms
        for algo, info in self.WEAK_ALGORITHMS.items():
            # Create pattern that matches algorithm usage
            patterns = [
                rf'\b{algo}\b',
                rf'[\'"]({algo})[\'"]',
                rf'{algo}\(',
                rf'algorithm.*{algo}',
                rf'digest.*{algo}',
            ]
            
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    context = self._get_context(content, match.start(), match.end())
                    
                    # Avoid duplicates by checking if we already found this
                    if not any(f['value'] == match.group() and f['context'] == context for f in findings):
                        findings.append({
                            'type': f'Weak {info["type"]}: {algo}',
                            'value': match.group(),
                            'severity': info['severity'],
                            'recommendation': self._get_recommendation(algo),
                            'context': context
                        })
                    break  # Only find first match per pattern to avoid duplicates
        
        # Check for hardcoded salts/IVs
        hardcoded_patterns = [
            (r'salt\s*=\s*[\'"][a-zA-Z0-9+/=]{8,}[\'"]', 'Hardcoded Salt', 'HIGH'),
            (r'iv\s*=\s*[\'"][a-zA-Z0-9+/=]{8,}[\'"]', 'Hardcoded IV (Initialization Vector)', 'HIGH'),
            (r'secret\s*=\s*[\'"][a-zA-Z0-9+/=]{8,}[\'"]', 'Hardcoded Secret', 'CRITICAL'),
        ]
        
        for pattern, issue_type, severity in hardcoded_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'type': issue_type,
                    'value': match.group()[:50] + '...' if len(match.group()) > 50 else match.group(),
                    'severity': severity,
                    'recommendation': f'{issue_type} should be generated randomly and stored securely, not hardcoded.',
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        # Check for weak key sizes
        weak_key_patterns = [
            (r'RSA.*512', 'RSA 512-bit key', 'CRITICAL'),
            (r'RSA.*1024', 'RSA 1024-bit key', 'HIGH'),
        ]
        
        for pattern, issue_type, severity in weak_key_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'type': f'Weak Key Size: {issue_type}',
                    'value': match.group(),
                    'severity': severity,
                    'recommendation': 'Use RSA-2048 or higher for secure encryption. Smaller keys can be cracked.',
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        return {
            'category': 'Weak Cryptography',
            'total_found': len(findings),
            'findings': findings,
            'severity': self._calculate_severity(findings),
            'description': f'Found {len(findings)} weak cryptography indicator(s).'
        }
    
    def _get_recommendation(self, algorithm: str) -> str:
        """Get specific recommendation for weak algorithm"""
        recommendations = {
            'MD5': 'Replace MD5 with SHA-256 or SHA-3 for hashing.',
            'SHA-1': 'Replace SHA-1 with SHA-256, SHA-384, or SHA-512.',
            'SHA1': 'Replace SHA-1 with SHA-256, SHA-384, or SHA-512.',
            'DES': 'Replace DES with AES-256 for encryption.',
            '3DES': 'Replace 3DES with AES-256 for modern encryption.',
            'RC4': 'Replace RC4 with AES-GCM or ChaCha20-Poly1305.',
            'ECB': 'Replace ECB mode with CBC, CTR, or GCM mode for secure encryption.',
        }
        return recommendations.get(algorithm, f'Replace {algorithm} with modern cryptographic alternatives.')
    
    def _get_context(self, content: str, start: int, end: int, window: int = 40) -> str:
        """Extract context around a match"""
        context_start = max(0, start - window)
        context_end = min(len(content), end + window)
        return content[context_start:context_end].replace('\n', ' ').replace('\r', '')
    
    def _calculate_severity(self, findings: list) -> str:
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
