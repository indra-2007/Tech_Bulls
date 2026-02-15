"""Infrastructure Leak Analyzer
Detects internal infrastructure information leaks
"""

import re

class InfrastructureAnalyzer:
    """Analyzes content for internal infrastructure leaks"""
    
    # Private IP address patterns (RFC 1918)
    PRIVATE_IP_PATTERNS = [
        (r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '10.0.0.0/8 (Class A private)'),
        (r'\b172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b', '172.16.0.0/12 (Class B private)'),
        (r'\b192\.168\.\d{1,3}\.\d{1,3}\b', '192.168.0.0/16 (Class C private)'),
    ]
    
    # Localhost patterns
    LOCALHOST_PATTERNS = [
        (r'\b127\.0\.0\.\d+\b', 'IPv4 Localhost'),
        (r'\blocalhost\b', 'Localhost domain'),
        (r'\b::1\b', 'IPv6 Localhost'),
    ]
    
    # Internal domain patterns
    INTERNAL_DOMAIN_PATTERNS = [
        (r'\b\w+\.local\b', '.local domain'),
        (r'\b\w+\.internal\b', '.internal domain'),
        (r'\bdev\.\w+\.\w+', 'dev.* subdomain'),
        (r'\bstaging\.\w+\.\w+', 'staging.* subdomain'),
        (r'\btest\.\w+\.\w+', 'test.* subdomain'),
        (r'\b\w+\.dev\b', '.dev domain'),
        (r'\b\w+\.test\b', '.test domain'),
        (r'\bintranet\.\w+', 'intranet.* domain'),
    ]
    
    def analyze(self, content: str, filename: str = '') -> dict:
        """
        Analyze content for infrastructure leaks
        
        Args:
            content: String content to analyze
            filename: Name of file being analyzed
            
        Returns:
            dict with findings, count, and severity
        """
        findings = []
        
        # Check for private IPs
        for pattern, ip_type in self.PRIVATE_IP_PATTERNS:
            matches = re.finditer(pattern, content)
            for match in matches:
                findings.append({
                    'type': f'Private IP Address ({ip_type})',
                    'value': match.group(),
                    'severity': 'MEDIUM',
                    'recommendation': 'Remove private IP addresses before production release. They expose internal network topology.',
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        # Check for localhost references
        for pattern, ref_type in self.LOCALHOST_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'type': f'Localhost Reference ({ref_type})',
                    'value': match.group(),
                    'severity': 'LOW',
                    'recommendation': 'Localhost references should be configurable via environment variables for different environments.',
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        # Check for internal domain patterns
        for pattern, domain_type in self.INTERNAL_DOMAIN_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'type': f'Internal Domain ({domain_type})',
                    'value': match.group(),
                    'severity': 'MEDIUM',
                    'recommendation': 'Remove internal domain references. Use environment-specific configuration instead.',
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        return {
            'category': 'Infrastructure Leaks',
            'total_found': len(findings),
            'findings': findings,
            'severity': self._calculate_severity(findings),
            'description': f'Found {len(findings)} internal infrastructure reference(s) that could expose network topology.'
        }
    
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
        if 'HIGH' in severities:
            return 'HIGH'
        elif 'MEDIUM' in severities:
            return 'MEDIUM'
        else:
            return 'LOW'
