"""Network Security Analyzer
Detects insecure network configurations and cleartext traffic
"""

import re

class NetworkAnalyzer:
    """Analyzes content for network security issues"""
    
    def analyze(self, content: str, filename: str = '') -> dict:
        """
        Analyze content for network security issues
        
        Args:
            content: String content to analyze
            filename: Name of file being analyzed
            
        Returns:
            dict with findings, count, and severity
        """
        findings = []
        
        # Detect HTTP (cleartext) URLs
        http_pattern = r'http://[a-zA-Z0-9\-\._~:/?#\[\]@!$&\'()*+,;=]+'
        http_matches = re.finditer(http_pattern, content)
        
        for match in http_matches:
            url = match.group()
            # Skip localhost/internal testing URLs (less critical)
            if 'localhost' in url or '127.0.0.1' in url:
                severity = 'LOW'
                recommendation = 'Localhost HTTP is acceptable for development, but ensure HTTPS in production.'
            else:
                severity = 'HIGH'
                recommendation = 'Replace HTTP with HTTPS to encrypt data in transit and prevent MITM attacks.'
            
            findings.append({
                'type': 'Cleartext Traffic (HTTP)',
                'value': url,
                'severity': severity,
                'recommendation': recommendation,
                'context': self._get_context(content, match.start(), match.end())
            })
        
        # Detect insecure WebSocket connections
        ws_pattern = r'ws://[a-zA-Z0-9\-\._~:/?#\[\]@!$&\'()*+,;=]+'
        ws_matches = re.finditer(ws_pattern, content)
        
        for match in ws_matches:
            findings.append({
                'type': 'Insecure WebSocket (WS)',
                'value': match.group(),
                'severity': 'HIGH',
                'recommendation': 'Use WSS (WebSocket Secure) instead of WS for encrypted communication.',
                'context': self._get_context(content, match.start(), match.end())
            })
        
        # Detect disabled SSL/TLS verification
        ssl_bypass_patterns = [
            (r'verify\s*=\s*False', 'SSL Verification Disabled'),
            (r'CURLOPT_SSL_VERIFYPEER.*false', 'CURL SSL Verification Disabled'),
            (r'NODE_TLS_REJECT_UNAUTHORIZED.*0', 'Node.js TLS Verification Disabled'),
        ]
        
        for pattern, issue_type in ssl_bypass_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'type': issue_type,
                    'value': match.group(),
                    'severity': 'CRITICAL',
                    'recommendation': 'Never disable SSL/TLS certificate verification. This makes you vulnerable to MITM attacks.',
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        return {
            'category': 'Network Security',
            'total_found': len(findings),
            'findings': findings,
            'severity': self._calculate_severity(findings),
            'description': f'Found {len(findings)} network security issue(s).'
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
        if 'CRITICAL' in severities:
            return 'CRITICAL'
        elif 'HIGH' in severities:
            return 'HIGH'
        elif 'MEDIUM' in severities:
            return 'MEDIUM'
        else:
            return 'LOW'
