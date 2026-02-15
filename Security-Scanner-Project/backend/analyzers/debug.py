"""Debug Analyzer
Detects developer leftovers and debug code in production builds
"""

import re

class DebugAnalyzer:
    """Analyzes content for development artifacts and debug code"""
    
    # Debug comment patterns
    DEBUG_COMMENTS = {
        'TODO': 'LOW',
        'FIXME': 'MEDIUM',
        'HACK': 'MEDIUM',
        'XXX': 'MEDIUM',
        'BUG': 'HIGH',
        'TEMP': 'LOW',
        'TEMPORARY': 'LOW',
    }
    
    # Debug logging patterns
    DEBUG_LOGGING = [
        (r'console\.log\s*\(', 'console.log()', 'JavaScript'),
        (r'console\.debug\s*\(', 'console.debug()', 'JavaScript'),
        (r'print\s*\(', 'print()', 'Python'),
        (r'System\.out\.println\s*\(', 'System.out.println()', 'Java'),
        (r'NSLog\s*\(', 'NSLog()', 'Objective-C'),
        (r'Log\.[dviwe]\s*\(', 'Android Log', 'Android'),
        (r'console\.warn\s*\(', 'console.warn()', 'JavaScript'),
        (r'console\.error\s*\(', 'console.error()', 'JavaScript'),
    ]
    
    def analyze(self, content: str, filename: str = '') -> dict:
        """
        Analyze content for debug code and developer leftovers
        
        Args:
            content: String content to analyze
            filename: Name of file being analyzed
            
        Returns:
            dict with findings, count, and severity
        """
        findings = []
        
        # Check for debug comments 
        for comment_type, severity in self.DEBUG_COMMENTS.items():
            # Match comment patterns with the keyword
            patterns = [
                rf'//\s*{comment_type}[:\s]',  # // TODO: 
                rf'/\*\s*{comment_type}[:\s]',  # /* TODO: 
                rf'#\s*{comment_type}[:\s]',    # # TODO:
            ]
            
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Get the full comment line
                    line_start = content.rfind('\n', 0, match.start()) + 1
                    line_end = content.find('\n', match.end())
                    if line_end == -1:
                        line_end = len(content)
                    
                    comment_line = content[line_start:line_end].strip()
                    
                    findings.append({
                        'type': f'{comment_type} Comment',
                        'value': comment_line[:100] + '...' if len(comment_line) > 100 else comment_line,
                        'severity': severity,
                        'recommendation': f'Remove {comment_type} comments before production release. They indicate incomplete work.',
                        'context': comment_line
                    })
        
        # Check for debug logging
        for pattern, log_type, language in self.DEBUG_LOGGING:
            matches = re.finditer(pattern, content)
            for match in matches:
                findings.append({
                    'type': f'Debug Logging ({language})',
                    'value': log_type,
                    'severity': 'LOW',
                    'recommendation': f'Remove or replace {log_type} with proper logging framework before production.',
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        # Check for DEBUG flags
        debug_flag_patterns = [
            (r'DEBUG\s*=\s*True', 'DEBUG=True flag', 'HIGH'),
            (r'DEBUG\s*=\s*1', 'DEBUG=1 flag', 'HIGH'),
            (r'debuggable\s*=\s*true', 'Android debuggable=true', 'HIGH'),
        ]
        
        for pattern, flag_type, severity in debug_flag_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'type': f'Debug Flag: {flag_type}',
                    'value': match.group(),
                    'severity': severity,
                    'recommendation': 'Set DEBUG to False in production builds to prevent information leakage.',
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        # Check for hardcoded credentials patterns
        credential_patterns = [
            (r'password\s*=\s*[\'"][^\'"]{3,}[\'"]', 'Hardcoded Password'),
            (r'pwd\s*=\s*[\'"][^\'"]{3,}[\'"]', 'Hardcoded Password'),
            (r'passwd\s*=\s*[\'"][^\'"]{3,}[\'"]', 'Hardcoded Password'),
            (r'username\s*=\s*[\'"][^\'"]{3,}[\'"]', 'Hardcoded Username'),
        ]
        
        for pattern, cred_type in credential_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'type': cred_type,
                    'value': match.group()[:40] + '...',
                    'severity': 'CRITICAL',
                    'recommendation': 'Never hardcode credentials. Use environment variables or secure credential management.',
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        # Check for email addresses (developer emails)
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        email_matches = re.finditer(email_pattern, content)
        for match in email_matches:
            findings.append({
                'type': 'Email Address',
                'value': match.group(),
                'severity': 'LOW',
                'recommendation': 'Consider removing developer email addresses from production code.',
                'context': self._get_context(content, match.start(), match.end())
            })
        
        return {
            'category': 'Developer Leftovers',
            'total_found': len(findings),
            'findings': findings,
            'severity': self._calculate_severity(findings),
            'description': f'Found {len(findings)} developer leftover(s) and debug artifact(s).'
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
