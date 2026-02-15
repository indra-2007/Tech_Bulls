"""Static File Analyzer
Analyzes static files (JS, HTML, CSS, JSON) for security issues and bad practices
"""

import re

class StaticFileAnalyzer:
    """Analyzes static files for security issues"""
    
    # Patterns for JavaScript analysis
    JS_PATTERNS = {
        'Dangerous Eval': {
            'pattern': r'eval\s*\(',
            'severity': 'CRITICAL',
            'description': 'Use of eval() can lead to XSS and code injection'
        },
        'Document Write': {
            'pattern': r'document\.write\s*\(',
            'severity': 'HIGH',
            'description': 'document.write() is unsafe and can lead to XSS'
        },
        'InnerHTML Assignment': {
            'pattern': r'\.innerHTML\s*=',
            'severity': 'MEDIUM',
            'description': 'Direct assignment to innerHTML without sanitization can cause XSS'
        },
        'OuterHTML Assignment': {
            'pattern': r'\.outerHTML\s*=',
            'severity': 'MEDIUM',
            'description': 'Direct assignment to outerHTML without sanitization can cause XSS'
        },
        'Weak Random': {
            'pattern': r'Math\.random\(\)',
            'severity': 'LOW',
            'description': 'Math.random() is not cryptographically secure'
        },
        'Console Log': {
            'pattern': r'console\.log\s*\(',
            'severity': 'INFO',
            'description': 'Console logs should be removed in production'
        },
        'Debugger Statement': {
            'pattern': r'debugger',
            'severity': 'LOW',
            'description': 'Debugger statements should be removed in production'
        },
        'Hardcoded Secret': {
            'pattern': r'(api_key|apikey|secret|token)\s*[:=]\s*[\'"][a-zA-Z0-9_\-]{20,}[\'"]',
            'severity': 'CRITICAL',
            'description': 'Potential hardcoded secret or API key found'
        }
    }

    # Patterns for HTML analysis
    HTML_PATTERNS = {
        'Inline Script': {
            'pattern': r'<script\b[^>]*>.*?</script>',
            'severity': 'MEDIUM',
            'description': 'Inline scripts increase XSS risk; use external files'
        },
        'Insecure HTTP': {
            'pattern': r'http://',
            'severity': 'HIGH',
            'description': 'Resource loaded over insecure HTTP connection'
        },
        'Iframe Usage': {
            'pattern': r'<iframe',
            'severity': 'LOW',
            'description': 'Iframes can be a security risk (clickjacking, etc.)'
        }
    }

    def analyze(self, content: str, filename: str) -> dict:
        """
        Analyze a static file for issues
        
        Args:
            content: File content string
            filename: Name of the file
            
        Returns:
            dict with findings
        """
        findings = []
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        
        # Select patterns based on file extension
        patterns = {}
        if ext in ['js', 'ts', 'jsx', 'tsx']:
            patterns.update(self.JS_PATTERNS)
        elif ext in ['html', 'htm', 'php', 'jsp', 'asp']:
            patterns.update(self.HTML_PATTERNS)
            # HTML files often contain JS, so check for common JS patterns too
            patterns.update({k: v for k, v in self.JS_PATTERNS.items() if k in ['Dangerous Eval', 'Document Write', 'Hardcoded Secret']})
        
        # General patterns for all text files (comments, etc.)
        general_patterns = {
            'TODO Comment': {
                'pattern': r'//\s*TODO:|<!--\s*TODO:',
                'severity': 'INFO',
                'description': 'TODO comment found (may indicate unfinished code)'
            },
            'FIXME Comment': {
                'pattern': r'//\s*FIXME:|<!--\s*FIXME:',
                'severity': 'LOW',
                'description': 'FIXME comment found (indicates broken code)'
            }
        }
        patterns.update(general_patterns)

        for name, info in patterns.items():
            for match in re.finditer(info['pattern'], content, re.IGNORECASE | re.MULTILINE):
                # Get context
                start = max(0, match.start() - 40)
                end = min(len(content), match.end() + 40)
                context = content[start:end].strip()
                
                findings.append({
                    'type': name,
                    'severity': info['severity'],
                    'description': info['description'],
                    'match': match.group().strip(),
                    'context': context,
                    'position': match.start()
                })
        
        return {
            'category': 'Static Analysis',
            'total_found': len(findings),
            'findings': findings,
            'severity': self._calculate_severity(findings),
            'description': f'Found {len(findings)} issue(s) in static file analysis.'
        }

    def _calculate_severity(self, findings: list) -> str:
        """Calculate overall severity based on findings"""
        if not findings:
            return 'SAFE'
        
        severities = [f['severity'] for f in findings]
        if 'CRITICAL' in severities:
            return 'CRITICAL'
        if 'HIGH' in severities:
            return 'HIGH'
        if 'MEDIUM' in severities:
            return 'MEDIUM'
        if 'LOW' in severities:
            return 'LOW'
        return 'INFO'
