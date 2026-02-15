"""API Key Detection Analyzer
Detects 20+ common API key patterns in file content
"""

import re

class APIKeyAnalyzer:
    """Analyzes content for exposed API keys and secrets"""
    
    # Comprehensive API key patterns
    PATTERNS = {
        'AWS Access Key': r'AKIA[0-9A-Z]{16}',
        'AWS Secret Key': r'aws(.{0,20})?[\'"][0-9a-zA-Z\/+]{40}[\'"]',
        'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
        'Google Cloud Platform API Key': r'AIza[0-9A-Za-z\\-_]{35}',
        'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        'Google Cloud Platform OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        'GitHub Personal Access Token': r'ghp_[0-9a-zA-Z]{36}',
        'GitHub OAuth Access Token': r'gho_[0-9a-zA-Z]{36}',
        'GitHub App Token': r'(ghu|ghs)_[0-9a-zA-Z]{36}',
        'GitHub Refresh Token': r'ghr_[0-9a-zA-Z]{76}',
        'GitLab Personal Access Token': r'glpat-[0-9a-zA-Z\-\_]{20}',
        'OpenAI API Key': r'sk-[a-zA-Z0-9]{48}',
        'Anthropic API Key': r'sk-ant-[a-zA-Z0-9\-_]{95}',
        'Stripe API Key': r'sk_(live|test)_[0-9a-zA-Z]{24,}',
        'Stripe Publishable Key': r'pk_(live|test)_[0-9a-zA-Z]{24,}',
        'Stripe Restricted Key': r'rk_(live|test)_[0-9a-zA-Z]{24,}',
        'Firebase API Key': r'AIza[0-9A-Za-z\\-_]{35}',
        'Azure Access Token': r'ey[A-Za-z0-9\-_]+\.ey[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
        'Slack Token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}',
        'Slack Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
        'SendGrid API Key': r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',
        'Twilio API Key': r'SK[a-z0-9]{32}',
        'Shopify Access Token': r'shpat_[a-fA-F0-9]{32}',
        'JWT Token': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
        'Generic API Key Pattern': r'[aA][pP][iI][-_]?[kK][eE][yY][\'\"\s:=]+[a-zA-Z0-9\-_]{20,}',
        'Generic Secret Pattern': r'[sS][eE][cC][rR][eE][tT][\'\"\s:=]+[a-zA-Z0-9\-_]{20,}',
        
        # Database Connection Strings
        'MongoDB Connection String': r'mongodb(\+srv)?://[^\s\'"]+',
        'PostgreSQL Connection String': r'postgres(ql)?://[^\s\'"]+',
        'MySQL Connection String': r'mysql://[^\s\'"]+',
        'Redis Connection String': r'redis://[^\s\'"]+',
        'MSSQL Connection String': r'(mssql|sqlserver)://[^\s\'"]+',
        
        # Hardcoded Credentials
        'Hardcoded Password': r'["\']?password["\']?\s*[:=]\s*["\'][^"\'\s]{6,}["\']',
        'Hardcoded Username': r'["\']?username["\']?\s*[:=]\s*["\'][^"\'\s]{3,}["\']',
        'Hardcoded Database Password': r'["\']?(db_password|db_pass|database_password)["\']?\s*[:=]\s*["\'][^"\'\s]{6,}["\']',
        'Admin Credentials': r'["\']?(admin_password|admin_pass|root_password)["\']?\s*[:=]\s*["\'][^"\'\s]{6,}["\']',
    }
    
    def analyze(self, content: str, filename: str = '') -> dict:
        """
        Analyze content for API keys
        
        Args:
            content: String content to analyze
            filename: Name of file being analyzed
            
        Returns:
            dict with findings, count, and severity
        """
        findings = []
        
        for key_type, pattern in self.PATTERNS.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                context_start = max(0, match.start() - 30)
                context_end = min(len(content), match.end() + 30)
                context = content[context_start:context_end]
                
                findings.append({
                    'type': key_type,
                    'value': match.group(),
                    'context': context.replace('\n', ' ').replace('\r', ''),
                    'position': match.start(),
                    'severity': 'CRITICAL',
                    'recommendation': f'Remove {key_type} from code. Use environment variables or secret management systems.'
                })
        
        return {
            'category': 'API Keys & Secrets',
            'total_found': len(findings),
            'findings': findings,
            'severity': 'CRITICAL' if findings else 'SAFE',
            'description': f'Found {len(findings)} potential API key(s) or secret(s) in the file.'
        }
