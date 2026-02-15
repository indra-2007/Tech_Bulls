"""Cloud Storage Analyzer
Detects exposed cloud storage bucket URLs
"""

import re

class CloudStorageAnalyzer:
    """Analyzes content for exposed cloud storage buckets"""
    
    CLOUD_PATTERNS = {
        'AWS S3': [
            r's3://[a-zA-Z0-9\-\.]+',
            r'https?://[a-zA-Z0-9\-\.]+\.s3\.amazonaws\.com',
            r'https?://s3\.amazonaws\.com/[a-zA-Z0-9\-\.]+',
            r'https?://s3-[a-z0-9\-]+\.amazonaws\.com/[a-zA-Z0-9\-\.]+',
            r'https?://[a-zA-Z0-9\-\.]+\.s3-[a-z0-9\-]+\.amazonaws\.com',
        ],
        'Azure Blob Storage': [
            r'https?://[a-zA-Z0-9\-]+\.blob\.core\.windows\.net',
            r'DefaultEndpointsProtocol=https;.*blob\.core\.windows\.net',
        ],
        'Google Cloud Storage': [
            r'https?://storage\.googleapis\.com/[a-zA-Z0-9\-\.\_]+',
            r'https?://[a-zA-Z0-9\-\.\_]+\.storage\.googleapis\.com',
            r'gs://[a-zA-Z0-9\-\.\_]+',
        ],
    }
    
    def analyze(self, content: str, filename: str = '') -> dict:
        """
        Analyze content for cloud storage URLs
        
        Args:
            content: String content to analyze
            filename: Name of file being analyzed
            
        Returns:
            dict with findings, count, and severity
        """
        findings = []
        
        for cloud_provider, patterns in self.CLOUD_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    bucket_url = match.group()
                    
                    findings.append({
                        'type': f'{cloud_provider} Bucket',
                        'value': bucket_url,
                        'severity': 'CRITICAL',
                        'recommendation': (
                            f'Verify {cloud_provider} bucket permissions. '
                            'Ensure the bucket is not publicly accessible unless absolutely necessary. '
                            'Use IAM policies and bucket policies to restrict access.'
                        ),
                        'context': self._get_context(content, match.start(), match.end()),
                        'security_tips': [
                            'Check bucket permissions and ACLs',
                            'Enable bucket versioning',
                            'Enable access logging',
                            'Use bucket policies for least-privilege access'
                        ]
                    })
        
        return {
            'category': 'Cloud Storage Exposure',
            'total_found': len(findings),
            'findings': findings,
            'severity': 'CRITICAL' if findings else 'SAFE',
            'description': (
                f'Found {len(findings)} cloud storage URL(s). '
                'Verify these buckets are not publicly accessible.'
            )
        }
    
    def _get_context(self, content: str, start: int, end: int, window: int = 40) -> str:
        """Extract context around a match"""
        context_start = max(0, start - window)
        context_end = min(len(content), end + window)
        return content[context_start:context_end].replace('\n', ' ').replace('\r', '')
