"""Report Generator
Compiles security findings into comprehensive reports.
Produces dual-view output: Developer (detailed) + User (summary).
JSON output matches the frontend API contract exactly.
"""

from typing import List, Dict
from datetime import datetime


class ReportGenerator:
    """Generates comprehensive security reports with dual views"""

    # ── Severity penalty weights for risk scoring ─────────────────────
    SEVERITY_PENALTIES = {
        'CRITICAL': 15,
        'HIGH': 8,
        'MEDIUM': 4,
        'LOW': 1,
    }

    # ── Context multipliers for APK-specific risk ─────────────────────
    CATEGORY_WEIGHTS = {
        'Manifest Security': 1.2,
        'Hardcoded Secrets': 1.5,
        'Code Vulnerabilities': 1.3,
        'High Entropy Strings': 0.8,
        'Code Obfuscation': 0.5,
        'Certificate Security': 1.4,
        'Permission Risk Correlation': 1.5,
        'Component Exposure': 1.0,
        'DEX Structure': 0.2,
    }

    @staticmethod
    def generate_report(all_findings: dict, file_info: dict, file_hash: dict, app_info: dict = None) -> dict:
        """
        Generate comprehensive security report.

        Args:
            all_findings: Dict of category_name -> {category, findings, severity, ...}
            file_info: File metadata
            file_hash: File hash values
            app_info: Optional APK info (package name, version, etc.)

        Returns:
            Complete security report matching frontend API contract
        """
        # ── Calculate weighted security score ─────────────────────
        total_score = 100.0
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        total_findings = 0

        for category_name, results in all_findings.items():
            if not isinstance(results, dict) or 'findings' not in results:
                continue

            weight = ReportGenerator.CATEGORY_WEIGHTS.get(category_name, 1.0)
            findings = results['findings']
            total_findings += len(findings)

            for finding in findings:
                severity = finding.get('severity', 'LOW')
                if severity in severity_counts:
                    severity_counts[severity] += 1
                    penalty = ReportGenerator.SEVERITY_PENALTIES.get(severity, 0) * weight
                    total_score -= penalty

        security_score = max(0, min(100, int(total_score)))

        # ── Risk level ────────────────────────────────────────────
        risk_level = ReportGenerator._calculate_risk_level(security_score, severity_counts)

        # ── Recommendations (Developer + User) ────────────────────
        recommendations = ReportGenerator._generate_recommendations(all_findings, severity_counts)

        # ── User summary ──────────────────────────────────────────
        user_summary = ReportGenerator._generate_user_summary(
            security_score, risk_level, severity_counts, total_findings, all_findings
        )

        # ── Build report ──────────────────────────────────────────
        report = {
            'scan_metadata': {
                'timestamp': datetime.now().isoformat(),
                'file_info': file_info,
                'file_hash': file_hash,
                'scanner_version': '2.0.0',
                'engine': 'Androguard Static Analysis',
            },
            'security_score': security_score,
            'risk_level': risk_level,
            'summary': {
                'total_issues': total_findings,
                'critical': severity_counts['CRITICAL'],
                'high': severity_counts['HIGH'],
                'medium': severity_counts['MEDIUM'],
                'low': severity_counts['LOW'],
            },
            'findings_by_category': all_findings,
            'recommendations': recommendations,
            'user_summary': user_summary,
        }

        if app_info:
            report['app_info'] = app_info

        return report

    @staticmethod
    def _calculate_risk_level(score: int, severity_counts: dict) -> str:
        """Calculate overall risk level from score and severity distribution"""
        if severity_counts['CRITICAL'] >= 2 or score < 30:
            return 'CRITICAL'
        elif severity_counts['CRITICAL'] > 0 or score < 50:
            return 'HIGH'
        elif severity_counts['HIGH'] > 2 or score < 70:
            return 'MEDIUM'
        elif severity_counts['HIGH'] > 0 or score < 85:
            return 'LOW'
        else:
            return 'SAFE'

    @staticmethod
    def _generate_recommendations(all_findings: dict, severity_counts: dict) -> list:
        """Generate actionable recommendations based on findings"""
        recommendations = []

        # ── Critical actions ──────────────────────────────────────
        if severity_counts['CRITICAL'] > 0:
            critical_actions = []
            for cat_name, results in all_findings.items():
                if not isinstance(results, dict):
                    continue
                for f in results.get('findings', []):
                    if f.get('severity') == 'CRITICAL' and f.get('recommendation'):
                        action = f['recommendation']
                        if action not in critical_actions:
                            critical_actions.append(action)
            recommendations.append({
                'priority': 'CRITICAL',
                'title': 'Immediate Action Required',
                'description': f'{severity_counts["CRITICAL"]} critical security issue(s) found. These must be fixed before any public release.',
                'actions': critical_actions[:5],
            })

        # ── High priority ─────────────────────────────────────────
        if severity_counts['HIGH'] > 0:
            high_actions = []
            for cat_name, results in all_findings.items():
                if not isinstance(results, dict):
                    continue
                for f in results.get('findings', []):
                    if f.get('severity') == 'HIGH' and f.get('recommendation'):
                        action = f['recommendation']
                        if action not in high_actions:
                            high_actions.append(action)
            recommendations.append({
                'priority': 'HIGH',
                'title': 'High Priority Issues',
                'description': f'{severity_counts["HIGH"]} high severity issue(s) that should be addressed before release.',
                'actions': high_actions[:5],
            })

        # ── Medium priority ───────────────────────────────────────
        if severity_counts['MEDIUM'] > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'title': 'Code Quality & Hardening',
                'description': f'{severity_counts["MEDIUM"]} medium severity issue(s) related to code quality and security hardening.',
                'actions': [
                    'Enable ProGuard/R8 code obfuscation for release builds',
                    'Review and minimize exported components',
                    'Implement network security configuration',
                    'Remove debug flags and development artifacts',
                ],
            })

        # ── Low priority ──────────────────────────────────────────
        if severity_counts['LOW'] > 0:
            recommendations.append({
                'priority': 'LOW',
                'title': 'Best Practice Improvements',
                'description': f'{severity_counts["LOW"]} low severity finding(s) for general improvement.',
                'actions': [
                    'Review informational findings for security awareness',
                    'Consider stricter permission model',
                    'Implement certificate pinning for added security',
                ],
            })

        # ── Clean bill ────────────────────────────────────────────
        if not recommendations:
            recommendations.append({
                'priority': 'SAFE',
                'title': 'No Major Security Issues Found',
                'description': 'The APK appears to follow security best practices. No critical issues detected.',
                'actions': [
                    'Continue following secure development practices',
                    'Perform regular security audits',
                    'Keep dependencies up to date',
                ],
            })

        return recommendations

    @staticmethod
    def _generate_user_summary(score, risk_level, severity_counts, total_findings, all_findings) -> dict:
        """Generate plain-English user summary for the User view"""

        # Risk level descriptions
        risk_descriptions = {
            'CRITICAL': '🔴 This app has critical security issues that could put your data at serious risk.',
            'HIGH': '🟠 This app has important security concerns that should be addressed.',
            'MEDIUM': '🟡 This app has some security issues, but is generally acceptable with improvements.',
            'LOW': '🟢 This app has minor issues but follows most security best practices.',
            'SAFE': '✅ This app appears to be secure with no significant issues detected.',
        }

        # Build category summaries for user
        category_summaries = []
        for cat_name, results in all_findings.items():
            if not isinstance(results, dict):
                continue
            count = len(results.get('findings', []))
            sev = results.get('severity', 'LOW')
            if count > 0 and sev in ('CRITICAL', 'HIGH', 'MEDIUM'):
                plain_name = ReportGenerator._user_friendly_category(cat_name)
                category_summaries.append(f'{plain_name}: {count} issue(s)')

        return {
            'risk_description': risk_descriptions.get(risk_level, risk_descriptions['MEDIUM']),
            'score_explanation': (
                f'Security Score: {score}/100. '
                f'Found {total_findings} total finding(s): '
                f'{severity_counts["CRITICAL"]} critical, '
                f'{severity_counts["HIGH"]} high, '
                f'{severity_counts["MEDIUM"]} medium, '
                f'{severity_counts["LOW"]} low.'
            ),
            'category_summaries': category_summaries,
        }

    @staticmethod
    def _user_friendly_category(category: str) -> str:
        """Convert internal category name to user-friendly label"""
        mapping = {
            'Manifest Security': 'App Settings & Permissions',
            'Hardcoded Secrets': 'Exposed Passwords & Keys',
            'Code Vulnerabilities': 'Code Security Issues',
            'High Entropy Strings': 'Potential Hidden Secrets',
            'Code Obfuscation': 'Code Protection',
            'Certificate Security': 'App Signing',
            'Permission Risk Correlation': 'Permission Safety',
            'Component Exposure': 'App Component Access',
            'DEX Structure': 'App Structure',
        }
        return mapping.get(category, category)

    @staticmethod
    def generate_url_report(url: str, findings: dict) -> dict:
        """Generate report for URL scans (unchanged from original)"""
        security_score = 100
        issues = []

        if url.startswith('http://'):
            security_score -= 40
            issues.append({
                'severity': 'HIGH',
                'type': 'Insecure Protocol',
                'description': 'URL uses HTTP instead of HTTPS'
            })

        import re
        if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
            security_score -= 20
            issues.append({
                'severity': 'MEDIUM',
                'type': 'IP-based URL',
                'description': 'URL uses IP address instead of domain name'
            })

        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        if any(url.endswith(tld) for tld in suspicious_tlds):
            security_score -= 30
            issues.append({
                'severity': 'HIGH',
                'type': 'Suspicious TLD',
                'description': 'URL uses a TLD commonly associated with spam/phishing'
            })

        risk_level = 'SAFE'
        if security_score < 40:
            risk_level = 'CRITICAL'
        elif security_score < 60:
            risk_level = 'HIGH'
        elif security_score < 80:
            risk_level = 'MEDIUM'
        elif security_score < 100:
            risk_level = 'LOW'

        return {
            'url': url,
            'security_score': max(0, security_score),
            'risk_level': risk_level,
            'issues': issues,
            'timestamp': datetime.now().isoformat()
        }
