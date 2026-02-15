"""Android APK Analyzer
Analyzes Android APK files for dangerous permissions
"""

import re
import zipfile
import xml.etree.ElementTree as ET
from io import BytesIO

class AndroidAnalyzer:
    """Analyzes Android APK files for security issues"""
    
    # Dangerous Android permissions that require user approval
    DANGEROUS_PERMISSIONS = {
        'READ_CALENDAR': {'severity': 'MEDIUM', 'category': 'Calendar'},
        'WRITE_CALENDAR': {'severity': 'MEDIUM', 'category': 'Calendar'},
        'CAMERA': {'severity': 'HIGH', 'category': 'Camera'},
        'READ_CONTACTS': {'severity': 'HIGH', 'category': 'Contacts'},
        'WRITE_CONTACTS': {'severity': 'HIGH', 'category': 'Contacts'},
        'GET_ACCOUNTS': {'severity': 'MEDIUM', 'category': 'Contacts'},
        'ACCESS_FINE_LOCATION': {'severity': 'HIGH', 'category': 'Location'},
        'ACCESS_COARSE_LOCATION': {'severity': 'HIGH', 'category': 'Location'},
        'RECORD_AUDIO': {'severity': 'HIGH', 'category': 'Microphone'},
        'READ_PHONE_STATE': {'severity': 'MEDIUM', 'category': 'Phone'},
        'READ_PHONE_NUMBERS': {'severity': 'MEDIUM', 'category': 'Phone'},
        'CALL_PHONE': {'severity': 'MEDIUM', 'category': 'Phone'},
        'READ_CALL_LOG': {'severity': 'HIGH', 'category': 'Phone'},
        'WRITE_CALL_LOG': {'severity': 'HIGH', 'category': 'Phone'},
        'ADD_VOICEMAIL': {'severity': 'MEDIUM', 'category': 'Phone'},
        'USE_SIP': {'severity': 'LOW', 'category': 'Phone'},
        'PROCESS_OUTGOING_CALLS': {'severity': 'MEDIUM', 'category': 'Phone'},
        'BODY_SENSORS': {'severity': 'MEDIUM', 'category': 'Sensors'},
        'SEND_SMS': {'severity': 'HIGH', 'category': 'SMS'},
        'RECEIVE_SMS': {'severity': 'MEDIUM', 'category': 'SMS'},
        'READ_SMS': {'severity': 'HIGH', 'category': 'SMS'},
        'RECEIVE_WAP_PUSH': {'severity': 'MEDIUM', 'category': 'SMS'},
        'RECEIVE_MMS': {'severity': 'MEDIUM', 'category': 'SMS'},
        'READ_EXTERNAL_STORAGE': {'severity': 'MEDIUM', 'category': 'Storage'},
        'WRITE_EXTERNAL_STORAGE': {'severity': 'MEDIUM', 'category': 'Storage'},
        'SYSTEM_ALERT_WINDOW': {'severity': 'HIGH', 'category': 'System'},
        'WRITE_SETTINGS': {'severity': 'MEDIUM', 'category': 'System'},
    }
    
    def analyze_apk(self, apk_path: str) -> dict:
        """
        Analyze an APK file for dangerous permissions
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            dict with findings
        """
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk:
                # Extract AndroidManifest.xml
                if 'AndroidManifest.xml' not in apk.namelist():
                    return self._error_result('AndroidManifest.xml not found in APK')
                
                manifest_data = apk.read('AndroidManifest.xml')
                return self.analyze_manifest(manifest_data)
                
        except zipfile.BadZipFile:
            return self._error_result('Invalid APK file (not a valid ZIP archive)')
        except Exception as e:
            return self._error_result(f'Error analyzing APK: {str(e)}')
    
    def analyze_manifest(self, manifest_content: bytes) -> dict:
        """
        Parse AndroidManifest.xml and analyze permissions
        
        Args:
            manifest_content: Raw AndroidManifest.xml bytes or string
            
        Returns:
            dict with findings
        """
        findings = []
        
        try:
            # Try to parse as XML (for decompiled/text manifests)
            if isinstance(manifest_content, bytes):
                try:
                    manifest_content = manifest_content.decode('utf-8')
                except:
                    # Binary manifest - try to extract permissions with regex
                    return self._analyze_binary_manifest(manifest_content)
            
            # Parse XML manifest
            root = ET.fromstring(manifest_content)
            
            # Find all uses-permission tags
            for perm in root.findall('.//{http://schemas.android.com/apk/res/android}uses-permission') + \
                       root.findall('.//uses-permission'):
                perm_name = None
                for attr in perm.attrib.values():
                    if 'android.permission.' in str(attr):
                        perm_name = str(attr).split('.')[-1]
                        break
                
                if perm_name and perm_name in self.DANGEROUS_PERMISSIONS:
                    perm_info = self.DANGEROUS_PERMISSIONS[perm_name]
                    findings.append({
                        'type': f'Dangerous Permission: {perm_name}',
                        'category': perm_info['category'],
                        'severity': perm_info['severity'],
                        'value': f'android.permission.{perm_name}',
                        'recommendation': f'Verify that {perm_name} permission is essential for app functionality. Request only necessary permissions.'
                    })
            
            return self._format_result(findings)
            
        except ET.ParseError:
            # Try binary manifest analysis
            if isinstance(manifest_content, (bytes, str)):
                return self._analyze_binary_manifest(manifest_content)
            return self._error_result('Could not parse AndroidManifest.xml')
    
    def _analyze_binary_manifest(self, content) -> dict:
        """Analyze binary AndroidManifest.xml using string search"""
        findings = []
        
        # Convert to string if bytes
        if isinstance(content, bytes):
            try:
                content_str = content.decode('utf-8', errors='ignore')
            except:
                content_str = str(content)
        else:
            content_str = content
        
        # Search for permission strings
        for perm_name, perm_info in self.DANGEROUS_PERMISSIONS.items():
            pattern = f'android.permission.{perm_name}'
            if pattern in content_str or perm_name in content_str:
                findings.append({
                    'type': f'Dangerous Permission: {perm_name}',
                    'category': perm_info['category'],
                    'severity': perm_info['severity'],
                    'value': pattern,
                    'recommendation': f'Verify that {perm_name} permission is essential for app functionality.'
                })
        
        return self._format_result(findings)
    
    def _format_result(self, findings: list) -> dict:
        """Format analysis results"""
        # Group by category
        categories = {}
        for finding in findings:
            cat = finding['category']
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(finding)
        
        # Calculate severity
        severities = [f['severity'] for f in findings]
        overall_severity = 'SAFE'
        if 'HIGH' in severities:
            overall_severity = 'HIGH'
        elif 'MEDIUM' in severities:
            overall_severity = 'MEDIUM'
        elif 'LOW' in severities:
            overall_severity = 'LOW'
        
        return {
            'category': 'Android Permissions',
            'total_found': len(findings),
            'findings': findings,
            'grouped_by_category': categories,
            'severity': overall_severity,
            'description': f'Found {len(findings)} dangerous permission(s) requested by the app.'
        }
    
    def _error_result(self, error_msg: str) -> dict:
        """Return error result"""
        return {
            'category': 'Android Permissions',
            'total_found': 0,
            'findings': [],
            'severity': 'ERROR',
            'description': error_msg,
            'error': True
        }
