"""
Flask Security Scanner API Backend v3.0
Multi-format static analysis engine.

Pipeline:
1. File intake → save temporarily
2. File classification → magic bytes + structure validation
3. Route to appropriate analyzer (APK, EXE/DLL, SO, JAR, IPA, PDF, JS)
4. Unified rule engine applied to all extracted strings
5. Risk scoring + dual report generation (Developer + User views)
6. File cleanup
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import tempfile
import traceback
from werkzeug.utils import secure_filename

# ── File Classification ───────────────────────────────────────────
from analyzers.file_classifier import FileClassifier

# ── APK Analysis Pipeline (Androguard-based) ─────────────────────
from analyzers.apk_parser import APKParser
from analyzers.manifest_analyzer import ManifestAnalyzer
from analyzers.dex_analyzer import DEXAnalyzer
from analyzers.secret_detector import SecretDetector
from analyzers.code_patterns import CodePatternAnalyzer
from analyzers.entropy_analyzer import EntropyAnalyzer
from analyzers.obfuscation_detector import ObfuscationDetector
from analyzers.certificate_analyzer import CertificateAnalyzer
from analyzers.permission_risk import PermissionRiskAnalyzer
from analyzers.component_exposure import ComponentExposureAnalyzer

# ── Multi-Format Analyzers ────────────────────────────────────────
from analyzers.exe_analyzer import PEAnalyzer
from analyzers.elf_analyzer import ELFAnalyzer
from analyzers.jar_analyzer import JARAnalyzer
from analyzers.ipa_analyzer import IPAAnalyzer
from analyzers.pdf_analyzer import PDFAnalyzer
from analyzers.js_analyzer import JSAnalyzer

# ── Utilities ─────────────────────────────────────────────────────
from utils.file_handler import FileHandler
from utils.report_generator import ReportGenerator

app = Flask(__name__)
CORS(app)

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200MB max
UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {
    'apk', 'exe', 'dll', 'so',
    'jar', 'ipa', 'pdf',
    'js', 'html', 'htm', 'css', 'json', 'xml',
}


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Security Scanner API',
        'engine': 'Multi-Format Static Analysis v3.0',
        'supported_formats': sorted(list(ALLOWED_EXTENSIONS)),
    }), 200


@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    """
    Scan uploaded file for security vulnerabilities.
    Auto-detects file type via magic bytes + structure validation.
    Routes to the appropriate analyzer pipeline.
    """
    try:
        # ── File Intake Validation ────────────────────────────────
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not allowed_file(file.filename):
            supported = ', '.join(f'.{ext}' for ext in sorted(ALLOWED_EXTENSIONS))
            return jsonify({'error': f'Unsupported file type. Supported: {supported}'}), 400

        # Save file temporarily
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        try:
            # ── File Metadata ─────────────────────────────────────
            file_info = FileHandler.get_file_info(file_path)
            file_info['filename'] = filename
            file_hash = FileHandler.calculate_hash(file_path)

            try:
                file_info['entropy'] = FileHandler.calculate_entropy(file_path)
            except Exception:
                file_info['entropy'] = 0

            # ── Step 1: Classify file type ────────────────────────
            file_type, type_description = FileClassifier.classify(file_path)
            file_info['type'] = file_type
            file_info['type_description'] = type_description

            # ── Step 2: Route to correct pipeline ─────────────────
            route = FileClassifier.get_analyzer_route(file_type)

            if route == 'apk_pipeline':
                report = _analyze_apk(file_path, file_info, file_hash)
            elif route == 'pe_pipeline':
                report = _analyze_pe(file_path, file_type, file_info, file_hash)
            elif route == 'elf_pipeline':
                report = _analyze_elf(file_path, file_info, file_hash)
            elif route == 'jar_pipeline':
                report = _analyze_jar(file_path, file_info, file_hash)
            elif route == 'ipa_pipeline':
                report = _analyze_ipa(file_path, file_info, file_hash)
            elif route == 'pdf_pipeline':
                report = _analyze_pdf(file_path, file_info, file_hash)
            elif route == 'js_pipeline':
                report = _analyze_js(file_path, file_type, file_info, file_hash)
            else:
                report = _analyze_generic(file_path, filename, file_type, file_info, file_hash)

            return jsonify(report), 200

        finally:
            # ── Cleanup (always delete temp file) ─────────────────
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception:
                    pass

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


# ═══════════════════════════════════════════════════════════════════
# ANALYZER PIPELINES
# ═══════════════════════════════════════════════════════════════════

def _analyze_apk(file_path: str, file_info: dict, file_hash: dict) -> dict:
    """Full APK analysis pipeline using Androguard"""
    try:
        apk_result = APKParser.parse(file_path)
    except ValueError as e:
        return _validation_error_report(str(e), 'APK', file_info, file_hash)
    except RuntimeError as e:
        return _runtime_error_report(str(e), file_info, file_hash)

    # Extract app info
    app_info = {}
    try:
        app_info = {
            'package_name': apk_result.apk.get_package(),
            'app_name': apk_result.apk.get_app_name(),
            'version_name': apk_result.apk.get_androidversion_name(),
            'version_code': apk_result.apk.get_androidversion_code(),
            'min_sdk': apk_result.apk.get_min_sdk_version(),
            'target_sdk': apk_result.apk.get_target_sdk_version(),
        }
    except Exception:
        pass

    # Run all APK analyzers (each in try/except for resilience)
    all_findings = {}

    # Phase 1: Run secret detector first to collect matched values
    secret_result = None
    try:
        secret_result = SecretDetector().analyze(apk_result)
        all_findings['Hardcoded Secrets'] = secret_result
    except Exception as e:
        print(f'[!] Hardcoded Secrets error: {e}')

    # Collect secret-matched values to exclude from entropy
    secret_matched_values = set()
    if secret_result:
        for f in secret_result.get('findings', []):
            val = f.get('value', '')
            if val.endswith('...'):
                val = val[:-3]
            if len(val) >= 10:
                secret_matched_values.add(val)

    # Phase 2: Run remaining analyzers
    analyzers = [
        ('Manifest Security', lambda: ManifestAnalyzer().analyze(apk_result)),
        ('DEX Structure', lambda: DEXAnalyzer().analyze(apk_result)),
        ('Code Vulnerabilities', lambda: CodePatternAnalyzer().analyze(apk_result)),
        ('High Entropy Strings', lambda: EntropyAnalyzer().analyze(apk_result, exclude_values=secret_matched_values)),
        ('Code Obfuscation', lambda: ObfuscationDetector().analyze(apk_result)),
        ('Certificate Security', lambda: CertificateAnalyzer().analyze(apk_result)),
        ('Permission Risk Correlation', lambda: PermissionRiskAnalyzer().analyze(apk_result)),
        ('Component Exposure', lambda: ComponentExposureAnalyzer().analyze(apk_result)),
    ]

    for name, analyzer_fn in analyzers:
        try:
            all_findings[name] = analyzer_fn()
        except Exception as e:
            print(f'[!] {name} error: {e}')

    return ReportGenerator.generate_report(all_findings, file_info, file_hash, app_info)


def _analyze_pe(file_path: str, file_type: str, file_info: dict, file_hash: dict) -> dict:
    """EXE/DLL analysis via PE parser"""
    all_findings = PEAnalyzer().analyze(file_path, file_type)
    return ReportGenerator.generate_report(all_findings, file_info, file_hash)


def _analyze_elf(file_path: str, file_info: dict, file_hash: dict) -> dict:
    """SO/ELF analysis"""
    all_findings = ELFAnalyzer().analyze(file_path)
    return ReportGenerator.generate_report(all_findings, file_info, file_hash)


def _analyze_jar(file_path: str, file_info: dict, file_hash: dict) -> dict:
    """JAR analysis"""
    all_findings = JARAnalyzer().analyze(file_path)
    return ReportGenerator.generate_report(all_findings, file_info, file_hash)


def _analyze_ipa(file_path: str, file_info: dict, file_hash: dict) -> dict:
    """IPA analysis"""
    all_findings = IPAAnalyzer().analyze(file_path)
    return ReportGenerator.generate_report(all_findings, file_info, file_hash)


def _analyze_pdf(file_path: str, file_info: dict, file_hash: dict) -> dict:
    """PDF analysis"""
    all_findings = PDFAnalyzer().analyze(file_path)
    return ReportGenerator.generate_report(all_findings, file_info, file_hash)


def _analyze_js(file_path: str, file_type: str, file_info: dict, file_hash: dict) -> dict:
    """JS/HTML/CSS/JSON analysis"""
    all_findings = JSAnalyzer().analyze(file_path, file_type)
    return ReportGenerator.generate_report(all_findings, file_info, file_hash)


def _analyze_generic(file_path: str, filename: str, file_type: str,
                     file_info: dict, file_hash: dict) -> dict:
    """Fallback generic analysis using string extraction + unified rules"""
    from analyzers.unified_rules import UnifiedRuleEngine

    try:
        file_content = FileHandler.extract_strings(file_path)
    except Exception:
        file_content = ''

    all_findings = {}
    if file_content:
        all_findings = UnifiedRuleEngine.scan(file_content, file_type, 'full_file')

    return ReportGenerator.generate_report(all_findings, file_info, file_hash)


# ═══════════════════════════════════════════════════════════════════
# ERROR HELPERS
# ═══════════════════════════════════════════════════════════════════

def _validation_error_report(error_msg: str, file_type: str,
                              file_info: dict, file_hash: dict) -> dict:
    return {
        'security_score': 0,
        'risk_level': 'CRITICAL',
        'summary': {'total_issues': 1, 'critical': 1, 'high': 0, 'medium': 0, 'low': 0},
        'findings_by_category': {
            'validation': {
                'category': f'{file_type} Validation',
                'total_found': 1,
                'severity': 'CRITICAL',
                'findings': [{
                    'type': f'Invalid {file_type}',
                    'severity': 'CRITICAL',
                    'value': error_msg,
                    'description': f'The uploaded file failed {file_type} validation.',
                    'recommendation': f'Ensure the file is a valid {file_type}.',
                }]
            }
        },
        'recommendations': [{
            'priority': 'CRITICAL',
            'title': f'Invalid {file_type} File',
            'description': error_msg,
            'actions': [f'Upload a valid {file_type} file.'],
        }],
        'scan_metadata': {'file_info': file_info, 'file_hash': file_hash},
    }


def _runtime_error_report(error_msg: str, file_info: dict, file_hash: dict) -> dict:
    return {
        'security_score': 0,
        'risk_level': 'CRITICAL',
        'error': error_msg,
        'summary': {'total_issues': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'findings_by_category': {},
        'recommendations': [],
        'scan_metadata': {'file_info': file_info, 'file_hash': file_hash},
    }


# ═══════════════════════════════════════════════════════════════════
# STARTUP
# ═══════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print(' ')
    print('=' * 60)
    print('  Security Scanner API Server v3.0')
    print('  Multi-Format Static Analysis Engine')
    print('=' * 60)
    print('  Supported File Types:')
    print('    🤖  APK  → Androguard structured analysis')
    print('    🖥️  EXE  → PE parser + import analysis')
    print('    📦  DLL  → PE parser + import analysis')
    print('    🐧  SO   → ELF parser + symbol analysis')
    print('    ☕  JAR  → ZIP + class string extraction')
    print('    🍎  IPA  → Info.plist + Mach-O strings')
    print('    📄  PDF  → JS detection + embedded exe scan')
    print('    🌐  JS   → Regex + XSS pattern analysis')
    print('    📝  HTML → Script + form security analysis')
    print('  Host: http://localhost:5001')
    print('=' * 60)
    print(' ')

    app.run(debug=True, host='0.0.0.0', port=5001)
