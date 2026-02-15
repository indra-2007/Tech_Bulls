"""DEX Analyzer
Extracts structured data from DEX files via Androguard Analysis object.
Provides string pool, class definitions, method references, and invoked methods.
Does NOT scan raw binary — only structured DEX data.
"""

from typing import List, Dict


class DEXAnalyzer:
    """Extracts and analyzes structured DEX data via Androguard"""

    def analyze(self, apk_result) -> dict:
        """
        Extract and report DEX structure overview.

        Args:
            apk_result: APKParseResult from apk_parser

        Returns:
            dict with DEX structure findings (informational)
        """
        findings = []
        dx = apk_result.analysis
        a = apk_result.apk

        # 1. DEX file count
        dex_count = len(apk_result.dex_list) if apk_result.dex_list else 0
        if dex_count > 1:
            findings.append({
                'type': 'Multi-DEX Application',
                'severity': 'LOW',
                'value': f'{dex_count} DEX files detected',
                'source': 'DEX',
                'description': f'Application uses {dex_count} DEX files (multidex). This is common for large apps but increases attack surface.',
                'recommendation': 'Ensure all DEX files are analyzed. Multi-DEX apps may hide code in secondary DEX files.',
            })

        # 2. String pool stats
        string_count = len(apk_result.dex_strings)
        findings.append({
            'type': 'DEX String Pool',
            'severity': 'LOW',
            'value': f'{string_count} strings extracted from DEX',
            'source': 'DEX',
            'description': f'Extracted {string_count} strings from the DEX string pool for analysis by the rule engine.',
            'recommendation': 'String pool analysis helps detect hardcoded secrets, URLs, and configuration data.',
        })

        # 3. Class count
        try:
            classes = list(dx.get_classes())
            class_count = len(classes)
            external_count = sum(1 for c in classes if c.is_external())
            internal_count = class_count - external_count

            findings.append({
                'type': 'DEX Class Analysis',
                'severity': 'LOW',
                'value': f'{internal_count} internal classes, {external_count} external references',
                'source': 'DEX',
                'description': f'Total classes: {class_count}. Internal (app code): {internal_count}. External (framework/library): {external_count}.',
                'recommendation': 'Internal classes contain the application logic and are the primary target for security analysis.',
            })
        except Exception:
            pass

        # 4. Method count
        try:
            methods = list(dx.get_methods())
            method_count = len(methods)
            findings.append({
                'type': 'DEX Method Count',
                'severity': 'LOW',
                'value': f'{method_count} methods analyzed',
                'source': 'DEX',
                'description': f'Analyzed {method_count} method references for security-relevant API calls.',
                'recommendation': 'Method analysis helps detect dangerous API usage patterns.',
            })
        except Exception:
            pass

        return {
            'category': 'DEX Structure',
            'total_found': len(findings),
            'findings': findings,
            'severity': 'LOW',
            'description': f'DEX structural analysis: {dex_count} DEX file(s), {string_count} strings extracted.'
        }

    @staticmethod
    def get_method_calls(apk_result) -> List[Dict]:
        """
        Extract all method invocations from DEX for code pattern analysis.

        Returns:
            List of dicts with: class_name, method_name, descriptor, xrefs
        """
        method_calls = []
        dx = apk_result.analysis

        try:
            for method in dx.get_methods():
                try:
                    method_info = method.get_method()
                    class_name = str(method_info.get_class_name()).replace('/', '.').strip('L;')
                    method_name = str(method_info.get_name())
                    descriptor = str(method_info.get_descriptor())

                    method_calls.append({
                        'class_name': class_name,
                        'method_name': method_name,
                        'descriptor': descriptor,
                        'is_external': method.is_external(),
                    })
                except Exception:
                    continue
        except Exception:
            pass

        return method_calls

    @staticmethod
    def get_string_usages(apk_result) -> List[Dict]:
        """
        Get all DEX strings with their class/method usage context.
        This is the primary data source for secret detection and rule engine.

        Returns:
            List of dicts: {value, source, class_name, method_name}
        """
        return apk_result.dex_string_contexts

    @staticmethod
    def get_class_names(apk_result) -> List[str]:
        """
        Get all internal class names for obfuscation analysis.

        Returns:
            List of class name strings
        """
        class_names = []
        try:
            for c in apk_result.analysis.get_classes():
                if not c.is_external():
                    name = str(c.name).replace('/', '.').strip('L;')
                    class_names.append(name)
        except Exception:
            pass
        return class_names
