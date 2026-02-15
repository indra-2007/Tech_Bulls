"""APK Structural Parser
Validates and parses APK files using Androguard.
Single entry point for all APK analysis — calls AnalyzeAPK once
and provides structured data to all downstream analyzers.
"""

import zipfile
import os
from typing import Tuple, Optional, List, Dict


class APKParseResult:
    """Holds all parsed APK data for downstream analyzers"""

    def __init__(self, apk_obj, dex_list, analysis_obj):
        self.apk = apk_obj        # androguard APK object
        self.dex_list = dex_list   # list of DalvikVMFormat objects
        self.analysis = analysis_obj  # Analysis object (handles multi-dex)
        self._dex_strings = None
        self._dex_string_contexts = None
        self._resource_strings = None
        self._manifest_xml = None

    @property
    def dex_strings(self) -> List[str]:
        """All strings extracted from DEX files via Analysis object"""
        if self._dex_strings is None:
            self._dex_strings = []
            try:
                for s in self.analysis.get_strings():
                    try:
                        self._dex_strings.append(str(s.get_orig_value()))
                    except Exception:
                        pass
            except Exception:
                pass
        return self._dex_strings

    @property
    def dex_string_contexts(self) -> List[Dict]:
        """DEX strings with class/method context for traceability"""
        if self._dex_string_contexts is None:
            self._dex_string_contexts = []
            try:
                for string_analysis in self.analysis.get_strings():
                    try:
                        string_value = str(string_analysis.get_orig_value())
                    except Exception:
                        continue

                    # Get cross-references to find which class/method uses this string
                    xrefs = []
                    try:
                        for ref_tuple in string_analysis.get_xref_from():
                            # Androguard returns (ClassAnalysis, MethodAnalysis) tuples
                            class_analysis = ref_tuple[0]
                            method_analysis = ref_tuple[1]
                            try:
                                class_name = str(class_analysis.name).replace('/', '.').strip('L;')
                            except Exception:
                                class_name = str(class_analysis).replace('/', '.').strip('L;')
                            try:
                                method_obj = method_analysis.get_method()
                                method_name = str(method_obj.get_name())
                            except Exception:
                                try:
                                    method_name = str(method_analysis.name)
                                except Exception:
                                    method_name = 'unknown'
                            xrefs.append({
                                'class_name': str(class_name),
                                'method_name': str(method_name)
                            })
                    except Exception:
                        pass

                    self._dex_string_contexts.append({
                        'value': string_value,
                        'source': 'DEX',
                        'xrefs': xrefs,
                        'class_name': xrefs[0]['class_name'] if xrefs else None,
                        'method_name': xrefs[0]['method_name'] if xrefs else None,
                    })
            except Exception:
                pass
        return self._dex_string_contexts

    @property
    def resource_strings(self) -> List[Dict]:
        """Strings extracted from resource files inside the APK"""
        if self._resource_strings is None:
            self._resource_strings = []
            scannable_extensions = (
                '.xml', '.json', '.properties', '.txt', '.cfg',
                '.conf', '.yml', '.yaml', '.ini', '.env'
            )
            try:
                for filename in self.apk.get_files():
                    if filename.lower().endswith(scannable_extensions):
                        try:
                            file_data = self.apk.get_file(filename)
                            if file_data:
                                decoded = file_data.decode('utf-8', errors='ignore')
                                self._resource_strings.append({
                                    'value': decoded,
                                    'source': 'resource',
                                    'filename': filename
                                })
                        except Exception:
                            pass
            except Exception:
                pass
        return self._resource_strings

    @property
    def manifest_xml(self) -> str:
        """Decoded AndroidManifest.xml as plain text XML"""
        if self._manifest_xml is None:
            try:
                xml_val = self.apk.get_android_manifest_axml().get_xml()
                self._manifest_xml = xml_val.decode('utf-8', errors='replace') if isinstance(xml_val, bytes) else str(xml_val)
            except Exception:
                self._manifest_xml = ""
        return self._manifest_xml

    def get_all_scannable_text(self) -> str:
        """Combined text from DEX strings + resource files + manifest for regex scanning"""
        parts = []
        parts.extend(self.dex_strings)
        for res in self.resource_strings:
            parts.append(res['value'])
        parts.append(self.manifest_xml)
        return '\n'.join(parts)


class APKParser:
    """Validates and parses APK files using Androguard"""

    @staticmethod
    def validate(file_path: str) -> Tuple[bool, str]:
        """
        Validate that the file is a legitimate APK.

        Checks:
        1. File exists and is readable
        2. Magic bytes match PK (ZIP) signature
        3. Valid ZIP archive
        4. Contains AndroidManifest.xml
        5. Contains at least one classes.dex

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check file exists
        if not os.path.exists(file_path):
            return False, "File does not exist"

        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return False, "File is empty"
        if file_size > 200 * 1024 * 1024:  # 200MB limit
            return False, "File exceeds maximum size limit (200MB)"

        # Check magic bytes (PK signature: 0x50 0x4B 0x03 0x04)
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
            if header[:2] != b'PK':
                return False, "Invalid file signature: not a ZIP/APK file"
            if header[2:4] != b'\x03\x04':
                return False, "Invalid ZIP local file header"
        except Exception as e:
            return False, f"Cannot read file: {str(e)}"

        # Check valid ZIP
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                file_list = zf.namelist()
        except zipfile.BadZipFile:
            return False, "Corrupted APK: not a valid ZIP archive"
        except Exception as e:
            return False, f"Error reading APK: {str(e)}"

        # Check AndroidManifest.xml
        if 'AndroidManifest.xml' not in file_list:
            return False, "Invalid APK: AndroidManifest.xml not found"

        # Check at least one classes.dex
        dex_files = [f for f in file_list if f.endswith('.dex')]
        if not dex_files:
            return False, "Invalid APK: no classes.dex found"

        return True, "Valid APK"

    @staticmethod
    def parse(file_path: str) -> APKParseResult:
        """
        Parse APK using Androguard's AnalyzeAPK.
        Call this ONCE and pass the result to all downstream analyzers.

        Returns:
            APKParseResult containing (apk, dex_list, analysis) objects

        Raises:
            ValueError: If APK is invalid
            RuntimeError: If Androguard fails to parse
        """
        # Validate first
        is_valid, error_msg = APKParser.validate(file_path)
        if not is_valid:
            raise ValueError(f"APK validation failed: {error_msg}")

        try:
            from androguard.misc import AnalyzeAPK
            a, d, dx = AnalyzeAPK(file_path)
            return APKParseResult(a, d, dx)
        except ImportError:
            raise RuntimeError("Androguard is not installed. Run: pip install androguard")
        except Exception as e:
            raise RuntimeError(f"Androguard failed to parse APK: {str(e)}")
