"""EXE/DLL Analyzer (PE Format)
Parses Windows PE files using pefile library.
Extracts strings from data sections, analyzes imports, detects packing.
"""

import math
import re
from collections import Counter
from typing import List, Dict, Optional
from analyzers.unified_rules import UnifiedRuleEngine


class PEAnalyzer:
    """Analyzes Windows EXE and DLL files"""

    # Suspicious imports that indicate dangerous capabilities
    SUSPICIOUS_IMPORTS = {
        'CRITICAL': {
            'VirtualAllocEx': 'Remote memory allocation — used for code injection',
            'WriteProcessMemory': 'Writing to another process memory — code injection',
            'CreateRemoteThread': 'Remote thread creation — common injection technique',
            'NtCreateThreadEx': 'Low-level thread creation — evasion technique',
            'RtlCreateUserThread': 'Low-level thread creation — evasion technique',
            'SetWindowsHookExA': 'Keyboard/mouse hook — keylogger indicator',
            'SetWindowsHookExW': 'Keyboard/mouse hook — keylogger indicator',
            'GetAsyncKeyState': 'Keystroke monitoring — keylogger indicator',
            'OpenProcess': 'Opening other process handles — injection setup',
            'AdjustTokenPrivileges': 'Privilege escalation attempt',
            'LdrLoadDll': 'Manual DLL loading — evasion technique',
            'IsDebuggerPresent': 'Anti-debugging check — evasion technique',
            'CheckRemoteDebuggerPresent': 'Anti-debugging check — evasion technique',
        },
        'HIGH': {
            'CreateToolhelp32Snapshot': 'Process enumeration — reconnaissance',
            'Process32First': 'Process enumeration — reconnaissance',
            'ShellExecuteA': 'Command execution',
            'ShellExecuteW': 'Command execution',
            'WinExec': 'Legacy command execution',
            'CreateProcessA': 'New process creation',
            'CreateProcessW': 'New process creation',
            'InternetOpenA': 'Network connection initiation',
            'InternetOpenUrlA': 'URL download capability',
            'URLDownloadToFileA': 'File download from URL',
            'URLDownloadToFileW': 'File download from URL',
            'CryptEncrypt': 'Encryption capability — ransomware indicator',
            'CryptDecrypt': 'Decryption capability',
            'RegSetValueExA': 'Registry modification — persistence',
            'RegSetValueExW': 'Registry modification — persistence',
        },
        'MEDIUM': {
            'CreateServiceA': 'Service creation — persistence mechanism',
            'CreateServiceW': 'Service creation — persistence mechanism',
            'GetVolumeInformationA': 'System info enumeration',
            'GetAdaptersInfo': 'Network adapter enumeration',
            'GetModuleHandleA': 'Module enumeration',
            'LoadLibraryA': 'Dynamic library loading',
            'LoadLibraryW': 'Dynamic library loading',
            'FindResourceA': 'Resource extraction',
            'CreateFileA': 'File operations',
            'CreateFileW': 'File operations',
            'DeleteFileA': 'File deletion',
            'DeleteFileW': 'File deletion',
        },
    }

    def analyze(self, file_path: str, file_type: str = 'EXE') -> dict:
        """
        Full PE analysis pipeline.

        Returns:
            Dict with all findings categories
        """
        all_findings = {}

        try:
            import pefile
            pe = pefile.PE(file_path)
        except ImportError:
            return self._error_result('pefile library not installed')
        except Exception as e:
            return self._error_result(f'PE parse failed: {str(e)}')

        # ── PE Structure info ─────────────────────────────────────
        try:
            pe_info = self._extract_pe_info(pe, file_type)
            all_findings['PE Structure'] = pe_info
        except Exception as e:
            print(f'[!] PE structure analysis error: {e}')

        # ── Extract strings from data sections ────────────────────
        extracted_strings = ''
        try:
            extracted_strings = self._extract_section_strings(pe, file_path)
        except Exception as e:
            print(f'[!] PE string extraction error: {e}')

        # ── Suspicious imports ────────────────────────────────────
        try:
            import_findings = self._analyze_imports(pe, file_type)
            if import_findings['total_found'] > 0:
                all_findings['Suspicious Imports'] = import_findings
        except Exception as e:
            print(f'[!] PE import analysis error: {e}')

        # ── Section entropy (packing detection) ───────────────────
        try:
            packing_findings = self._detect_packing(pe, file_type)
            if packing_findings['total_found'] > 0:
                all_findings['Packing Detection'] = packing_findings
        except Exception as e:
            print(f'[!] PE packing detection error: {e}')

        # ── Run unified rule engine on extracted strings ──────────
        if extracted_strings:
            rule_findings = UnifiedRuleEngine.scan(
                extracted_strings, file_type, 'PE data sections'
            )
            all_findings.update(rule_findings)

        return all_findings

    def _extract_pe_info(self, pe, file_type: str) -> dict:
        """Extract PE structural information"""
        findings = []

        # Basic PE info
        compile_time = None
        try:
            import time
            compile_time = time.strftime(
                '%Y-%m-%d %H:%M:%S',
                time.gmtime(pe.FILE_HEADER.TimeDateStamp)
            )
        except Exception:
            pass

        sections = []
        for section in pe.sections:
            try:
                name = section.Name.rstrip(b'\x00').decode('utf-8', errors='replace')
                sections.append(name)
            except Exception:
                sections.append('(unknown)')

        findings.append({
            'type': 'PE File Info',
            'severity': 'LOW',
            'value': f'Sections: {", ".join(sections)}',
            'source': file_type,
            'description': f'PE file with {len(pe.sections)} sections. Compile timestamp: {compile_time or "unknown"}.',
            'recommendation': 'Review PE structure for anomalies.',
            'context': f'Machine: {hex(pe.FILE_HEADER.Machine)}, Compile: {compile_time}',
        })

        # Check for ASLR, DEP
        try:
            dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
            aslr = bool(dll_chars & 0x0040)
            dep = bool(dll_chars & 0x0100)

            if not aslr:
                findings.append({
                    'type': 'ASLR Disabled',
                    'severity': 'MEDIUM',
                    'value': 'ASLR (Address Space Layout Randomization) not enabled',
                    'source': file_type,
                    'description': 'ASLR is not enabled. Makes memory-based exploits easier.',
                    'recommendation': 'Enable ASLR via /DYNAMICBASE linker flag.',
                })
            if not dep:
                findings.append({
                    'type': 'DEP Disabled',
                    'severity': 'MEDIUM',
                    'value': 'DEP (Data Execution Prevention) not enabled',
                    'source': file_type,
                    'description': 'DEP/NX is not enabled. Allows code execution from data pages.',
                    'recommendation': 'Enable DEP via /NXCOMPAT linker flag.',
                })
        except Exception:
            pass

        severities = [f['severity'] for f in findings]
        overall = 'LOW'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'PE Structure',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'PE file structure analysis: {len(pe.sections)} sections detected.',
        }

    def _extract_section_strings(self, pe, file_path: str, min_length: int = 6) -> str:
        """Extract printable strings from PE data sections"""
        all_strings = []

        # Extract from sections
        data_sections = ['.rdata', '.data', '.rsrc', '.text']
        for section in pe.sections:
            try:
                name = section.Name.rstrip(b'\x00').decode('utf-8', errors='replace')
                data = section.get_data()
                strings = self._extract_printable(data, min_length)
                all_strings.extend(strings)
            except Exception:
                continue

        # Also extract from the raw file for anything missed
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
            raw_strings = self._extract_printable(raw_data, min_length)
            # Deduplicate
            existing = set(all_strings)
            for s in raw_strings:
                if s not in existing:
                    all_strings.append(s)
        except Exception:
            pass

        return '\n'.join(all_strings)

    def _extract_printable(self, data: bytes, min_length: int = 6) -> List[str]:
        """Extract printable ASCII strings from binary data"""
        strings = []
        current = []
        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if current and len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        if current and len(current) >= min_length:
            strings.append(''.join(current))
        return strings

    def _analyze_imports(self, pe, file_type: str) -> dict:
        """Check PE imports against suspicious function database"""
        findings = []

        try:
            if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                return {'category': 'Suspicious Imports', 'total_found': 0, 'findings': [], 'severity': 'SAFE', 'description': 'No imports found.'}

            imported_dlls = []
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='replace')
                imported_dlls.append(dll_name)
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='replace')
                        for severity, funcs in self.SUSPICIOUS_IMPORTS.items():
                            if func_name in funcs:
                                findings.append({
                                    'type': f'Suspicious Import: {func_name}',
                                    'severity': severity,
                                    'value': f'{dll_name}:{func_name}',
                                    'source': file_type,
                                    'context': f'DLL: {dll_name}',
                                    'description': funcs[func_name],
                                    'recommendation': 'Investigate why this API is being used. May indicate malicious intent.',
                                })
        except Exception as e:
            print(f'[!] Import analysis error: {e}')

        severities = [f['severity'] for f in findings]
        overall = 'SAFE'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'Suspicious Imports',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Analyzed PE imports: {len(findings)} suspicious import(s) found.',
        }

    def _detect_packing(self, pe, file_type: str) -> dict:
        """Detect packed/encrypted sections by entropy analysis"""
        findings = []

        for section in pe.sections:
            try:
                name = section.Name.rstrip(b'\x00').decode('utf-8', errors='replace')
                data = section.get_data()
                entropy = self._section_entropy(data)

                if entropy >= 7.0:
                    findings.append({
                        'type': 'Packed/Encrypted Section',
                        'severity': 'HIGH',
                        'value': f'Section "{name}" entropy: {entropy:.2f}/8.0',
                        'source': file_type,
                        'context': f'Section: {name}, Size: {len(data)} bytes',
                        'description': f'Section "{name}" has extremely high entropy ({entropy:.2f}), indicating packing, encryption, or compressed data. Common in packed malware.',
                        'recommendation': 'Investigate packed sections. Use tools like UPX or custom unpackers to analyze.',
                    })
                elif entropy >= 6.5:
                    findings.append({
                        'type': 'High Entropy Section',
                        'severity': 'MEDIUM',
                        'value': f'Section "{name}" entropy: {entropy:.2f}/8.0',
                        'source': file_type,
                        'context': f'Section: {name}, Size: {len(data)} bytes',
                        'description': f'Section "{name}" has elevated entropy ({entropy:.2f}). May contain compressed resources or obfuscated data.',
                        'recommendation': 'Review section contents for obfuscated code or embedded payloads.',
                    })
            except Exception:
                continue

        severities = [f['severity'] for f in findings]
        overall = 'SAFE'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'Packing Detection',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Section entropy analysis: {len(findings)} anomalous section(s).',
        }

    def _section_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy for a section"""
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _error_result(self, msg: str) -> dict:
        return {
            'PE Analysis Error': {
                'category': 'PE Analysis Error',
                'total_found': 1,
                'findings': [{
                    'type': 'Analysis Error',
                    'severity': 'MEDIUM',
                    'value': msg,
                    'source': 'PE',
                    'description': msg,
                    'recommendation': 'Ensure pefile is installed: pip install pefile',
                }],
                'severity': 'MEDIUM',
                'description': msg,
            }
        }
