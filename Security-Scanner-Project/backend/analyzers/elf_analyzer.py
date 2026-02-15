"""ELF/SO Analyzer
Parses Linux ELF shared objects and executables.
Extracts symbol tables, string tables, detects suspicious patterns.
"""

import struct
import math
import re
from collections import Counter
from typing import List, Dict
from analyzers.unified_rules import UnifiedRuleEngine


class ELFAnalyzer:
    """Analyzes ELF (SO/Linux binary) files"""

    # Suspicious symbols/functions
    SUSPICIOUS_SYMBOLS = {
        'CRITICAL': {
            'system': 'Arbitrary command execution via system()',
            'popen': 'Command execution with pipe — shell command',
            'execve': 'Process replacement — execute arbitrary binary',
            'execvp': 'Search PATH and execute — command execution',
            'dlopen': 'Dynamic library loading — code injection risk',
            'mprotect': 'Memory permission change — bypass DEP',
            'ptrace': 'Process tracing — anti-debug or injection',
        },
        'HIGH': {
            'fork': 'Process forking — daemon/persistence',
            'socket': 'Network socket creation',
            'connect': 'Network connection initiation',
            'bind': 'Network port binding — server capability',
            'listen': 'Listening for incoming connections',
            'sendto': 'Sending network data',
            'recvfrom': 'Receiving network data',
            'chmod': 'File permission modification',
            'chown': 'File ownership change',
            'setuid': 'Setting user ID — privilege escalation',
            'setgid': 'Setting group ID — privilege escalation',
            'unlink': 'File deletion',
            'mmap': 'Memory mapping — potential code injection',
        },
        'MEDIUM': {
            'getenv': 'Reading environment variables',
            'setenv': 'Setting environment variables',
            'fopen': 'File operations',
            'opendir': 'Directory enumeration',
            'getpid': 'Process ID retrieval',
            'signal': 'Signal handling',
            'pthread_create': 'Thread creation',
            'syslog': 'System logging',
        },
    }

    def analyze(self, file_path: str) -> dict:
        """Full ELF analysis pipeline"""
        all_findings = {}

        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            return self._error_result(f'Cannot read file: {e}')

        # Validate ELF header
        if data[:4] != b'\x7fELF':
            return self._error_result('Not a valid ELF file')

        # ── ELF structure info ────────────────────────────────────
        try:
            elf_info = self._parse_elf_header(data)
            all_findings['ELF Structure'] = elf_info
        except Exception as e:
            print(f'[!] ELF header parse error: {e}')

        # ── Extract all printable strings ─────────────────────────
        extracted_strings = self._extract_printable_strings(data)

        # ── Symbol analysis ───────────────────────────────────────
        try:
            symbol_findings = self._analyze_symbols(extracted_strings)
            if symbol_findings['total_found'] > 0:
                all_findings['Suspicious Symbols'] = symbol_findings
        except Exception as e:
            print(f'[!] Symbol analysis error: {e}')

        # ── ELF-specific pattern detection ────────────────────────
        try:
            elf_patterns = self._detect_elf_patterns(extracted_strings)
            if elf_patterns['total_found'] > 0:
                all_findings['ELF Specific Patterns'] = elf_patterns
        except Exception as e:
            print(f'[!] ELF pattern detection error: {e}')

        # ── Section entropy ───────────────────────────────────────
        try:
            entropy_result = self._analyze_entropy(data)
            if entropy_result['total_found'] > 0:
                all_findings['Binary Entropy'] = entropy_result
        except Exception as e:
            print(f'[!] Entropy analysis error: {e}')

        # ── Run unified rule engine on extracted strings ──────────
        text = '\n'.join(extracted_strings)
        if text:
            rule_findings = UnifiedRuleEngine.scan(text, 'SO', 'ELF strings')
            all_findings.update(rule_findings)

        return all_findings

    def _parse_elf_header(self, data: bytes) -> dict:
        """Parse ELF header for structural information"""
        findings = []

        is_64bit = data[4] == 2
        endian = '<' if data[5] == 1 else '>'

        machine_types = {
            3: 'x86', 40: 'ARM', 62: 'x86_64', 183: 'AArch64',
            8: 'MIPS', 21: 'PowerPC64', 43: 'SPARC',
        }

        elf_types = {1: 'Relocatable', 2: 'Executable', 3: 'Shared Object', 4: 'Core'}

        if is_64bit:
            e_type = struct.unpack_from(endian + 'H', data, 16)[0]
            e_machine = struct.unpack_from(endian + 'H', data, 18)[0]
        else:
            e_type = struct.unpack_from(endian + 'H', data, 16)[0]
            e_machine = struct.unpack_from(endian + 'H', data, 18)[0]

        machine = machine_types.get(e_machine, f'Unknown ({e_machine})')
        elf_type = elf_types.get(e_type, f'Unknown ({e_type})')

        findings.append({
            'type': 'ELF File Info',
            'severity': 'LOW',
            'value': f'{elf_type}, {machine}, {"64" if is_64bit else "32"}-bit',
            'source': 'SO',
            'description': f'ELF file: {elf_type} for {machine} architecture, {"64" if is_64bit else "32"}-bit.',
            'recommendation': 'Review ELF metadata for expected architecture.',
        })

        return {
            'category': 'ELF Structure',
            'total_found': len(findings),
            'findings': findings,
            'severity': 'LOW',
            'description': f'ELF structure: {elf_type}, {machine}, {"64" if is_64bit else "32"}-bit.',
        }

    def _extract_printable_strings(self, data: bytes, min_length: int = 6) -> List[str]:
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

    def _analyze_symbols(self, strings: List[str]) -> dict:
        """Check extracted strings against suspicious symbol database"""
        findings = []
        seen = set()

        for s in strings:
            clean = s.strip()
            for severity, syms in self.SUSPICIOUS_SYMBOLS.items():
                if clean in syms and clean not in seen:
                    seen.add(clean)
                    findings.append({
                        'type': f'Suspicious Symbol: {clean}',
                        'severity': severity,
                        'value': clean,
                        'source': 'SO',
                        'description': syms[clean],
                        'recommendation': 'Investigate why this function is used. May indicate malicious behavior.',
                    })

        severities = [f['severity'] for f in findings]
        overall = 'SAFE'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'Suspicious Symbols',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Symbol analysis: {len(findings)} suspicious function(s) detected.',
        }

    def _detect_elf_patterns(self, strings: List[str]) -> dict:
        """Detect ELF-specific suspicious patterns"""
        findings = []
        text = '\n'.join(strings)

        patterns = [
            (r'/bin/sh', 'Shell Reference', 'CRITICAL',
             'Reference to /bin/sh — indicates shell command execution.'),
            (r'/bin/bash', 'Bash Reference', 'CRITICAL',
             'Reference to /bin/bash — indicates shell command execution.'),
            (r'/tmp/[a-zA-Z0-9_\-]+', 'Temp File Usage', 'MEDIUM',
             'Writes to /tmp directory — may be used for staging.'),
            (r'/etc/passwd', 'Password File Access', 'CRITICAL',
             'Accesses /etc/passwd — user database enumeration.'),
            (r'/etc/shadow', 'Shadow File Access', 'CRITICAL',
             'Accesses /etc/shadow — password hash extraction.'),
            (r'/proc/self/', 'Proc Self Access', 'MEDIUM',
             'Reads /proc/self — process introspection.'),
            (r'LD_PRELOAD', 'LD_PRELOAD Hijack', 'CRITICAL',
             'LD_PRELOAD detected — library injection technique.'),
        ]

        for pattern, name, severity, desc in patterns:
            matches = re.findall(pattern, text)
            if matches:
                for m in set(matches[:3]):
                    findings.append({
                        'type': name,
                        'severity': severity,
                        'value': m,
                        'source': 'SO',
                        'description': desc,
                        'recommendation': 'Review this reference for malicious intent.',
                    })

        severities = [f['severity'] for f in findings]
        overall = 'SAFE'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'ELF Specific Patterns',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'ELF-specific pattern detection: {len(findings)} finding(s).',
        }

    def _analyze_entropy(self, data: bytes) -> dict:
        """Analyze overall binary entropy for packing/encryption"""
        findings = []

        if not data:
            return {'category': 'Binary Entropy', 'total_found': 0, 'findings': [], 'severity': 'SAFE', 'description': 'Empty data.'}

        # Overall entropy
        entropy = self._shannon_entropy(data)

        if entropy >= 7.0:
            findings.append({
                'type': 'Packed Binary',
                'severity': 'HIGH',
                'value': f'Overall entropy: {entropy:.2f}/8.0',
                'source': 'SO',
                'description': f'Binary has very high entropy ({entropy:.2f}), indicating packing or encryption.',
                'recommendation': 'Investigate with tools like UPX or binwalk.',
            })
        elif entropy >= 6.5:
            findings.append({
                'type': 'Elevated Entropy',
                'severity': 'MEDIUM',
                'value': f'Overall entropy: {entropy:.2f}/8.0',
                'source': 'SO',
                'description': f'Binary has elevated entropy ({entropy:.2f}). May contain compressed regions.',
                'recommendation': 'Review binary for obfuscated or compressed sections.',
            })

        severities = [f['severity'] for f in findings]
        overall = 'SAFE'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'Binary Entropy',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Binary entropy: {entropy:.2f}/8.0.',
        }

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
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
            'ELF Analysis Error': {
                'category': 'ELF Analysis Error',
                'total_found': 1,
                'findings': [{
                    'type': 'Analysis Error',
                    'severity': 'MEDIUM',
                    'value': msg,
                    'source': 'SO',
                    'description': msg,
                    'recommendation': 'Ensure the file is a valid ELF binary.',
                }],
                'severity': 'MEDIUM',
                'description': msg,
            }
        }
