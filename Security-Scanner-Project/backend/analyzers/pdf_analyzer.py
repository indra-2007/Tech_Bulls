"""PDF Analyzer
Analyzes PDF documents for embedded threats.
Detects embedded JavaScript, auto-execution, embedded files,
suspicious URLs, and obfuscated streams.
"""

import re
import math
from collections import Counter
from typing import List, Dict
from analyzers.unified_rules import UnifiedRuleEngine


class PDFAnalyzer:
    """Analyzes PDF files for security threats"""

    # PDF threat keywords by category
    PDF_THREATS = {
        'JavaScript Execution': {
            'patterns': [
                r'/JavaScript\b', r'/JS\b', r'/RichMedia',
            ],
            'severity': 'CRITICAL',
            'description': 'PDF contains JavaScript. Can be used for exploitation.',
            'recommendation': 'Remove embedded JavaScript. Scan PDF with antivirus.',
        },
        'Auto-Execution': {
            'patterns': [
                r'/OpenAction', r'/AA\b', r'/Launch', r'/SubmitForm',
                r'/GoTo\b', r'/GoToR', r'/GoToE', r'/Named',
            ],
            'severity': 'HIGH',
            'description': 'PDF contains auto-execution triggers. May run code when opened.',
            'recommendation': 'Open PDF in a sandboxed viewer. Check OpenAction targets.',
        },
        'Embedded Files': {
            'patterns': [
                r'/EmbeddedFile', r'/EmbeddedFiles',
                r'/Filespec', r'/F\s*\(', r'/UF\s*\(',
            ],
            'severity': 'HIGH',
            'description': 'PDF contains embedded files. May contain hidden executables.',
            'recommendation': 'Extract and scan embedded files separately.',
        },
        'Form Actions': {
            'patterns': [
                r'/AcroForm', r'/XFA\b', r'/SubmitForm', r'/ImportData',
            ],
            'severity': 'MEDIUM',
            'description': 'PDF contains interactive forms. May submit data to external servers.',
            'recommendation': 'Review form actions and submit targets.',
        },
        'External References': {
            'patterns': [
                r'/URI\s*\(', r'/URL\s*\(',
                r'/S\s*/URI', r'/S\s*/GoToR',
            ],
            'severity': 'MEDIUM',
            'description': 'PDF references external URLs. May phone home or redirect.',
            'recommendation': 'Review all external URLs for legitimacy.',
        },
        'Obfuscation Indicators': {
            'patterns': [
                r'/Filter\s*/ASCIIHexDecode', r'/Filter\s*/ASCII85Decode',
                r'/Filter\s*/LZWDecode', r'/Filter\s*/RunLengthDecode',
                r'/Crypt\b',
            ],
            'severity': 'MEDIUM',
            'description': 'PDF uses encoding filters that may hide content.',
            'recommendation': 'Decode and inspect filtered streams.',
        },
    }

    def analyze(self, file_path: str) -> dict:
        """Full PDF analysis pipeline"""
        all_findings = {}

        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
        except Exception as e:
            return self._error_result(f'Cannot read file: {e}')

        # Validate PDF
        if not raw_data[:5] == b'%PDF-':
            return self._error_result('Not a valid PDF file')

        try:
            text = raw_data.decode('latin-1', errors='replace')
        except Exception:
            text = ''

        # ── PDF Structure ─────────────────────────────────────────
        try:
            structure = self._analyze_structure(text, raw_data)
            all_findings['PDF Structure'] = structure
        except Exception as e:
            print(f'[!] PDF structure error: {e}')

        # ── Threat keyword scanning ───────────────────────────────
        try:
            threat_findings = self._scan_threats(text)
            if threat_findings['total_found'] > 0:
                all_findings['PDF Threats'] = threat_findings
        except Exception as e:
            print(f'[!] PDF threat scan error: {e}')

        # ── Embedded executable detection ─────────────────────────
        try:
            exe_findings = self._detect_embedded_executables(raw_data)
            if exe_findings['total_found'] > 0:
                all_findings['Embedded Executables'] = exe_findings
        except Exception as e:
            print(f'[!] Embedded exe detection error: {e}')

        # ── URL extraction ────────────────────────────────────────
        try:
            url_findings = self._extract_urls(text)
            if url_findings['total_found'] > 0:
                all_findings['Embedded URLs'] = url_findings
        except Exception as e:
            print(f'[!] URL extraction error: {e}')

        # ── Stream entropy analysis ───────────────────────────────
        try:
            entropy_findings = self._analyze_stream_entropy(raw_data)
            if entropy_findings['total_found'] > 0:
                all_findings['Stream Entropy'] = entropy_findings
        except Exception as e:
            print(f'[!] Stream entropy error: {e}')

        # ── Extract printable strings + run unified rules ─────────
        printable_text = self._extract_printable_strings(raw_data)
        if printable_text:
            rule_findings = UnifiedRuleEngine.scan(
                printable_text, 'PDF', 'document content'
            )
            all_findings.update(rule_findings)

        return all_findings

    def _analyze_structure(self, text: str, raw_data: bytes) -> dict:
        """Analyze PDF structure"""
        findings = []

        # PDF version
        version_match = re.search(r'%PDF-(\d+\.\d+)', text[:20])
        version = version_match.group(1) if version_match else 'unknown'

        # Count objects
        obj_count = len(re.findall(r'\d+\s+\d+\s+obj', text))
        stream_count = len(re.findall(r'\bstream\b', text))
        page_count = len(re.findall(r'/Type\s*/Page\b', text))

        # Incremental updates (suspicious for tampering)
        xref_count = len(re.findall(r'\bxref\b', text))

        findings.append({
            'type': 'PDF Info',
            'severity': 'LOW',
            'value': f'PDF {version}, {obj_count} objects, {page_count} pages, {stream_count} streams',
            'source': 'PDF',
            'description': f'PDF version {version} with {obj_count} objects, {page_count} page(s), {stream_count} stream(s).',
            'recommendation': 'Review PDF structure for anomalies.',
        })

        if xref_count > 1:
            findings.append({
                'type': 'Incremental Updates',
                'severity': 'MEDIUM',
                'value': f'{xref_count} cross-reference tables',
                'source': 'PDF',
                'description': f'PDF has {xref_count} xref tables indicating incremental updates. May indicate tampering.',
                'recommendation': 'Verify PDF integrity. Multiple updates may hide modifications.',
            })

        # Check for encryption
        if '/Encrypt' in text:
            findings.append({
                'type': 'Encrypted PDF',
                'severity': 'MEDIUM',
                'value': 'PDF uses encryption',
                'source': 'PDF',
                'description': 'PDF has encryption enabled. Content analysis may be limited.',
                'recommendation': 'Decrypt PDF for full analysis.',
            })

        return {
            'category': 'PDF Structure',
            'total_found': len(findings),
            'findings': findings,
            'severity': 'LOW',
            'description': f'PDF {version}: {obj_count} objects, {page_count} pages.',
        }

    def _scan_threats(self, text: str) -> dict:
        """Scan for PDF-specific threat keywords"""
        findings = []
        seen = set()

        for threat_name, config in self.PDF_THREATS.items():
            for pattern in config['patterns']:
                matches = re.findall(pattern, text)
                for match in matches:
                    if threat_name not in seen:
                        seen.add(threat_name)
                        findings.append({
                            'type': threat_name,
                            'severity': config['severity'],
                            'value': match.strip(),
                            'source': 'PDF',
                            'description': config['description'],
                            'recommendation': config['recommendation'],
                        })

        severities = [f['severity'] for f in findings]
        overall = 'SAFE'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'PDF Threats',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'PDF threat analysis: {len(findings)} threat indicator(s) found.',
        }

    def _detect_embedded_executables(self, data: bytes) -> dict:
        """Detect embedded executable content in PDF"""
        findings = []

        # Look for PE (MZ) header embedded
        mz_positions = [m.start() for m in re.finditer(b'MZ', data)]
        for pos in mz_positions[:5]:
            # Verify it's a real PE header (check for PE signature at offset)
            if pos > 0 and pos + 64 < len(data):
                try:
                    pe_offset_bytes = data[pos + 60:pos + 64]
                    if len(pe_offset_bytes) == 4:
                        import struct
                        pe_offset = struct.unpack('<I', pe_offset_bytes)[0]
                        if 0 < pe_offset < 1024 and pos + pe_offset + 4 <= len(data):
                            if data[pos + pe_offset:pos + pe_offset + 2] == b'PE':
                                findings.append({
                                    'type': 'Embedded Windows Executable',
                                    'severity': 'CRITICAL',
                                    'value': f'PE/EXE embedded at offset {pos}',
                                    'source': 'PDF',
                                    'description': 'Windows executable (EXE/DLL) embedded inside PDF. Critical malware indicator.',
                                    'recommendation': 'This PDF is likely malicious. Quarantine immediately and scan with antivirus.',
                                })
                except Exception:
                    pass

        # Look for ELF header
        elf_positions = [m.start() for m in re.finditer(b'\x7fELF', data)]
        if elf_positions:
            for pos in elf_positions[:3]:
                if pos > 0:
                    findings.append({
                        'type': 'Embedded Linux Binary',
                        'severity': 'CRITICAL',
                        'value': f'ELF binary embedded at offset {pos}',
                        'source': 'PDF',
                        'description': 'Linux/Unix binary embedded inside PDF. Malware indicator.',
                        'recommendation': 'This PDF is likely malicious. Quarantine and scan.',
                    })

        # Look for Mach-O headers
        macho_signatures = [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']
        for sig in macho_signatures:
            positions = [m.start() for m in re.finditer(re.escape(sig), data)]
            for pos in positions[:2]:
                if pos > 0:
                    findings.append({
                        'type': 'Embedded macOS Binary',
                        'severity': 'CRITICAL',
                        'value': f'Mach-O binary embedded at offset {pos}',
                        'source': 'PDF',
                        'description': 'macOS/iOS binary embedded inside PDF. Malware indicator.',
                        'recommendation': 'This PDF is likely malicious. Quarantine and scan.',
                    })

        severities = [f['severity'] for f in findings]
        overall = 'SAFE'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'Embedded Executables',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Embedded executable detection: {len(findings)} executable(s) found.',
        }

    def _extract_urls(self, text: str) -> dict:
        """Extract and classify URLs from PDF"""
        findings = []
        seen = set()

        url_pattern = r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
        urls = re.findall(url_pattern, text)

        for url in urls:
            if url in seen or len(url) < 10:
                continue
            seen.add(url)

            severity = 'LOW'
            desc = 'External URL found in PDF.'

            if url.startswith('http://'):
                severity = 'HIGH'
                desc = 'Insecure HTTP URL in PDF. Data could be intercepted.'

            # Check for IP-based URLs
            if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
                severity = 'HIGH'
                desc = 'IP-based URL. May indicate C2 server or phishing.'

            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.work']
            if any(url.rstrip('/').endswith(tld) for tld in suspicious_tlds):
                severity = 'HIGH'
                desc = 'URL uses a TLD commonly associated with malicious activity.'

            # Check for URL shorteners
            shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd']
            if any(s in url.lower() for s in shorteners):
                severity = 'MEDIUM'
                desc = 'Shortened URL. Destination is hidden.'

            findings.append({
                'type': 'Embedded URL',
                'severity': severity,
                'value': url[:200],
                'source': 'PDF',
                'description': desc,
                'recommendation': 'Verify URL legitimacy before accessing.',
            })

        # Limit
        findings = findings[:30]

        severities = [f['severity'] for f in findings]
        overall = 'SAFE'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'Embedded URLs',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'URL extraction: {len(findings)} URL(s) found in PDF.',
        }

    def _analyze_stream_entropy(self, data: bytes) -> dict:
        """Analyze PDF streams for high entropy indicating obfuscation"""
        findings = []

        # Find stream boundaries
        stream_starts = [m.start() for m in re.finditer(b'stream\r?\n', data)]
        stream_ends = [m.start() for m in re.finditer(b'\r?\nendstream', data)]

        high_entropy_count = 0
        for i, start in enumerate(stream_starts[:50]):
            # Find matching endstream
            matching_ends = [e for e in stream_ends if e > start]
            if not matching_ends:
                continue
            end = matching_ends[0]

            stream_data = data[start + 7:end]  # Skip "stream\n"
            if len(stream_data) < 100:
                continue

            entropy = self._shannon_entropy(stream_data)
            if entropy >= 7.5:
                high_entropy_count += 1

        if high_entropy_count > 0:
            severity = 'HIGH' if high_entropy_count >= 3 else 'MEDIUM'
            findings.append({
                'type': 'High Entropy Streams',
                'severity': severity,
                'value': f'{high_entropy_count} high-entropy stream(s) detected',
                'source': 'PDF',
                'description': f'{high_entropy_count} PDF stream(s) with very high entropy (>7.5). Indicates obfuscation or hidden payload.',
                'recommendation': 'Decode and inspect high-entropy streams for hidden content.',
            })

        severities = [f['severity'] for f in findings]
        overall = 'SAFE'
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if s in severities:
                overall = s
                break

        return {
            'category': 'Stream Entropy',
            'total_found': len(findings),
            'findings': findings,
            'severity': overall,
            'description': f'Stream entropy analysis: {high_entropy_count} anomalous stream(s).',
        }

    def _extract_printable_strings(self, data: bytes, min_length: int = 6) -> str:
        """Extract printable strings from PDF binary data + decompressed streams + CMap text"""
        all_text_parts = []

        # 1. Extract from raw bytes (catches uncompressed content)
        all_text_parts.append(self._strings_from_bytes(data, min_length))

        # 2. Decompress FlateDecode streams and extract from those too
        decompressed_streams = []
        try:
            import zlib
            stream_starts = [m.end() for m in re.finditer(b'stream\r?\n', data)]
            stream_ends = [m.start() for m in re.finditer(b'\r?\nendstream', data)]

            for start in stream_starts:
                matching_ends = [e for e in stream_ends if e > start]
                if not matching_ends:
                    continue
                end = matching_ends[0]
                stream_data = data[start:end]

                if len(stream_data) < 10:
                    continue

                decompressed = None
                try:
                    decompressed = zlib.decompress(stream_data)
                except Exception:
                    try:
                        decompressed = zlib.decompress(stream_data, -15)
                    except Exception:
                        pass

                if decompressed:
                    text = self._strings_from_bytes(decompressed, min_length)
                    all_text_parts.append(text)
                    try:
                        decompressed_streams.append(decompressed.decode('latin-1', errors='replace'))
                    except Exception:
                        pass
        except Exception:
            pass

        # 3. Decode CIDFont hex-encoded text via CMap
        #    Modern PDFs store text as hex glyph IDs (e.g. <01020304>)
        #    with a CMap that maps glyph IDs to Unicode characters.
        #    Without decoding, API keys like "AIzaSy..." are invisible.
        try:
            cmap_decoded = self._decode_cmap_text(decompressed_streams)
            if cmap_decoded:
                all_text_parts.append(cmap_decoded)
        except Exception:
            pass

        # 4. Extract parenthesized strings — PDF string objects like (text here)
        try:
            paren_strings = re.findall(rb'\(([^)]{6,})\)', data)
            for ps in paren_strings:
                try:
                    decoded = ps.decode('latin-1', errors='replace')
                    # Only include if mostly printable ASCII
                    printable_count = sum(1 for c in decoded if 32 <= ord(c) <= 126)
                    if printable_count > len(decoded) * 0.6:
                        all_text_parts.append(decoded)
                except Exception:
                    pass
        except Exception:
            pass

        return '\n'.join(part for part in all_text_parts if part)

    def _decode_cmap_text(self, decompressed_streams: list) -> str:
        """
        Decode CIDFont hex-encoded text using CMap character mappings.

        CMap streams contain mappings like:
            <01> <0041>   (glyph 0x01 -> Unicode 'A')
            <02> <0049>   (glyph 0x02 -> Unicode 'I')

        Content streams contain hex text like:
            <0102030405> Tj    -> "AIzaS..."

        This method parses the CMap, then decodes all hex strings
        in content streams to reconstruct the actual readable text.
        """
        if not decompressed_streams:
            return ''

        # Step 1: Find and parse CMap stream
        cmap_mappings = {}
        for stream_text in decompressed_streams:
            if 'beginbfchar' not in stream_text and 'beginbfrange' not in stream_text:
                continue

            # Parse bfchar: <src> <unicode_dst>
            chars = re.findall(r'<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>', stream_text)
            for src_hex, dst_hex in chars:
                try:
                    src_int = int(src_hex, 16)
                    dst_char = chr(int(dst_hex, 16))
                    cmap_mappings[src_int] = dst_char
                except (ValueError, OverflowError):
                    pass

        if not cmap_mappings:
            return ''

        # Step 2: Find content streams and decode hex strings
        decoded_parts = []
        for stream_text in decompressed_streams:
            # Content streams contain operators like Tj, TJ, BDC, etc.
            if 'Tj' not in stream_text and 'TJ' not in stream_text:
                continue

            # Find hex strings: <hexdigits>
            hex_strings = re.findall(r'<([0-9A-Fa-f]{2,})>', stream_text)
            for hex_str in hex_strings:
                decoded_chars = []
                for i in range(0, len(hex_str), 2):
                    if i + 2 <= len(hex_str):
                        byte_val = int(hex_str[i:i+2], 16)
                        if byte_val in cmap_mappings:
                            decoded_chars.append(cmap_mappings[byte_val])
                if decoded_chars:
                    decoded_parts.append(''.join(decoded_chars))

        return ' '.join(decoded_parts)

    @staticmethod
    def _strings_from_bytes(data: bytes, min_length: int = 6) -> str:
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
        return '\n'.join(strings)

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
            'PDF Analysis Error': {
                'category': 'PDF Analysis Error',
                'total_found': 1,
                'findings': [{
                    'type': 'Analysis Error',
                    'severity': 'MEDIUM',
                    'value': msg,
                    'source': 'PDF',
                    'description': msg,
                    'recommendation': 'Ensure the file is a valid PDF.',
                }],
                'severity': 'MEDIUM',
                'description': msg,
            }
        }
