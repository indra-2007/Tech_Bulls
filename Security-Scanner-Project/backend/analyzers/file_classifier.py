"""File Classifier
Detects file type using magic bytes (priority) and structure validation.
Routes files to the appropriate analyzer module.
"""

import os
import zipfile
import struct
from typing import Tuple, Optional


class FileClassifier:
    """Classifies files by magic bytes + internal structure validation"""

    # ── Magic Byte Signatures ─────────────────────────────────────────
    MAGIC_SIGNATURES = {
        b'PK\x03\x04': 'ZIP',       # ZIP-based: APK, JAR, IPA, DOCX, etc.
        b'MZ':         'PE',         # Windows PE: EXE, DLL
        b'\x7fELF':    'ELF',        # Linux ELF: SO, executables
        b'%PDF':       'PDF',        # PDF documents
    }

    @classmethod
    def classify(cls, file_path: str) -> Tuple[str, str]:
        """
        Classify a file by magic bytes + structure validation.

        Returns:
            Tuple of (file_type, description)
            file_type is one of: APK, JAR, IPA, EXE, DLL, SO, PDF, JS, HTML, CSS, JSON, UNKNOWN
        """
        if not os.path.exists(file_path):
            return 'UNKNOWN', 'File does not exist'

        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return 'UNKNOWN', 'Empty file'

        filename = os.path.basename(file_path).lower()
        extension = filename.rsplit('.', 1)[-1] if '.' in filename else ''

        # ── Step 1: Magic bytes (priority) ────────────────────────
        magic_type = cls._detect_magic(file_path)

        # ── Step 2: Structure validation ──────────────────────────
        if magic_type == 'ZIP':
            return cls._classify_zip(file_path, extension)
        elif magic_type == 'PE':
            return cls._classify_pe(file_path, extension)
        elif magic_type == 'ELF':
            return 'SO', 'ELF Shared Object / Linux Binary'
        elif magic_type == 'PDF':
            return 'PDF', 'PDF Document'

        # ── Step 3: Text-based files (no magic header) ────────────
        if cls._is_text_file(file_path):
            if extension == 'js':
                return 'JS', 'JavaScript File'
            elif extension in ('html', 'htm'):
                return 'HTML', 'HTML File'
            elif extension == 'css':
                return 'CSS', 'CSS Stylesheet'
            elif extension == 'json':
                return 'JSON', 'JSON File'
            elif extension in ('xml', 'svg'):
                return 'XML', 'XML File'
            elif extension in ('py', 'rb', 'php', 'java', 'c', 'cpp', 'h', 'go', 'rs'):
                return 'SOURCE', f'Source Code ({extension.upper()})'
            else:
                return 'TEXT', 'Plain Text File'

        # ── Step 4: Extension fallback ────────────────────────────
        if extension == 'apk':
            return 'APK', 'Android APK (unverified structure)'
        elif extension == 'jar':
            return 'JAR', 'Java Archive (unverified structure)'
        elif extension == 'ipa':
            return 'IPA', 'iOS App (unverified structure)'
        elif extension in ('exe', 'dll', 'so', 'pdf', 'js'):
            return extension.upper(), f'{extension.upper()} file (unverified)'

        return 'UNKNOWN', f'Unknown file type (extension: .{extension})'

    @classmethod
    def _detect_magic(cls, file_path: str) -> Optional[str]:
        """Read first 4 bytes and match against known magic signatures"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)

            for magic, file_type in cls.MAGIC_SIGNATURES.items():
                if header[:len(magic)] == magic:
                    return file_type
        except Exception:
            pass
        return None

    @classmethod
    def _classify_zip(cls, file_path: str, extension: str) -> Tuple[str, str]:
        """Classify ZIP-based formats by internal structure"""
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                names = zf.namelist()

                # APK: Must contain AndroidManifest.xml
                if 'AndroidManifest.xml' in names:
                    dex_files = [n for n in names if n.endswith('.dex')]
                    if dex_files:
                        return 'APK', f'Android APK ({len(dex_files)} DEX file(s))'
                    return 'APK', 'Android APK (no DEX — resource-only?)'

                # IPA: Must contain Payload/*.app/
                payload_apps = [n for n in names if n.startswith('Payload/') and '.app/' in n]
                if payload_apps:
                    return 'IPA', 'iOS Application Package'

                # JAR: Must contain META-INF/ or .class files
                has_meta_inf = any(n.startswith('META-INF/') for n in names)
                has_class = any(n.endswith('.class') for n in names)
                if has_meta_inf or has_class:
                    return 'JAR', 'Java Archive (JAR)'

                # Fallback by extension
                if extension == 'apk':
                    return 'APK', 'Android APK (minimal structure)'
                elif extension == 'ipa':
                    return 'IPA', 'iOS App (minimal structure)'
                elif extension == 'jar':
                    return 'JAR', 'Java Archive (minimal structure)'

                return 'ZIP', 'ZIP Archive (unknown format)'

        except zipfile.BadZipFile:
            # Not a valid ZIP despite PK header
            if extension == 'apk':
                return 'APK', 'Corrupted APK (bad ZIP)'
            return 'UNKNOWN', 'Corrupted ZIP archive'
        except Exception:
            return 'ZIP', 'ZIP Archive'

    @classmethod
    def _classify_pe(cls, file_path: str, extension: str) -> Tuple[str, str]:
        """Classify PE files (EXE vs DLL) by PE header characteristics"""
        try:
            import pefile
            pe = pefile.PE(file_path, fast_load=True)

            # Check DLL characteristic flag
            is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)

            if is_dll:
                return 'DLL', 'Windows Dynamic Link Library (DLL)'
            else:
                return 'EXE', 'Windows Executable (EXE)'

        except Exception:
            # PE parsing failed, fallback to extension
            if extension == 'dll':
                return 'DLL', 'Windows DLL (PE parse failed)'
            return 'EXE', 'Windows EXE (PE parse failed)'

    @classmethod
    def _is_text_file(cls, file_path: str, check_size: int = 8192) -> bool:
        """Check if file is a valid UTF-8 text file"""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(check_size)

            # Try UTF-8 decode
            try:
                chunk.decode('utf-8')
            except UnicodeDecodeError:
                return False

            # Check for binary null bytes (text files shouldn't have them)
            if b'\x00' in chunk:
                return False

            # Check if mostly printable
            printable_count = sum(1 for b in chunk if 32 <= b <= 126 or b in (9, 10, 13))
            ratio = printable_count / len(chunk) if chunk else 0
            return ratio > 0.85

        except Exception:
            return False

    @classmethod
    def get_analyzer_route(cls, file_type: str) -> str:
        """Map file type to analyzer pipeline name"""
        routes = {
            'APK': 'apk_pipeline',
            'EXE': 'pe_pipeline',
            'DLL': 'pe_pipeline',
            'SO':  'elf_pipeline',
            'JAR': 'jar_pipeline',
            'IPA': 'ipa_pipeline',
            'PDF': 'pdf_pipeline',
            'JS':  'js_pipeline',
            'HTML': 'js_pipeline',     # Same text-based analysis
            'CSS':  'js_pipeline',
            'JSON': 'js_pipeline',
            'XML':  'js_pipeline',
            'SOURCE': 'js_pipeline',
            'TEXT': 'js_pipeline',
        }
        return routes.get(file_type, 'generic_pipeline')
