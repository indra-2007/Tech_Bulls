"""File Handler Utilities
Handles file operations, string extraction, and hash generation
"""

import hashlib
import os
import tempfile
from typing import Tuple, Optional

class FileHandler:
    """Utility class for file processing operations"""
    
    @staticmethod
    def extract_strings(file_path: str, min_length: int = 4) -> str:
        """
        Extract printable strings from binary files
        
        Args:
            file_path: Path to file
            min_length: Minimum string length to extract
            
        Returns:
            Extracted strings as a single text block
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Extract ASCII strings
            strings = []
            current_string = []
            
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string.append(chr(byte))
                else:
                    if len(current_string) >= min_length:
                        strings.append(''.join(current_string))
                    current_string = []
            
            # Don't forget the last string
            if len(current_string) >= min_length:
                strings.append(''.join(current_string))
            
            return '\n'.join(strings)
            
        except Exception as e:
            return f"Error extracting strings: {str(e)}"
    
    @staticmethod
    def calculate_hash(file_path: str) -> dict:
        """
        Calculate file hashes
        
        Args:
            file_path: Path to file
            
        Returns:
            dict with hash values
        """
        try:
            sha256_hash = hashlib.sha256()
            md5_hash = hashlib.md5()
            
            with open(file_path, 'rb') as f:
                # Read in chunks for large files
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
            
            return {
                'sha256': sha256_hash.hexdigest(),
                'md5': md5_hash.hexdigest()
            }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_file_info(file_path: str) -> dict:
        """
        Get file metadata
        
        Args:
            file_path: Path to file
            
        Returns:
            dict with file information
        """
        try:
            stat_info = os.stat(file_path)
            return {
                'size': stat_info.st_size,
                'size_human': FileHandler._human_readable_size(stat_info.st_size),
                'modified': stat_info.st_mtime,
            }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def _human_readable_size(size_bytes: int) -> str:
        """Convert bytes to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"
    
    @staticmethod
    def calculate_entropy(file_path: str) -> float:
        """
        Calculate file entropy (randomness measure)
        High entropy may indicate encryption/compression
        
        Args:
            file_path: Path to file
            
        Returns:
            Entropy value (0-8, where 8 is maximum randomness)
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024 * 1024)  # Read first 1MB
            
            if not data:
                return 0.0
            
            # Count byte frequencies
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            
            for count in byte_counts:
                if count == 0:
                    continue
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
            
            return round(entropy, 2)
            
        except Exception:
            return 0.0
    
    @staticmethod
    def detect_file_type(file_path: str) -> Tuple[str, str]:
        """
        Detect file type from magic bytes
        
        Args:
            file_path: Path to file
            
        Returns:
            Tuple of (file_type, description)
        """
        try:
            with open(file_path, 'rb') as f:
                header = f.read(20)
            
            # Check magic bytes
            if header[:2] == b'PK':
                if header[2:4] == b'\x03\x04':
                    return ('ZIP/APK', 'ZIP archive or Android APK')
            elif header[:2] == b'MZ':
                return ('EXE/DLL', 'Windows executable or DLL')
            elif header[:4] == b'\x7fELF':
                return ('ELF', 'Linux executable')
            elif header[:4] == b'\xca\xfe\xba\xbe':
                return ('Mach-O', 'macOS executable')
            elif header[:5] == b'%PDF-':
                return ('PDF', 'PDF document')
            
            # Try text detection
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    f.read(1024)
                return ('TEXT', 'Text file')
            except:
                return ('BINARY', 'Unknown binary file')
                
        except Exception as e:
            return ('UNKNOWN', f'Error: {str(e)}')
