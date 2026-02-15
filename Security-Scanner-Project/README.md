Security Scanner - EXE/APK Only Edition
========================================

This is a simplified security scanner focused exclusively on Windows executables (.exe) and Android applications (.apk).

Structure:
- backend/  : Python Flask API and security analyzers
- frontend/ : HTML/CSS/JS web interface

Features:
✓ API Key Detection (25+ formats)
✓ Network Security Analysis
✓ Cloud Storage Exposure Detection
✓ Android Permissions Analysis (APK)
✓ Infrastructure Leak Detection
✓ Weak Cryptography Detection
✓ Debug Artifact Detection

How to Run:
1. Navigate to the 'backend' folder
2. Install dependencies: pip install -r requirements.txt
3. Run the server: python app.py
4. Open 'frontend/index.html' in your browser
5. Upload .exe or .apk files only

Removed Features (simplified version):
✗ URL scanning
✗ Scan history database
✗ Deep/recursive scan for archives
✗ Analysis dashboard
✗ Multi-file format support

This version is optimized for focused executable analysis only.
