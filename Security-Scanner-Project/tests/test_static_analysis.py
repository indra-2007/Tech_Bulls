import sys
import os

# Add backend directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from analyzers.static_files import StaticFileAnalyzer

def test_static_analyzer():
    analyzer = StaticFileAnalyzer()
    
    # Test JS content
    js_content = """
    function malicious() {
        var x = eval("2 + 2");
        document.write("Hello");
        var apiKey = "AIzaSyD-1234567890abcdef1234567890";
    }
    """
    
    print("Testing JS Analysis...")
    results = analyzer.analyze(js_content, "test.js")
    
    findings = {f['type'] for f in results['findings']}
    print(f"Findings: {findings}")
    
    assert 'Dangerous Eval' in findings, "Failed to detect eval()"
    assert 'Document Write' in findings, "Failed to detect document.write()"
    assert 'Hardcoded Secret' in findings, "Failed to detect hardcoded secret"
    
    print("JS Analysis Test Passed!")
    
    # Test HTML content
    html_content = """
    <html>
        <body>
            <script>alert('xss')</script>
            <iframe src="http://example.com"></iframe>
        </body>
    </html>
    """
    
    print("\nTesting HTML Analysis...")
    results = analyzer.analyze(html_content, "test.html")
    
    findings = {f['type'] for f in results['findings']}
    print(f"Findings: {findings}")
    
    assert 'Inline Script' in findings, "Failed to detect inline script"
    assert 'Insecure HTTP' in findings, "Failed to detect insecure HTTP"
    assert 'Iframe Usage' in findings, "Failed to detect iframe"
    
    print("HTML Analysis Test Passed!")

if __name__ == "__main__":
    try:
        test_static_analyzer()
        print("\nAll tests passed successfully!")
    except AssertionError as e:
        print(f"\nTest Failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        sys.exit(1)
