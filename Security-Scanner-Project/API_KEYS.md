# Security Scanner API Configuration

## API Keys for Enhanced URL Scanning

To enable advanced URL scanning features, you need to configure API keys:

### 1. Google Safe Browsing API

**Get your API key:**
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable "Safe Browsing API"
4. Go to "Credentials" → "Create Credentials" → "API Key"
5. Copy your API key

**Set environment variable:**
```bash
# Windows (PowerShell)
$env:GOOGLE_SAFE_BROWSING_API_KEY="YOUR_API_KEY_HERE"

# Windows (CMD)
set GOOGLE_SAFE_BROWSING_API_KEY=YOUR_API_KEY_HERE

# Linux/Mac
export GOOGLE_SAFE_BROWSING_API_KEY="YOUR_API_KEY_HERE"
```

### 2. URLScan.io API

**Get your API key:**
1. Sign up at [URLScan.io](https://urlscan.io/user/signup)
2. Go to Settings → API
3. Copy your API key

**Set environment variable:**
```bash
# Windows (PowerShell)
$env:URLSCAN_API_KEY="YOUR_API_KEY_HERE"

# Windows (CMD)
set URLSCAN_API_KEY=YOUR_API_KEY_HERE

# Linux/Mac
export URLSCAN_API_KEY="YOUR_API_KEY_HERE"
```

## Features Without API Keys

The scanner will still work without API keys, but will skip external checks:
- ✅ SSL Certificate validation (always works)
- ✅ Protocol analysis (HTTP vs HTTPS)
- ✅ TLD checking
- ✅ IP address detection
- ❌ Google Safe Browsing (requires key)
- ❌ URLScan.io deep analysis (requires key)

## Alternative: Pass API Keys in Request

You can also send API keys with each request:

```javascript
fetch('http://localhost:5000/api/scan/url', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
        url: 'https://example.com',
        google_api_key: 'YOUR_GOOGLE_KEY',  // Optional
        urlscan_api_key: 'YOUR_URLSCAN_KEY'  // Optional
    })
})
```

## Security Note

⚠️ **Never commit API keys to version control!**
- Use environment variables
- Add `.env` to `.gitignore`
- For production, use secret management (AWS Secrets Manager, Azure Key Vault, etc.)
