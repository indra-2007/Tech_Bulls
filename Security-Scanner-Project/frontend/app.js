// Binary Transparency & Security Analyzer - Core Engine

class SecurityAnalyzer {
    constructor() {
        this.selectedFile = null;
        this.isScanning = false;
        this.apiBaseUrl = 'http://localhost:5001/api';
        this.init();
    }

    init() {
        this.initMatrix();
        this.initEventListeners();
        this.initTabs();
        this.initScrollObserver();
    }

    // --- Scroll Animations ---
    initScrollObserver() {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('active');
                }
            });
        }, { threshold: 0.1 });

        document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
    }

    // --- Matrix Animation ---
    initMatrix() {
        const canvas = document.getElementById('matrix-canvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');

        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;

        const chars = "01010101ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        const fontSize = 14;
        const columns = canvas.width / fontSize;
        const drops = [];

        for (let x = 0; x < columns; x++) {
            drops[x] = 1;
        }

        const draw = () => {
            ctx.fillStyle = 'rgba(15, 15, 15, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            ctx.fillStyle = '#00ff88';
            ctx.font = fontSize + 'px monospace';

            for (let i = 0; i < drops.length; i++) {
                const text = chars.charAt(Math.floor(Math.random() * chars.length));
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);

                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        };

        setInterval(draw, 50);

        window.addEventListener('resize', () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        });
    }

    // --- UI Interactions ---
    initEventListeners() {
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');
        const scanBtn = document.getElementById('scanButton');
        const removeBtn = document.getElementById('removeFile');

        if (dropZone) {
            dropZone.addEventListener('click', () => fileInput.click());
            dropZone.addEventListener('dragover', (e) => {
                e.preventDefault();
                dropZone.classList.add('active');
            });
            dropZone.addEventListener('dragleave', () => dropZone.classList.remove('active'));
            dropZone.addEventListener('drop', (e) => {
                e.preventDefault();
                dropZone.classList.remove('active');
                if (e.dataTransfer.files.length > 0) this.handleFileSelect(e.dataTransfer.files[0]);
            });
        }

        if (fileInput) {
            fileInput.addEventListener('change', (e) => {
                if (e.target.files.length > 0) this.handleFileSelect(e.target.files[0]);
            });
        }

        if (scanBtn) {
            scanBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.executeScan();
            });
        }

        if (removeBtn) {
            removeBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.resetUpload();
            });
        }
    }

    handleFileSelect(file) {
        const allowed = ['apk', 'exe', 'pdf', 'jar', 'dll', 'so', 'ipa', 'js'];
        const ext = file.name.split('.').pop().toLowerCase();

        if (!allowed.includes(ext)) {
            alert(`File type .${ext} is not supported. Please use: ${allowed.join(', ')}`);
            return;
        }

        this.selectedFile = file;
        document.querySelector('.upload-content').classList.add('hidden');
        document.getElementById('filePreview').classList.remove('hidden');
        document.getElementById('fileName').textContent = file.name;
        document.getElementById('fileSize').textContent = this.formatSize(file.size);
    }

    formatSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    resetUpload() {
        this.selectedFile = null;
        document.querySelector('.upload-content').classList.remove('hidden');
        document.getElementById('filePreview').classList.add('hidden');
        document.getElementById('fileInput').value = '';
    }

    // --- Scanning Engine ---
    async executeScan() {
        if (!this.selectedFile || this.isScanning) return;
        this.isScanning = true;

        // Hide upload preview, show console
        document.getElementById('filePreview').classList.add('hidden');
        const consoleEl = document.getElementById('consoleContainer');
        consoleEl.style.display = 'block';

        await this.logToConsole("Initializing Binary Analyzer...");
        await this.logToConsole(`Target: ${this.selectedFile.name}`);
        await this.logToConsole("Extracting headers and strings...");
        await this.delay(800);
        await this.logToConsole("Identifying entry points and syscalls...");
        await this.delay(500);
        await this.logToConsole("Running heuristic rule engine [YARA v4.2]...");

        try {
            const formData = new FormData();
            formData.append('file', this.selectedFile);

            const response = await fetch(`${this.apiBaseUrl}/scan/file`, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Scan failed');
            }

            const data = await response.json();

            await this.logToConsole("Static analysis complete. Compiling findings...");
            await this.delay(600);
            await this.logToConsole("Generating security report...");
            await this.delay(400);

            this.showResults(data);

        } catch (error) {
            await this.logToConsole(`ERROR: ${error.message}`, 'critical');
            alert(`Scan Failed: ${error.message}`);
            this.resetUpload();
            this.isScanning = false;
        }
    }

    async logToConsole(message, type = '') {
        const lines = document.getElementById('consoleLines');
        const line = document.createElement('div');
        line.className = `console-line ${type}`;
        lines.appendChild(line);

        // Typing effect
        for (let i = 0; i < message.length; i++) {
            line.textContent += message[i];
            await this.delay(20);
        }

        // Scroll to bottom
        const container = document.getElementById('consoleContainer');
        container.scrollTop = container.scrollHeight;
    }

    delay(ms) { return new Promise(res => setTimeout(res, ms)); }

    // --- Results Display ---
    showResults(data) {
        document.getElementById('consoleContainer').style.display = 'none';
        document.getElementById('resultsSection').style.display = 'block';
        document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth' });

        this.populateRiskBar(data);
        this.populateCategoryAccordion(data);
        this.isScanning = false;
    }

    populateRiskBar(data) {
        const score = data.security_score ?? 0;
        const riskLevel = data.risk_level || 'SAFE';
        const summary = data.summary || {};

        // Score circle — color based on score (0 = worst/red, 100 = best/green)
        const circleEl = document.getElementById('scoreCircleMini');
        const scoreVal = document.getElementById('scoreValueMini');
        const labelEl = document.getElementById('riskLabelText');

        let color, labelText;
        if (score <= 20) {
            color = '#ff3e3e'; labelText = 'CRITICAL RISK';
        } else if (score <= 40) {
            color = '#ff6b3e'; labelText = 'HIGH RISK';
        } else if (score <= 60) {
            color = '#ffb800'; labelText = 'MEDIUM RISK';
        } else if (score <= 80) {
            color = '#a8ff3e'; labelText = 'LOW RISK';
        } else {
            color = '#00ff88'; labelText = 'SECURE';
        }

        // Override label with backend risk_level for consistency
        const riskLabels = {
            'CRITICAL': 'CRITICAL RISK', 'HIGH': 'HIGH RISK',
            'MEDIUM': 'MEDIUM RISK', 'LOW': 'LOW RISK', 'SAFE': 'SYSTEM SECURE'
        };
        labelText = riskLabels[riskLevel] || labelText;

        circleEl.style.color = color;
        circleEl.style.borderColor = color;
        circleEl.style.boxShadow = `0 0 20px ${color}40`;
        labelEl.style.color = color;
        labelEl.textContent = labelText;

        // Animated counter
        let count = 0;
        const interval = setInterval(() => {
            if (count >= score) {
                count = score;
                clearInterval(interval);
            }
            scoreVal.textContent = count;
            count++;
        }, 15);

        // Total issues
        const totalIssues = summary.total_issues || 0;
        const totalEl = document.getElementById('totalIssuesCount');
        let issueCount = 0;
        const issueInterval = setInterval(() => {
            if (issueCount >= totalIssues) {
                issueCount = totalIssues;
                clearInterval(issueInterval);
            }
            totalEl.textContent = issueCount;
            issueCount++;
        }, 15);

        // Severity pills
        const pillsEl = document.getElementById('severityPills');
        pillsEl.innerHTML = '';
        const severities = [
            { key: 'critical', label: 'CRITICAL', cls: 'pill-critical' },
            { key: 'high', label: 'HIGH', cls: 'pill-high' },
            { key: 'medium', label: 'MEDIUM', cls: 'pill-medium' },
            { key: 'low', label: 'LOW', cls: 'pill-low' },
        ];
        for (const s of severities) {
            const val = summary[s.key] || 0;
            if (val > 0) {
                const pill = document.createElement('div');
                pill.className = `severity-pill ${s.cls}`;
                pill.innerHTML = `<span class="pill-count">${val}</span> ${s.label}`;
                pillsEl.appendChild(pill);
            }
        }
    }

    populateCategoryAccordion(data) {
        const container = document.getElementById('categoryAccordion');
        container.innerHTML = '';

        const findingsData = data.findings_by_category || data.findings || {};
        const sevOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'SAFE': 4 };

        // Build sorted category list — sort by worst severity DESC
        const categories = [];
        for (const [catName, catData] of Object.entries(findingsData)) {
            if (!catData || !catData.findings) continue;
            const findings = catData.findings || [];
            if (findings.length === 0) continue;

            // Sort findings within category by severity (CRITICAL first)
            findings.sort((a, b) => {
                return (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4);
            });

            categories.push({
                name: catName,
                severity: catData.severity || 'LOW',
                count: findings.length,
                findings: findings,
                description: catData.description || '',
            });
        }

        // Sort categories: CRITICAL first, then HIGH, etc.
        categories.sort((a, b) => {
            return (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4);
        });

        if (categories.length === 0) {
            container.innerHTML = `
                <div style="text-align:center; padding:40px; color:var(--success); font-family:var(--font-mono);">
                    <i class="fas fa-shield-alt" style="font-size:3rem; margin-bottom:15px; display:block;"></i>
                    NO THREATS DETECTED — BINARY APPEARS CLEAN
                </div>`;
            return;
        }

        for (const cat of categories) {
            const section = document.createElement('div');
            section.className = 'category-section';

            const icon = this.getCategoryIcon(cat.name);
            const sevClass = `sev-${cat.severity.toLowerCase()}`;

            // Category header
            const header = document.createElement('div');
            header.className = 'category-header';
            header.innerHTML = `
                <i class="fas fa-chevron-right category-chevron"></i>
                <span class="category-icon">${icon}</span>
                <span class="category-name">${cat.name}</span>
                <span class="category-count">${cat.count} issue${cat.count !== 1 ? 's' : ''}</span>
                <span class="severity-badge category-severity-badge ${sevClass}">${cat.severity}</span>
            `;

            // Category body with findings
            const body = document.createElement('div');
            body.className = 'category-body';
            const bodyInner = document.createElement('div');
            bodyInner.className = 'category-body-inner';

            for (const f of cat.findings) {
                const item = document.createElement('div');
                item.className = 'finding-item';

                const fSevClass = `sev-${(f.severity || 'low').toLowerCase()}`;

                let detailsHTML = '';
                if (f.description) {
                    detailsHTML += `<div class="finding-detail-row"><strong>Description:</strong> ${f.description}</div>`;
                }
                if (f.value) {
                    detailsHTML += `<div class="finding-detail-row"><strong>Value:</strong> <code>${this.escapeHtml(f.value)}</code></div>`;
                }
                if (f.context) {
                    detailsHTML += `<div class="finding-detail-row"><strong>Context:</strong> <code>${this.escapeHtml(f.context)}</code></div>`;
                }
                if (f.entropy !== undefined) {
                    detailsHTML += `<div class="finding-detail-row"><strong>Entropy:</strong> ${f.entropy} | <strong>Length:</strong> ${f.length}</div>`;
                }
                if (f.recommendation) {
                    detailsHTML += `<div class="finding-recommendation">💡 <strong>Fix:</strong> ${f.recommendation}</div>`;
                }

                item.innerHTML = `
                    <div class="finding-item-header">
                        <span class="finding-item-type">${f.type || cat.name}</span>
                        <span class="severity-badge ${fSevClass}">${f.severity || 'LOW'}</span>
                    </div>
                    <div class="finding-item-details">${detailsHTML}</div>
                `;

                // Toggle individual finding
                item.querySelector('.finding-item-header').addEventListener('click', (e) => {
                    e.stopPropagation();
                    item.classList.toggle('expanded');
                });

                bodyInner.appendChild(item);
            }

            body.appendChild(bodyInner);
            section.appendChild(header);
            section.appendChild(body);

            // Toggle category
            header.addEventListener('click', () => {
                section.classList.toggle('expanded');
            });

            container.appendChild(section);
        }
    }

    getCategoryIcon(name) {
        const icons = {
            'Secret Exposure': '🔑',
            'Hardcoded Secrets': '🔑',
            'Manifest Security': '📋',
            'Code Vulnerabilities': '⚠️',
            'Code Obfuscation': '🔒',
            'Certificate Security': '📜',
            'Permission Risk Correlation': '🛡️',
            'Component Exposure': '🔓',
            'DEX Structure': '🧬',
            'High Entropy Strings': '🎲',
            'JavaScript Security': '🌐',
            'Insecure Configuration': '⚙️',
            'Suspicious Behavior': '👁️',
            'Dangerous Capability': '💀',
            'PDF Threats': '📄',
            'PDF Structure': '📊',
            'Stream Entropy': '📈',
            'Embedded URLs': '🔗',
            'Embedded Executables': '💣',
            'File Info': 'ℹ️',
            'HTML Security': '🌐',
        };
        return icons[name] || '🔍';
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Tabs removed — single developer view with category accordion
    initTabs() { }
}

// Initialize on Load
document.addEventListener('DOMContentLoaded', () => {
    new SecurityAnalyzer();
});
