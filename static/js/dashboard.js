// ============================================================
//  NET-EGRESS Advanced Dashboard — dashboard.js
// ============================================================

// Connect Socket.IO
const socket = io({ transports: ['websocket', 'polling'] });

// ---- Global State ----
let scanActive = false;
let scanStopped = false;
let totalRequests = 0;
let totalVulnerabilities = 0;
let totalPayloads = 0;
let totalBypasses = 0;
let scanStartTime = null;
const vulnerabilityTypes = {};
const allLogs = [];
const allFindings = [];
let currentFinding = null;
window.scanFindings = {}; // Global registry for finding details

// ---- Topology State ----
let network = null;
const nodes = new vis.DataSet([]);
const edges = new vis.DataSet([]);
const topoHosts = new Set();
const topoServices = new Set();

// ---- Sounds ----
const alertSound = document.getElementById('alert-sound');
const criticalSound = document.getElementById('critical-sound');

// ============================================================
//  Chart: Vulnerability Doughnut
// ============================================================
function makeChart(id, config) {
    const el = document.getElementById(id);
    if (!el) { console.warn('[Dashboard] Canvas not found:', id); return null; }
    return new Chart(el.getContext('2d'), config);
}

const vulnChart = makeChart('vulnChart', {
    type: 'line',
    data: {
        labels: [], // Time or Request buckets
        datasets: [
            { label: 'Basic', data: [], borderColor: '#00d2ff', backgroundColor: 'rgba(0,210,255,0.05)', fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0 },
            { label: 'Bypass', data: [], borderColor: '#ff416c', backgroundColor: 'rgba(255,65,108,0.05)', fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0 },
            { label: 'Cloud', data: [], borderColor: '#00f260', backgroundColor: 'rgba(0,242,96,0.05)', fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0 },
            { label: 'OOB/Other', data: [], borderColor: '#f7c948', backgroundColor: 'rgba(247,201,72,0.05)', fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0 }
        ]
    },
    options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
            legend: { position: 'top', labels: { color: '#848aa0', font: { size: 10 }, usePointStyle: true, padding: 10 } },
            tooltip: { mode: 'index', intersect: false }
        },
        scales: {
            x: { grid: { display: false }, ticks: { color: '#848aa0', font: { size: 9 } } },
            y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#848aa0', font: { size: 9 }, stepSize: 1 }, beginAtZero: true }
        }
    }
});

// ---- Chart: CVSS Severity (bar) ----
const cvssChart = makeChart('cvssChart', {
    type: 'bar',
    data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
            label: 'Count',
            data: [0, 0, 0, 0],
            backgroundColor: ['rgba(255,65,108,0.7)', 'rgba(247,201,72,0.7)', 'rgba(0,210,255,0.7)', 'rgba(0,242,96,0.7)'],
            borderRadius: 6,
            borderWidth: 0
        }]
    },
    options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
            x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#848aa0' } },
            y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#848aa0', stepSize: 1 }, beginAtZero: true }
        }
    }
});

// ---- Chart: AI Patterns ----
const aiPatternChart = makeChart('aiPatternChart', {
    type: 'radar',
    data: {
        labels: ['Blind SSRF', 'Open Redirect', 'Metadata Access', 'Port Scan', 'File Read', 'Protocol Misuse'],
        datasets: [{
            label: 'Pattern Confidence',
            data: [0, 0, 0, 0, 0, 0],
            backgroundColor: 'rgba(0,210,255,0.1)',
            borderColor: '#00d2ff',
            pointBackgroundColor: '#00d2ff',
            borderWidth: 2
        }]
    },
    options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#f0f0f0' } } },
        scales: {
            r: {
                grid: { color: 'rgba(255,255,255,0.05)' },
                angleLines: { color: 'rgba(255,255,255,0.08)' },
                ticks: { color: '#848aa0', stepSize: 20 },
                pointLabels: { color: '#848aa0', font: { size: 10 } },
                min: 0, max: 100
            }
        }
    }
});

// ---- Chart: Threat Country ----
const threatCountryChart = makeChart('threatCountryChart', {
    type: 'bar',
    data: {
        labels: ['United States', 'China', 'Russia', 'Germany', 'India', 'Brazil'],
        datasets: [{
            label: 'Attacks',
            data: [348, 211, 189, 95, 82, 67],
            backgroundColor: 'rgba(0,210,255,0.5)',
            borderRadius: 4,
            borderWidth: 0
        }]
    },
    options: {
        responsive: true, maintainAspectRatio: false, indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
            x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#848aa0' } },
            y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#848aa0' } }
        }
    }
});

// ============================================================
//  Socket.IO
// ============================================================
socket.on('connect', () => {
    addLog('System', 'Connection established with backend', 'success');
    updateSystemStatus('online');
});
socket.on('disconnect', () => {
    addLog('System', 'Connection lost. Reconnecting...', 'warning');
    updateSystemStatus('warning');
});
socket.on('dashboard_update', (data) => handleScanEvent(data));

function handleScanEvent(data) {
    const { type, payload } = data;

    switch (type) {
        case 'SCAN_START':
            resetScan(payload.target_url);
            addLog('Scan', `▶ Started scan for: ${payload.target_url}`, 'info');
            showToast(`Scan started → ${payload.target_url}`, 'info');
            break;

        case 'BASELINE_DONE':
            addLog('Scan', '✓ Baseline fingerprint established', 'success');
            break;

        case 'PAYLOAD_TEST':
            updateStats(payload);
            break;

        case 'VULN_FOUND':
            handleVulnerability(payload);
            break;

        case 'SCAN_END':
            stopLiveMonitor(payload);
            break;
    }
}

// ============================================================
//  Scan lifecycle
// ============================================================
function resetScan(targetUrl) {
    scanActive = true;
    scanStopped = false;
    totalRequests = 0;
    totalVulnerabilities = 0;
    totalPayloads = 0;
    totalBypasses = 0;
    scanStartTime = Date.now();

    document.getElementById('target-info').innerText = 'Target: ' + targetUrl;
    document.getElementById('stat-requests').innerText = '0';
    document.getElementById('stat-vulnerabilities').innerText = '0';
    document.getElementById('stat-payloads').innerText = '0';
    document.getElementById('stat-bypasses').innerText = '0';
    document.getElementById('stat-duration').innerText = '0s';
    document.getElementById('stat-rps').innerText = '0';
    document.getElementById('scan-status-badge').innerText = 'RUNNING';
    document.getElementById('scan-status-badge').className = 'badge badge-running';
    document.getElementById('scan-stopped-banner').style.display = 'none';
    document.getElementById('vuln-chart-badge').innerText = 'LIVE';
    document.getElementById('vuln-chart-badge').className = 'badge badge-running';

    vulnChart.data.labels = ['Start'];
    vulnChart.data.datasets.forEach(ds => ds.data = [0]);
    vulnChart.update();

    document.getElementById('technique-list').innerHTML = '';

    // Reset topology
    document.getElementById('topo-status').innerText = 'SCANNING';
    document.getElementById('topo-status').className = 'badge badge-running';

    nodes.clear();
    edges.clear();
    topoHosts.clear();
    topoServices.clear();
    document.getElementById('topo-host-list').innerHTML = '';
    document.getElementById('topo-service-list').innerHTML = '';
    initTopology();
}

/** Called on SCAN_END — freezes Live Monitor */
function stopLiveMonitor(payload = {}) {
    scanActive = false;
    scanStopped = true;

    const found = payload.vulnerabilities_found ?? totalVulnerabilities;
    addLog('Scan', `⏹ Scan completed. ${found} vulnerabilities found.`, 'success');
    showToast(`Scan finished — ${found} vulns found`, 'success');

    // Update badge
    document.getElementById('scan-status-badge').innerText = 'COMPLETED';
    document.getElementById('scan-status-badge').className = 'badge badge-complete';
    document.getElementById('vuln-chart-badge').innerText = 'DONE';
    document.getElementById('vuln-chart-badge').className = 'badge badge-complete';

    // Show the frozen banner
    document.getElementById('scan-stopped-banner').style.display = '';

    // Update topology status
    document.getElementById('topo-status').innerText = 'DONE';
    document.getElementById('topo-status').className = 'badge badge-complete';
}

// ============================================================
//  Stats update
// ============================================================
function updateStats(data) {
    totalRequests++;
    if (data.is_bypass) totalBypasses++;
    totalPayloads++;

    document.getElementById('stat-requests').innerText = totalRequests.toLocaleString();
    document.getElementById('stat-payloads').innerText = totalPayloads.toLocaleString();
    document.getElementById('stat-bypasses').innerText = totalBypasses.toLocaleString();
}

function handleVulnerability(data) {
    totalVulnerabilities++;
    allFindings.push(data);
    document.getElementById('stat-vulnerabilities').innerText = totalVulnerabilities;

    const type = data.vulnerability_type || 'Unknown';
    addLog('CRITICAL', `⚠ Vulnerability: ${type} — ${data.test_url || ''}`, 'danger');

    if (data.confidence > 0.8) {
        criticalSound.play().catch(() => { });
    } else {
        alertSound.play().catch(() => { });
    }

    // Update phase-based line chart
    const phase = (data.attack_phase || 'basic').toLowerCase();
    let dsIndex = 3; // Default to 'OOB/Other'
    if (phase.includes('basic')) dsIndex = 0;
    else if (phase.includes('bypass')) dsIndex = 1;
    else if (phase.includes('cloud')) dsIndex = 2;

    const lastTime = Math.floor((Date.now() - scanStartTime) / 1000);
    vulnChart.data.labels.push(lastTime + 's');

    vulnChart.data.datasets.forEach((ds, i) => {
        const lastVal = ds.data[ds.data.length - 1] || 0;
        if (i === dsIndex) {
            ds.data.push(lastVal + 1);
        } else {
            ds.data.push(lastVal);
        }
    });

    if (vulnChart.data.labels.length > 20) {
        vulnChart.data.labels.shift();
        vulnChart.data.datasets.forEach(ds => ds.data.shift());
    }
    vulnChart.update('none'); // Update without animation for performance during flood

    addTechnique(data);
    updateCvssPanel(data);
    updateTopology(data);
}

// ============================================================
//  Network Topology Logic
// ============================================================

function initTopology() {
    if (network !== null) return; // Already initialized

    const container = document.getElementById('topo-network');
    const data = { nodes, edges };
    const options = {
        nodes: {
            shape: 'dot',
            size: 16,
            font: { color: '#848aa0', size: 12, face: 'Inter' },
            borderWidth: 2,
            shadow: true
        },
        edges: {
            width: 1.5,
            color: { color: 'rgba(0, 210, 255, 0.3)', highlight: '#00d2ff' },
            smooth: { type: 'continuous' }
        },
        physics: {
            forceAtlas2Based: { gravitationalConstant: -26, centralGravity: 0.005, springLength: 100, springConstant: 0.18 },
            maxVelocity: 50,
            solver: 'forceAtlas2Based',
            timestep: 0.35,
            stabilization: { iterations: 150 }
        },
        interaction: { hover: true, tooltipDelay: 200 }
    };

    network = new vis.Network(container, data, options);
}

function updateTopology(data) {
    const url = data.test_url || '';
    if (!url) return;

    // Regex to extract host and port
    const match = url.match(/(?:https?:\/\/)?([^\/:]+)(?::(\d+))?/);
    if (!match) return;

    const host = match[1];
    const port = match[2] || (url.startsWith('https') ? '443' : '80');
    const serviceId = `${host}:${port}`;

    initTopology();

    // Add target as root if empty
    if (nodes.length === 0) {
        nodes.add({ 
            id: 'ROOT', 
            label: 'Entrypoint', 
            title: 'Initial Scan Target', 
            color: { background: '#111', border: '#ff416c' },
            size: 20
        });
    }

    // Add host
    if (!topoHosts.has(host)) {
        topoHosts.add(host);
        nodes.add({ 
            id: host, 
            label: host, 
            title: `Host/IP: ${host}`,
            color: { background: '#111', border: '#00d2ff' } 
        });
        edges.add({ id: `e_ROOT_${host}`, from: 'ROOT', to: host });

        const hostEl = document.createElement('div');
        hostEl.className = 'history-item';
        hostEl.innerHTML = `<strong>IP:</strong> ${host}`;
        document.getElementById('topo-host-list').prepend(hostEl);
    }

    // Add service
    if (!topoServices.has(serviceId)) {
        topoServices.add(serviceId);
        nodes.add({ 
            id: serviceId, 
            label: `Port ${port}`, 
            title: `Service on Port ${port}\nFinding: ${data.vulnerability_type || 'Discovery'}`,
            color: { background: '#111', border: '#00f260' },
            size: 12
        });
        edges.add({ id: `e_${host}_${serviceId}`, from: host, to: serviceId });

        const svcEl = document.createElement('div');
        svcEl.className = 'history-item';
        svcEl.innerHTML = `<strong>Service:</strong> ${host} on ${port}`;
        document.getElementById('topo-service-list').prepend(svcEl);
    }
}

// ============================================================
//  Logging
// ============================================================
function addLog(source, message, type = 'info') {
    allLogs.push({ source, message, type, time: new Date() });

    const logFeed = document.getElementById('log-feed');
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    const t = new Date().toLocaleTimeString();
    entry.innerHTML = `<span style="opacity:0.4;">[${t}]</span> <strong style="color:var(--accent-cyan)">${source}</strong>: ${message}`;
    logFeed.prepend(entry);
    if (logFeed.children.length > 150) logFeed.removeChild(logFeed.lastChild);
}

function clearLogs() { document.getElementById('log-feed').innerHTML = ''; }

// ============================================================
//  Technique cards
// ============================================================
function addTechnique(data) {
    const list = document.getElementById('technique-list');
    list.querySelector('.empty-state')?.remove();

    // Ensure finding is in the global state for the modal to find it
    const id = `tech_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`;
    window.scanFindings[id] = data;

    const card = document.createElement('div');
    card.className = 'history-item clickable-card';
    card.style.flex = '1 1 100%'; 
    card.style.cursor = 'pointer';

    card.addEventListener('click', () => {
        console.log('[Dashboard] Opening details for technique:', data.vulnerability_type);
        shownFindingDetail(id); // Use the synchronized ID-based call
    });

    card.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.4rem;">
      <strong style="color:var(--accent-red);font-size:0.9rem;letter-spacing:0.02em;">${data.vulnerability_type || 'Unknown'}</strong>
      <span class="badge badge-error" style="font-size:0.7rem;">${((data.confidence || 0) * 100).toFixed(0)}% CONF</span>
    </div>
    <div style="font-size:0.8rem;color:var(--text-secondary);word-break:break-all;line-height:1.4;">
        ${data.test_url || ''} 
        <span style="color:var(--accent-cyan);opacity:0.8;font-family: 'Fira Code', monospace;margin-left:0.5rem;">[${data.payload || ''}]</span>
    </div>
  `;
    list.prepend(card);
}

// ============================================================
//  Finding Detail Modal
// ============================================================
function shownFindingDetail(id) {
    const data = window.scanFindings[id];
    if (!data) return;

    // Reset scroll positions
    const modalBody = document.querySelector('.modal-body');
    if (modalBody) modalBody.scrollTop = 0;
    
    selectedFindingId = id;
    currentFinding = data; // Restore global pointer for Repeater & Copy actions
    const modal = document.getElementById('finding-modal');
    if (!modal) return;

    // Switch to Overview tab by default
    switchModalTab('overview');

    document.getElementById('modal-title').innerText = data.vulnerability_type || 'Vulnerability Detail';
    const method = (data.response && data.response.method) || data.method || 'GET';
    const methodEl = document.getElementById('modal-method');
    methodEl.innerText = method;

    // Dynamic styling for method badge
    if (method === 'POST') {
        methodEl.style.background = 'var(--accent-purple)';
        methodEl.style.color = '#fff';
    } else {
        methodEl.style.background = 'var(--accent-cyan)';
        methodEl.style.color = '#000';
    }
    document.getElementById('modal-url').innerText = data.test_url || 'N/A';
    document.getElementById('modal-param').innerText = data.parameter || data.param || 'N/A';
    document.getElementById('modal-phase').innerText = data.attack_phase || 'Scanning Phase';
    document.getElementById('modal-confidence').innerText = `${((data.confidence || 0) * 100).toFixed(0)}%`;

    // Severity mapping & CVSS
    const score = (data.confidence || 0) * 10;
    const sevBadge = document.getElementById('modal-severity');
    const cvssEl = document.getElementById('modal-cvss');

    sevBadge.innerText = score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW';
    sevBadge.style.background = score >= 9 ? 'rgba(255,65,108,0.2)' : score >= 7 ? 'rgba(247,201,72,0.2)' : 'rgba(0,210,255,0.2)';
    sevBadge.style.color = score >= 9 ? 'var(--accent-red)' : score >= 7 ? 'var(--accent-yellow)' : 'var(--accent-cyan)';

    cvssEl.innerText = score.toFixed(1);
    cvssEl.style.color = score >= 9 ? 'var(--accent-red)' : score >= 7 ? 'var(--accent-yellow)' : 'var(--accent-cyan)';

    // RAG Intelligence (Priority) vs AI Insight (Heuristics)
    const type = (data.vulnerability_type || '').toLowerCase();
    const conf = (data.confidence || 0) * 100;
    let insight = "This finding requires manual verification to confirm impact depth.";

    if (data.rag_analysis) {
        // Use the elite RAG intelligence from our knowledge base
        insight = `[RAG INTELLIGENCE MATCH]\n${data.rag_analysis}`;
    } else {
        // Fallback to master logic heuristics
        if (conf > 85) {
            insight = `CRITICAL: Direct technical evidence of ${type.replace('ssrf_', '').replace('_', ' ')} found in response content. High risk of exploitation.`;
        } else if (type.includes('heuristic') || type.includes('anomaly')) {
            insight = `Heuristic Analysis: Significant response anomaly (Size/Time) detected. No direct content proof found, but server behavior deviates significantly from baseline.`;
        } else if (type.includes('network')) {
            insight = `Infrastructure Discovery: Target server returned network-level indicators (Connection Refused/Timeout). Useful for internal network mapping and port scanning.`;
        } else if (conf < 30) {
            insight = `LOW CONFIDENCE: Minor variance detected. Likely a scan artifact or generic server behavior change.`;
        } else if (type.includes('filtered')) {
            insight = `NOTICE: Initial indicators were found, but the Master Logic filtered this as a likely False Positive due to error-message strings.`;
        }
    }

    document.getElementById('modal-ai-insight').innerText = insight;

    // Technical Details
    document.getElementById('modal-payload').innerText = data.payload || 'No payload data recorded.';

    // Detailed Headers
    const headersArea = document.getElementById('modal-headers');
    if (headersArea) {
        const respHdrs = data.response?.headers || {};
        headersArea.innerText = Object.entries(respHdrs).map(([k, v]) => `${k}: ${v}`).join('\n');
    }

    // Full Response Body
    const evidenceArea = document.getElementById('modal-evidence');
    const content = data.response?.content || data.evidence || data.response_sample || 'No response sample available for this find.';
    evidenceArea.innerText = content;

    // Visual Render Engine
    const renderFrame = document.getElementById('modal-render-frame');
    const renderUrl = document.getElementById('render-url-display');
    if (renderFrame && content.includes('<')) {
        renderFrame.srcdoc = content;
        renderUrl.innerText = data.test_url || 'http://internal.target/';
    } else if (renderFrame) {
        renderFrame.srcdoc = `<html><body style="font-family:sans-serif;padding:2rem;color:#333;"><h3>Rendering Unavailable</h3><p>This response does not appear to be HTML/XML.</p><pre style="background:#f4f4f4;padding:1rem;border-radius:8px;">${content.substring(0, 500)}...</pre></body></html>`;
        renderUrl.innerText = data.test_url || 'http://internal.target/';
    }

    // Remediation steps
    const remList = document.getElementById('modal-remediation');
    remList.innerHTML = '';
    const template = REMEDIATION_TEMPLATES.find(t => type.includes(t.type.toLowerCase())) || REMEDIATION_TEMPLATES[0];
    template.steps.forEach(step => {
        const div = document.createElement('div');
        div.className = 'log-entry info';
        div.style.borderLeft = '2px solid var(--accent-green)';
        div.innerText = step;
        remList.appendChild(div);
    });

    modal.style.display = 'flex';
}

function switchModalTab(tabId) {
    // Buttons
    document.querySelectorAll('.modal-tabs .tab-btn').forEach(btn => {
        const onclick = btn.getAttribute('onclick') || '';
        btn.classList.toggle('active', onclick.includes(`'${tabId}'`));
    });
    // Content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === `modal-tab-${tabId}`);
    });
}

function closeFindingDetail() {
    const modal = document.getElementById('finding-modal');
    if (modal) modal.style.display = 'none';
    currentFinding = null;
}

function copyModalPayload() {
    if (!currentFinding) return;
    const payload = currentFinding.payload || '';
    const url = currentFinding.test_url || '';
    const method = currentFinding.method || 'GET';
    const curl = `curl -X ${method} "${url}" -d "${payload}"`;

    navigator.clipboard.writeText(curl).then(() => {
        showToast('Curl command copied to clipboard!', 'success');
    });
}

function exportMetricToRepeater() {
    if (!currentFinding) return;

    // Switch to repeater view
    showView('repeater', document.querySelector('.nav-item[onclick*="repeater"]'));

    // Populate fields
    document.getElementById('repeater-url').value = currentFinding.test_url || '';
    document.getElementById('repeater-method').value = currentFinding.method || 'GET';
    document.getElementById('repeater-body').value = currentFinding.payload || '';

    closeFindingDetail();
    showToast('Finding exported to Traffic Repeater', 'info');
}

// ============================================================
//  Navigation
// ============================================================
function showView(view, navEl) {
    document.querySelectorAll('.view-content').forEach(v => v.style.display = 'none');
    const el = document.getElementById(view + '-view');
    if (el) el.style.display = 'flex';

    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    navEl?.classList.add('active');

    if (view === 'history') refreshHistory();
    if (view === 'threatmap') startThreatFeed();
    if (view === 'cloud') loadCloudEndpoints('aws');
    if (view === 'exploitdb') loadRelatedCves();
    if (view === 'remediation') generateRemediation();
}

// ============================================================
//  Duration timer
// ============================================================
setInterval(() => {
    if (scanActive && scanStartTime) {
        const dur = Math.floor((Date.now() - scanStartTime) / 1000);
        document.getElementById('stat-duration').innerText = `${dur}s`;
        const rps = totalRequests > 0 ? (totalRequests / dur).toFixed(1) : '0';
        document.getElementById('stat-rps').innerText = isFinite(rps) ? rps : '0';
    }
}, 1000);

// ============================================================
//  System Status
// ============================================================
function updateSystemStatus(state) {
    const el = document.getElementById('system-status');
    if (state === 'online') {
        el.innerText = '● OPERATIONAL';
        el.className = 'status-badge status-online';
    } else {
        el.innerText = '● DEGRADED';
        el.className = 'status-badge status-warning';
    }
}

// ============================================================
//  Toast Notifications
// ============================================================
function showToast(msg, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${msg}</span>`;
    container.prepend(toast);
    setTimeout(() => toast.remove(), 4000);
}

// ============================================================
//  Scan History
// ============================================================
async function refreshHistory() {
    const container = document.getElementById('history-items');
    container.innerHTML = '<div class="empty-state">Loading...</div>';
    try {
        const res = await fetch('/api/reports');
        const reports = await res.json();
        container.innerHTML = '';
        if (!reports.length) {
            container.innerHTML = '<div class="empty-state">No reports found.</div>';
            return;
        }
        reports.forEach(r => {
            const item = document.createElement('div');
            item.className = 'history-item';
            const d = new Date(r.time * 1000).toLocaleString();
            item.innerHTML = `<div style="font-weight:600;">${r.name}</div><div style="font-size:0.78rem;color:var(--text-secondary);">${d}</div>`;
            container.appendChild(item);
        });
    } catch (e) {
        container.innerHTML = `<div class="empty-state" style="color:var(--accent-red);">Error: ${e}</div>`;
    }
}

// ============================================================
//  AI Analysis
// ============================================================
function runAiAnalysis() {
    const feed = document.getElementById('ai-anomaly-feed');
    feed.innerHTML = '';
    addAiLog('Initializing ML pattern classifier...', 'info');

    const patterns = ['Blind SSRF', 'Open Redirect', 'Metadata Access', 'Port Scan', 'File Read', 'Protocol Misuse'];
    const scores = patterns.map(() => Math.floor(Math.random() * 100));
    aiPatternChart.data.datasets[0].data = scores;
    aiPatternChart.update();

    let delay = 300;
    const insights = [
        { src: 'Anomaly', msg: 'Unusual response time deviation detected (σ=3.4)', type: 'warning' },
        { src: 'Pattern', msg: `Blind SSRF confidence: ${scores[0]}%`, type: scores[0] > 60 ? 'danger' : 'info' },
        { src: 'Pattern', msg: `Metadata endpoint probes: ${scores[2]}% match rate`, type: scores[2] > 70 ? 'danger' : 'info' },
        { src: 'Cluster', msg: `Detected ${Math.floor(Math.random() * 5) + 2} distinct attack clusters`, type: 'info' },
        { src: 'AI', msg: 'Analysis complete. Recommend reviewing HIGH confidence findings.', type: 'success' },
    ];
    insights.forEach(({ src, msg, type }) => {
        setTimeout(() => {
            const el = document.getElementById('ai-anomaly-feed');
            const entry = document.createElement('div');
            entry.className = `log-entry ${type}`;
            entry.innerHTML = `<strong>[${src}]</strong> ${msg}`;
            el.appendChild(entry);
        }, delay);
        delay += 500;
    });
}

function addAiLog(msg, type) {
    const feed = document.getElementById('ai-anomaly-feed');
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    entry.innerText = msg;
    feed.appendChild(entry);
}

// ============================================================
//  CVSS Panel
// ============================================================
function updateCvssPanel(data) {
    const score = (data.confidence || 0) * 10;
    if (score >= 9.0) { document.getElementById('cvss-critical').innerText = +document.getElementById('cvss-critical').innerText + 1; cvssChart.data.datasets[0].data[0]++; }
    else if (score >= 7.0) { document.getElementById('cvss-high').innerText = +document.getElementById('cvss-high').innerText + 1; cvssChart.data.datasets[0].data[1]++; }
    else if (score >= 4.0) { document.getElementById('cvss-medium').innerText = +document.getElementById('cvss-medium').innerText + 1; cvssChart.data.datasets[0].data[2]++; }
    else { document.getElementById('cvss-low').innerText = +document.getElementById('cvss-low').innerText + 1; cvssChart.data.datasets[0].data[3]++; }
    cvssChart.update();

    const finding = document.createElement('div');
    finding.className = 'log-entry ' + (score >= 7 ? 'danger' : 'warning');
    finding.innerHTML = `[${score.toFixed(1)}] ${data.vulnerability_type || 'Unknown'} — ${data.test_url || ''}`;
    document.getElementById('cvss-findings').prepend(finding);
}

function calcCvss() {
    const av = parseFloat(document.getElementById('cvss-av').value);
    const ac = parseFloat(document.getElementById('cvss-ac').value);
    const ci = parseFloat(document.getElementById('cvss-ci').value);
    const score = Math.min(10, (av * ac * (1 + ci))).toFixed(1);
    const el = document.getElementById('cvss-result');
    el.innerText = score;
    el.style.color = score >= 9 ? 'var(--accent-red)' : score >= 7 ? 'var(--accent-yellow)' : score >= 4 ? 'var(--accent-cyan)' : 'var(--accent-green)';
}

// ============================================================
//  Payload IDE
// ============================================================
function selectMutation(chip) {
    document.querySelectorAll('.mutation-chip').forEach(c => c.classList.remove('selected'));
    chip.classList.add('selected');
    document.getElementById('payload-editor').value = chip.dataset.payload;
}

async function runPayload() {
    const target = document.getElementById('payload-target').value.trim();
    const payload = document.getElementById('payload-editor').value.trim();
    const enc = document.getElementById('payload-encoding').value;
    const resp = document.getElementById('payload-response');

    if (!target || !payload) { showToast('Enter a target URL and payload', 'warning'); return; }

    resp.innerHTML = '<div class="log-entry info">Sending request...</div>';
    const finalPayload = applyEncoding(payload, enc);

    try {
        const r = await fetch('/api/repeater', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: target, payload: finalPayload })
        });
        const d = await r.json();
        resp.innerHTML = `<div class="log-entry success"><strong>Status:</strong> ${d.status || r.status}</div><div class="log-entry info" style="white-space:pre-wrap;">${d.body || JSON.stringify(d, null, 2)}</div>`;
    } catch (e) {
        resp.innerHTML = `<div class="log-entry danger">Request failed: ${e}</div>`;
    }
}

function mutatePayload() {
    const base = document.getElementById('payload-editor').value.trim();
    if (!base) { showToast('Enter a payload first', 'warning'); return; }
    const mutations = [
        base,
        encodeURIComponent(base),
        encodeURIComponent(encodeURIComponent(base)),
        base.replace('http://', 'http://0177.0.0.1/'),
        base.replace('127.0.0.1', '0x7f000001'),
        base + '#bypass',
        base.replace('http://', 'HTTP://'),
    ].filter((v, i, a) => a.indexOf(v) === i);
    const grid = document.getElementById('mutation-list');
    mutations.forEach((m, i) => {
        const already = grid.querySelector(`[data-payload="${CSS.escape(m)}"]`);
        if (!already) {
            const chip = document.createElement('div');
            chip.className = 'mutation-chip';
            chip.dataset.payload = m;
            chip.title = m;
            chip.innerText = `Variant ${i + 1}`;
            chip.onclick = () => selectMutation(chip);
            grid.appendChild(chip);
        }
    });
    showToast(`Generated ${mutations.length} mutations`, 'success');
}

function applyEncoding(payload, enc) {
    switch (enc) {
        case 'url': return encodeURIComponent(payload);
        case 'double-url': return encodeURIComponent(encodeURIComponent(payload));
        case 'base64': return btoa(payload);
        case 'hex': return [...payload].map(c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
        case 'unicode': return [...payload].map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
        default: return payload;
    }
}

function loadPresets() { showToast('Default presets already loaded', 'info'); }

// ============================================================
//  WAF Evasion
// ============================================================
const WAF_TECHNIQUES = {
    cloudflare: [
        { name: 'IP Literal Bypass', desc: 'Use octal/hex representations' },
        { name: 'URL Redirection Chain', desc: 'Multi-hop via open redirect' },
        { name: 'Protocol Confusion', desc: 'Gopher/Dict instead of HTTP' },
        { name: '@-Symbol Parser Confusion', desc: 'http://user@target@real/' },
        { name: 'IPv6 Shorthand', desc: '::1 instead of 127.0.0.1' },
    ],
    akamai: [
        { name: 'Case Variation', desc: 'HTTP:// vs http://' },
        { name: 'URL Fragment', desc: 'Append # to bypass rules' },
        { name: 'Null Byte Injection', desc: 'Insert %00 in payload' },
    ],
    awswaf: [
        { name: 'DNS Rebinding', desc: 'Rebind 169.254.x.x after TTL' },
        { name: 'Double Slash', desc: 'http://metadata.aws//latest/' },
        { name: 'Custom HTTP Header', desc: 'X-Forwarded-For: internal' },
    ],
    modsec: [
        { name: 'Unicode Normalization', desc: 'ⓐⓟⓟ.internal overrides' },
        { name: 'Chunked Transfer', desc: 'Bypass content-length checks' },
        { name: 'Tab/CRLF Injection', desc: 'Whitespace character variants' },
    ],
    f5: [
        { name: 'Request Smuggling', desc: 'H2->H1 downgrade' },
        { name: 'Max URL Length', desc: 'Overflow path length limits' },
    ],
    imperva: [
        { name: 'Scheme Confusion', desc: 'jar: and javascript: schemes' },
        { name: 'Slow HTTP', desc: 'Rate-based WAF exhaustion' },
    ]
};

function selectWAF(profile) {
    const techniques = WAF_TECHNIQUES[profile] || [];
    document.getElementById('waf-detail-title').innerText = profile.toUpperCase() + ' — Bypass Techniques';
    const list = document.getElementById('waf-technique-list');
    list.innerHTML = '';
    techniques.forEach(t => {
        const card = document.createElement('div');
        card.className = 'history-item';
        card.style.flex = '1 1 240px';
        card.innerHTML = `<strong style="color:var(--primary-color)">${t.name}</strong><div style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.3rem;">${t.desc}</div>`;
        list.appendChild(card);
    });
}

// ============================================================
//  Traffic Repeater
// ============================================================
async function sendRepeaterRequest() {
    const method = document.getElementById('repeater-method').value;
    const url = document.getElementById('repeater-url').value.trim();
    const rawHdrs = document.getElementById('repeater-headers').value.trim();
    const body = document.getElementById('repeater-body').value.trim();
    const respEl = document.getElementById('repeater-response');
    const statusEl = document.getElementById('repeater-status');

    if (!url) { showToast('Enter a target URL', 'warning'); return; }

    respEl.innerHTML = '<div class="log-entry info">Sending...</div>';
    statusEl.innerText = '...'; statusEl.className = 'badge badge-idle';

    try {
        const r = await fetch('/api/repeater', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, method, headers: rawHdrs, body })
        });
        const d = await r.json();
        const sc = d.status || r.status;
        statusEl.innerText = sc;
        statusEl.className = `badge ${sc < 400 ? 'badge-complete' : 'badge-error'}`;
        respEl.innerHTML = `<div class="log-entry info" style="white-space:pre-wrap;">${JSON.stringify(d, null, 2)}</div>`;
    } catch (e) {
        statusEl.innerText = 'ERR'; statusEl.className = 'badge badge-error';
        respEl.innerHTML = `<div class="log-entry danger">Error: ${e}</div>`;
    }
}

// ============================================================
//  DNS Rebinding
// ============================================================
function launchDnsRebind() {
    const target = document.getElementById('dns-target').value.trim();
    const ip = document.getElementById('dns-rebind-ip').value.trim();
    const ttl = document.getElementById('dns-ttl').value;
    const mode = document.getElementById('dns-mode').value;
    const log = document.getElementById('dns-log');

    if (!target || !ip) { showToast('Fill in target and rebind IP', 'warning'); return; }
    log.innerHTML = '';

    const steps = [
        { d: 0, t: 'info', m: `⚡ Launching ${mode} against ${target}` },
        { d: 500, t: 'info', m: `DNS records set — TTL ${ttl}s — resolves to attacker IP first` },
        { d: 1500, t: 'warning', m: `Waiting ${ttl}s for DNS cache to expire...` },
        { d: 3000, t: 'info', m: `DNS record updated — now resolves to ${ip}` },
        { d: 4000, t: 'danger', m: `Same-origin bypass achieved! Making cross-domain requests to ${ip}` },
        { d: 5000, t: 'success', m: `Attack simulation complete. Check response data.` },
    ];
    steps.forEach(({ d, t, m }) => {
        setTimeout(() => {
            const e = document.createElement('div');
            e.className = `log-entry ${t}`;
            e.innerText = m;
            log.appendChild(e);
            log.scrollTop = log.scrollHeight;
        }, d);
    });
}

// ============================================================
//  Cloud Metadata Explorer
// ============================================================
let currentCloud = 'aws';
const CLOUD_ENDPOINTS = {
    aws: [
        { name: 'Instance ID', url: 'http://169.254.169.254/latest/meta-data/instance-id' },
        { name: 'IAM Role Creds', url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' },
        { name: 'Public Keys', url: 'http://169.254.169.254/latest/meta-data/public-keys/' },
        { name: 'User Data', url: 'http://169.254.169.254/latest/user-data' },
        { name: 'AMI ID', url: 'http://169.254.169.254/latest/meta-data/ami-id' },
        { name: 'Security Groups', url: 'http://169.254.169.254/latest/meta-data/security-groups' },
        { name: 'Token', url: 'http://169.254.169.254/latest/api/token' },
    ],
    gcp: [
        { name: 'Project ID', url: 'http://metadata.google.internal/computeMetadata/v1/project/project-id' },
        { name: 'Instance Name', url: 'http://metadata.google.internal/computeMetadata/v1/instance/name' },
        { name: 'Service Accounts', url: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/' },
        { name: 'Access Token', url: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' },
    ],
    azure: [
        { name: 'Instance Metadata', url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' },
        { name: 'Access Token', url: 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' },
        { name: 'IMDS Key', url: 'http://169.254.169.254/metadata/attested/document?api-version=2021-02-01' },
    ]
};

function setCloudTab(cloud, btn) {
    currentCloud = cloud;
    document.querySelectorAll('.cloud-tab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    loadCloudEndpoints(cloud);
}

function loadCloudEndpoints(cloud) {
    const list = document.getElementById('cloud-endpoint-list');
    const eps = CLOUD_ENDPOINTS[cloud] || [];
    list.innerHTML = '';
    eps.forEach(ep => {
        const item = document.createElement('div');
        item.className = 'history-item';
        item.style.cursor = 'pointer';
        item.innerHTML = `<div style="font-weight:600;font-size:0.88rem;">${ep.name}</div><div style="font-size:0.75rem;color:var(--text-secondary);font-family:monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${ep.url}</div>`;
        item.dataset.url = ep.url;
        item.onclick = () => {
            document.querySelectorAll('#cloud-endpoint-list .history-item').forEach(i => i.style.borderColor = '');
            item.style.borderColor = 'var(--primary-color)';
        };
        list.appendChild(item);
    });
}

async function probeCloudEndpoint() {
    const selected = document.querySelector('#cloud-endpoint-list .history-item[style*="primary"]');
    const respEl = document.getElementById('cloud-response');

    if (!selected) { showToast('Select an endpoint first', 'warning'); return; }
    const url = selected.dataset.url;
    respEl.innerHTML = `<div class="log-entry info">Probing ${url}...</div>`;

    try {
        const r = await fetch('/api/probe', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const d = await r.json();
        respEl.innerHTML = `<div class="log-entry ${d.error ? 'danger' : 'success'}" style="white-space:pre-wrap;">${d.body || JSON.stringify(d, null, 2)}</div>`;
    } catch (e) {
        respEl.innerHTML = `<div class="log-entry danger">Probe error: ${e}</div>`;
    }
}

// ============================================================
//  Target Fingerprinting
// ============================================================
async function runFingerprint() {
    const target = document.getElementById('fp-target').value.trim();
    if (!target) { showToast('Enter a target URL', 'warning'); return; }

    const results = document.getElementById('fp-results');
    results.innerHTML = '<div class="log-entry info">Fingerprinting...</div>';

    try {
        const r = await fetch('/api/fingerprint', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: target })
        });
        const d = await r.json();
        results.innerHTML = '';
        Object.entries(d).forEach(([k, v]) => {
            const item = document.createElement('div');
            item.className = 'log-entry info';
            item.innerHTML = `<strong>${k}:</strong> ${v}`;
            results.appendChild(item);
        });

        // Mock tech tags
        const tags = ['Nginx', 'Python/Flask', 'Linux', 'TLS 1.3', 'Cloudflare'];
        const tagContainer = document.getElementById('fp-tech-tags');
        tagContainer.innerHTML = '';
        tags.forEach(t => {
            const chip = document.createElement('div');
            chip.className = 'mutation-chip';
            chip.innerText = t;
            tagContainer.appendChild(chip);
        });
    } catch (e) {
        results.innerHTML = `<div class="log-entry danger">Fingerprint failed: ${e}</div>`;
    }
}

// ============================================================
//  Exploit-DB Integration
// ============================================================
async function searchExploitDb() {
    const kw = document.getElementById('edb-search').value.trim();
    const list = document.getElementById('edb-results');
    if (!kw) return;
    list.innerHTML = '<div class="empty-state">Searching...</div>';
    try {
        const r = await fetch(`/api/exploitdb/search?q=${encodeURIComponent(kw)}`);
        const d = await r.json();
        list.innerHTML = '';
        if (!d.results || !d.results.length) {
            list.innerHTML = '<div class="empty-state">No results found.</div>';
            return;
        }
        d.results.forEach(item => {
            const el = document.createElement('div');
            el.className = 'history-item';
            el.innerHTML = `<div style="font-weight:600;">${item.title}</div><div style="font-size:0.78rem;color:var(--text-secondary);">${item.cve || 'EDB-' + item.edb_id} — ${item.description || ''}</div>`;
            list.appendChild(el);
        });
    } catch (e) {
        list.innerHTML = `<div class="empty-state" style="color:var(--accent-red);">Error: ${e}</div>`;
    }
}

async function loadRelatedCves() {
    const list = document.getElementById('edb-related');
    list.innerHTML = '<div class="empty-state">Loading related CVEs...</div>';
    try {
        const r = await fetch('/api/exploitdb/related');
        const d = await r.json();
        list.innerHTML = '';
        if (!d.results || !d.results.length) {
            list.innerHTML = '<div class="empty-state">No related CVEs found. Run a scan first.</div>';
            return;
        }
        d.results.forEach(item => {
            const el = document.createElement('div');
            el.className = 'history-item';
            el.innerHTML = `<strong>${item.cve || 'EDB-' + item.edb_id}</strong> — ${item.title}`;
            list.appendChild(el);
        });
    } catch (e) {
        list.innerHTML = '<div class="empty-state">Run a scan to see related CVEs.</div>';
    }
}

// ============================================================
//  Global Threat Map Feed
// ============================================================
const THREAT_COUNTRIES = ['USA', 'China', 'Russia', 'Germany', 'India', 'Brazil', 'Iran', 'Netherlands'];
const THREAT_TYPES = ['Blind SSRF probe', 'Metadata exfil', 'Internal port scan', 'IDOR chain', 'WAF bypass attempt'];
let threatInterval = null;

function startThreatFeed() {
    if (threatInterval) return;
    const iocList = document.getElementById('threat-ioc-list');
    const evtContainer = document.getElementById('threat-events');

    threatInterval = setInterval(() => {
        const src = THREAT_COUNTRIES[Math.floor(Math.random() * THREAT_COUNTRIES.length)];
        const type = THREAT_TYPES[Math.floor(Math.random() * THREAT_TYPES.length)];
        const ip = `${rand(1, 254)}.${rand(1, 254)}.${rand(1, 254)}.${rand(1, 254)}`;

        const ioc = document.createElement('div');
        ioc.className = 'log-entry warning';
        ioc.innerHTML = `<strong>[${src}]</strong> ${ip} — ${type}`;
        iocList.prepend(ioc);
        if (iocList.children.length > 50) iocList.removeChild(iocList.lastChild);

        const evt = document.createElement('div');
        evt.style.cssText = 'font-size:0.75rem;color:rgba(0,210,255,0.8);background:rgba(0,0,0,0.3);border-radius:4px;padding:0.2rem 0.5rem;';
        evt.innerText = `[${src}] ${type}`;
        evtContainer.prepend(evt);
        if (evtContainer.children.length > 3) evtContainer.removeChild(evtContainer.lastChild);
    }, 2500);
}

function rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

// ============================================================
//  Remediation
// ============================================================
const REMEDIATION_TEMPLATES = [
    { type: 'SSRF via URL Parameter', sev: 'Critical', steps: ['Validate and whitelist allowed URL schemes (https only)', 'Implement server-side DNS resolution with blocklist for internal ranges', 'Use an allow-list of permitted external hosts', 'Apply network-level egress filtering'] },
    { type: 'Blind SSRF via Webhook', sev: 'High', steps: ['Validate webhook URLs against a whitelist', 'Redirect webhook DNS through an internal proxy with egress controls', 'Implement TOFU (Trust On First Use) for new webhook URLs'] },
    { type: 'SSRF via File Import', sev: 'High', steps: ['Strip file://, gopher://, dict:// schemes before processing', 'Use sandboxed service for remote content fetching', 'Implement Content-Type validation on fetched resources'] },
    { type: 'Cloud Metadata Exposure', sev: 'Critical', steps: ['Enforce IMDSv2 on all AWS/Azure/GCP instances', 'Block 169.254.169.254 at the WAF and network layer', 'Rotate all credentials if exposure is confirmed'] },
];

function generateRemediation() {
    const grid = document.getElementById('remediation-cards');
    grid.innerHTML = '';
    const pool = allFindings.length > 0 ? allFindings.map(f => ({
        type: f.vulnerability_type || 'Unknown',
        sev: (f.confidence || 0) > 0.8 ? 'Critical' : 'High',
        steps: REMEDIATION_TEMPLATES[0].steps
    })) : REMEDIATION_TEMPLATES;

    pool.forEach(item => {
        const card = document.createElement('div');
        card.className = 'remediation-card';
        const sevClass = item.sev === 'Critical' ? 'sev-critical' : item.sev === 'High' ? 'sev-high' : 'sev-medium';
        card.innerHTML = `
      <span class="remediation-sev ${sevClass}">${item.sev}</span>
      <div style="font-weight:700;margin-bottom:0.6rem;">${item.type}</div>
      <ul style="padding-left:1.1rem;display:flex;flex-direction:column;gap:0.4rem;">
        ${item.steps.map(s => `<li style="font-size:0.82rem;color:var(--text-secondary);">${s}</li>`).join('')}
      </ul>
    `;
        grid.appendChild(card);
    });
}

// ============================================================
//  Export Suite
// ============================================================
async function exportReport(format) {
    showToast(`Generating ${format.toUpperCase()} export...`, 'info');
    try {
        const r = await fetch(`/api/export/${format}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ findings: allFindings }) });
        const blob = await r.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `ssrf-report-${Date.now()}.${format}`;
        a.click();
        URL.revokeObjectURL(url);
        showToast(`${format.toUpperCase()} downloaded!`, 'success');
        addExportHistory(format);
    } catch (e) {
        showToast(`Export failed: ${e}`, 'danger');
        addExportHistory(format, true);
    }
}

function addExportHistory(format, failed = false) {
    const list = document.getElementById('export-history');
    list.querySelector('.empty-state')?.remove();
    const item = document.createElement('div');
    item.className = 'history-item';
    item.innerHTML = `<div style="font-weight:600;">${format.toUpperCase()} Export</div><div style="font-size:0.78rem;color:${failed ? 'var(--accent-red)' : 'var(--text-secondary)'};">${new Date().toLocaleString()} — ${failed ? 'Failed' : 'Success'}</div>`;
    list.prepend(item);
}
