import os
import json
import csv
import io
import time
import requests
from flask import Flask, render_template, jsonify, request, send_from_directory, Response
from flask_socketio import SocketIO, emit
from pathlib import Path

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ssrf-dashboard-secret'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

# ============================================================
#  Core Routes
# ============================================================
@app.route('/')
def index():
    """Render the dashboard home page."""
    return render_template('dashboard.html')

@app.route('/api/reports')
def list_reports():
    """List all available scan reports."""
    reports = []
    for file in REPORTS_DIR.glob("*.json"):
        reports.append({
            "name": file.name,
            "path": str(file),
            "time": os.path.getmtime(file)
        })
    reports.sort(key=lambda x: x['time'], reverse=True)
    return jsonify(reports)

@app.route('/api/report/<filename>')
def get_report(filename):
    """Get content of a specific report."""
    safe_path = REPORTS_DIR / filename
    if not safe_path.exists() or not safe_path.is_file():
        return jsonify({"error": "Report not found"}), 404
    try:
        with open(safe_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================
#  Repeater / Payload IDE Proxy
# ============================================================
@app.route('/api/repeater', methods=['POST'])
def repeater():
    """Proxy an HTTP request from the dashboard."""
    data = request.get_json()
    target_url = data.get('url', '').strip()
    method  = data.get('method', 'GET').upper()
    raw_hdrs = data.get('headers', '')
    body    = data.get('body', '')

    if not target_url:
        return jsonify({"error": "No URL provided"}), 400

    # Parse headers
    headers = {}
    for line in raw_hdrs.splitlines():
        if ':' in line:
            k, _, v = line.partition(':')
            headers[k.strip()] = v.strip()

    try:
        resp = requests.request(
            method,
            target_url,
            headers=headers,
            data=body.encode() if body else None,
            timeout=10,
            allow_redirects=False,
            verify=False
        )
        return jsonify({
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:5000]
        })
    except requests.exceptions.Timeout:
        return jsonify({"status": 0, "body": "[Timeout — potential Blind SSRF indicator]"})
    except Exception as e:
        return jsonify({"status": 0, "body": str(e)}), 500

# ============================================================
#  Cloud Metadata Probe
# ============================================================
@app.route('/api/probe', methods=['POST'])
def probe_endpoint():
    """Probe a cloud metadata endpoint."""
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "No URL"}), 400

    headers = {}
    # GCP requires this header
    if 'google' in url or 'metadata.google' in url:
        headers['Metadata-Flavor'] = 'Google'
    # Azure requires this header
    if 'azure' in url or '169.254.169.254/metadata' in url:
        headers['Metadata'] = 'true'

    try:
        resp = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=False)
        return jsonify({"status": resp.status_code, "body": resp.text[:4000]})
    except requests.exceptions.Timeout:
        return jsonify({"status": 0, "body": "[Timed out — host likely not accessible from this server]"})
    except Exception as e:
        return jsonify({"status": 0, "body": str(e), "error": True})

# ============================================================
#  Target Fingerprinting
# ============================================================
@app.route('/api/fingerprint', methods=['POST'])
def fingerprint():
    """Basic fingerprinting of a target URL."""
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "No URL"}), 400

    result = {}
    try:
        resp = requests.get(url, timeout=8, allow_redirects=True, verify=False)
        result['HTTP Status'] = resp.status_code
        result['Final URL'] = resp.url

        hdrs = resp.headers
        result['Server'] = hdrs.get('Server', 'Not disclosed')
        result['X-Powered-By'] = hdrs.get('X-Powered-By', 'Not disclosed')
        result['X-Frame-Options'] = hdrs.get('X-Frame-Options', 'Not set')
        result['Content-Security-Policy'] = hdrs.get('Content-Security-Policy', 'Not set')[:100] if hdrs.get('Content-Security-Policy') else 'Not set'
        result['Strict-Transport-Security'] = hdrs.get('Strict-Transport-Security', 'Not set')
        result['Content-Type'] = hdrs.get('Content-Type', 'Unknown')
        result['Via'] = hdrs.get('Via', 'Not set')
        result['CF-Ray'] = hdrs.get('CF-Ray', 'Not detected (not Cloudflare)')
        result['Response Time (ms)'] = round(resp.elapsed.total_seconds() * 1000, 1)
        result['Response Size (bytes)'] = len(resp.content)

    except requests.exceptions.Timeout:
        result['Error'] = 'Request timed out'
    except Exception as e:
        result['Error'] = str(e)

    return jsonify(result)

# ============================================================
#  Exploit-DB Integration
# ============================================================
@app.route('/api/exploitdb/search')
def exploitdb_search():
    """Search exploit-DB via keyword."""
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify({"results": []})

    try:
        from ssrf_scanner.exploit_db import search_exploits, is_ssrf_related
        if not is_ssrf_related(q):
            return jsonify({"results": [], "message": "Non-SSRF queries are restricted"})
        raw = search_exploits(q)
        results = [{"edb_id": r[0], "title": r[1], "cve": r[2], "description": r[3]} for r in raw]
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"results": [], "error": str(e)})

@app.route('/api/exploitdb/related')
def exploitdb_related():
    """Return CVEs related to common SSRF types."""
    try:
        from ssrf_scanner.exploit_db import search_exploits
        raw = search_exploits("SSRF")
        results = [{"edb_id": r[0], "title": r[1], "cve": r[2], "description": r[3]} for r in raw[:10]]
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"results": [], "error": str(e)})

# ============================================================
#  Global Stats / Config
# ============================================================
@app.route('/api/stats/global')
def global_stats():
    """Return global runtime stats."""
    return jsonify({
        "uptime_seconds": int(time.time()),
        "reports_count": len(list(REPORTS_DIR.glob("*.json"))),
        "status": "operational"
    })

@app.route('/api/waf/profiles')
def waf_profiles():
    """Return list of WAF profiles."""
    profiles = ["cloudflare", "akamai", "awswaf", "modsec", "f5", "imperva"]
    return jsonify({"profiles": profiles})

# ============================================================
#  Export Suite
# ============================================================
@app.route('/api/export/json', methods=['POST'])
def export_json():
    data = request.get_json()
    findings = data.get('findings', [])
    blob = json.dumps({"export_time": time.time(), "findings": findings}, indent=2)
    return Response(blob, mimetype='application/json',
                    headers={"Content-Disposition": "attachment; filename=ssrf-report.json"})

@app.route('/api/export/csv', methods=['POST'])
def export_csv():
    data = request.get_json()
    findings = data.get('findings', [])
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['vulnerability_type', 'test_url', 'confidence', 'timestamp'])
    for f in findings:
        writer.writerow([f.get('vulnerability_type',''), f.get('test_url',''), f.get('confidence',''), f.get('timestamp','')])
    csv_data = output.getvalue()
    return Response(csv_data, mimetype='text/csv',
                    headers={"Content-Disposition": "attachment; filename=ssrf-report.csv"})

@app.route('/api/export/markdown', methods=['POST'])
def export_markdown():
    data = request.get_json()
    findings = data.get('findings', [])
    lines = ["# SSRF Scan Report\n", f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n", "## Findings\n\n"]
    for i, f in enumerate(findings, 1):
        lines.append(f"### {i}. {f.get('vulnerability_type','Unknown')}\n")
        lines.append(f"- **URL**: `{f.get('test_url','')}`\n")
        lines.append(f"- **Confidence**: {f.get('confidence', 0) * 100:.0f}%\n\n")
    md = ''.join(lines)
    return Response(md, mimetype='text/markdown',
                    headers={"Content-Disposition": "attachment; filename=ssrf-report.md"})

@app.route('/api/export/pdf', methods=['POST'])
def export_pdf():
    """Basic PDF export — returns JSON stub if no PDF lib available."""
    try:
        # If fpdf2 or reportlab is available, we'd generate here.
        # For now, return a JSON fallback with a clear message.
        data = request.get_json()
        findings = data.get('findings', [])
        return Response(
            json.dumps({"note": "PDF generation requires fpdf2 library. pip install fpdf2", "findings": findings}, indent=2),
            mimetype='application/json',
            headers={"Content-Disposition": "attachment; filename=ssrf-report.json"}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================
#  HTTP Bridge: Scanner → Dashboard
# ============================================================
@app.route('/api/scan-event', methods=['POST', 'OPTIONS'])
def scan_event_http():
    """
    Receive a scan event via HTTP POST from the CLI scanner and
    broadcast it to all connected dashboard browser clients via Socket.IO.
    """
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        resp = app.make_default_options_response()
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return resp

    data = request.get_json(silent=True, force=True)
    if not data:
        return jsonify({"error": "No JSON body"}), 400

    event_type = data.get('type')
    payload    = data.get('payload', {})
    if not event_type:
        return jsonify({"error": "Missing 'type'"}), 400

    # Log to server console for easy debugging
    print(f"[Dashboard ←] Event: {event_type} | Payload keys: {list(payload.keys()) if isinstance(payload, dict) else 'n/a'}")

    # Broadcast to ALL browser clients on the default namespace
    socketio.emit('dashboard_update', {'type': event_type, 'payload': payload}, namespace='/')

    resp = jsonify({"ok": True, "event": event_type})
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp

# ============================================================
#  WebSocket Events
# ============================================================
@socketio.on('connect')
def handle_connect():
    print('[Dashboard] Client connected')
    emit('status', {'data': 'Connected to NET-EGRESS Dashboard'})

@socketio.on('disconnect')
def handle_disconnect():
    print('[Dashboard] Client disconnected')

@socketio.on('scan_event')
def handle_scan_event(data):
    """Broadcast scan events to all connected dashboard clients."""
    emit('dashboard_update', data, broadcast=True)

# ============================================================
#  Entry Point
# ============================================================
if __name__ == '__main__':
    print("[Dashboard] NET-EGRESS Dashboard starting on http://127.0.0.1:5000")
    # threading mode: werkzeug serves HTTP, flask-socketio handles WS upgrade
    socketio.run(app, debug=False, port=5000, host='127.0.0.1', allow_unsafe_werkzeug=True)
