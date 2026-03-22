"""
Reporting Module - Generate JSON, CSV, and HTML reports
"""

import json
import csv
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import html

logger = logging.getLogger(__name__)


class Reporter:
    """Generates reports in multiple formats"""
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize reporter
        
        Args:
            output_dir: Directory to save reports
        """
        try:
            self.output_dir = Path(output_dir)
            self.output_dir.mkdir(exist_ok=True, parents=True)
            logger.info(f"Reporter initialized with output directory: {output_dir}")
        except Exception as e:
            logger.error(f"Error initializing reporter: {e}")
            raise
    
    def generate_json_report(
        self,
        scan_results: Dict,
        filename: Optional[str] = None
    ) -> str:
        """
        Generate JSON report
        
        Args:
            scan_results: Scan results dictionary
            filename: Output filename (auto-generated if None)
            
        Returns:
            Path to generated report
        """
        try:
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"ssrf_scan_{timestamp}.json"
            
            filepath = self.output_dir / filename
            
            # Prepare data for JSON serialization
            json_data = self._prepare_json_data(scan_results)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"JSON report generated: {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
            raise
    
    def generate_csv_report(
        self,
        scan_results: Dict,
        filename: Optional[str] = None
    ) -> str:
        """
        Generate CSV report
        
        Args:
            scan_results: Scan results dictionary
            filename: Output filename (auto-generated if None)
            
        Returns:
            Path to generated report
        """
        try:
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"ssrf_scan_{timestamp}.csv"
            
            filepath = self.output_dir / filename
            
            vulnerabilities = scan_results.get('vulnerabilities', [])
            
            if not vulnerabilities:
                logger.warning("No vulnerabilities to write to CSV")
                # Create empty CSV with headers
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        'Timestamp', 'Payload', 'URL', 'Vulnerability Type',
                        'Confidence', 'Status Code', 'Response Size', 'Severity'
                    ])
                return str(filepath)
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Headers
                writer.writerow([
                    'Timestamp', 'Payload', 'URL', 'Vulnerability Type',
                    'Confidence', 'Status Code', 'Response Size', 'Severity',
                    'Anomaly Reasons', 'Content Matches'
                ])
                
                # Data rows
                for vuln in vulnerabilities:
                    response = vuln.get('response', {})
                    
                    writer.writerow([
                        scan_results.get('scan_end_time', ''),
                        vuln.get('payload', ''),
                        vuln.get('test_url', ''),
                        vuln.get('vulnerability_type', ''),
                        f"{vuln.get('confidence', 0):.2%}",
                        response.get('status_code', ''),
                        response.get('content_length', ''),
                        self._get_severity(vuln.get('vulnerability_type', '')),
                        '; '.join(vuln.get('anomaly_reasons', [])),
                        '; '.join([m['pattern'] for m in vuln.get('content_matches', [])])
                    ])
            
            logger.info(f"CSV report generated: {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Error generating CSV report: {e}")
            raise
    
    def generate_html_report(
        self,
        scan_results: Dict,
        filename: Optional[str] = None
    ) -> str:
        """
        Generate HTML report
        
        Args:
            scan_results: Scan results dictionary
            filename: Output filename (auto-generated if None)
            
        Returns:
            Path to generated report
        """
        try:
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"ssrf_scan_{timestamp}.html"
            
            filepath = self.output_dir / filename
            
            html_content = self._generate_html_content(scan_results)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report generated: {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            raise
    
    def generate_all_reports(self, scan_results: Dict) -> Dict[str, str]:
        """
        Generate all report formats
        
        Args:
            scan_results: Scan results dictionary
            
        Returns:
            Dictionary mapping format to filepath
        """
        try:
            reports = {}
            
            try:
                reports['json'] = self.generate_json_report(scan_results)
            except Exception as e:
                logger.error(f"Failed to generate JSON report: {e}")
            
            try:
                reports['csv'] = self.generate_csv_report(scan_results)
            except Exception as e:
                logger.error(f"Failed to generate CSV report: {e}")
            
            try:
                reports['html'] = self.generate_html_report(scan_results)
            except Exception as e:
                logger.error(f"Failed to generate HTML report: {e}")
            
            logger.info(f"Generated {len(reports)} reports")
            return reports
            
        except Exception as e:
            logger.error(f"Error generating all reports: {e}")
            return {}
    
    def _prepare_json_data(self, scan_results: Dict) -> Dict:
        """Prepare scan results for JSON serialization"""
        try:
            # Convert bytes to strings
            json_data = {
                'scan_info': scan_results.get('scan_info', {}),
                'scan_start_time': scan_results.get('scan_start_time', ''),
                'scan_end_time': scan_results.get('scan_end_time', ''),
                'duration_seconds': scan_results.get('duration_seconds', 0),
                'total_requests': scan_results.get('total_requests', 0),
                'vulnerabilities_found': scan_results.get('vulnerabilities_found', 0),
                'baseline': self._serialize_baseline(scan_results.get('baseline')),
                'vulnerabilities': [],
                'remediation': scan_results.get('remediation', {})
            }
            
            # Process vulnerabilities
            for vuln in scan_results.get('vulnerabilities', []):
                vuln_copy = vuln.copy()
                
                # Convert response content from bytes to base64 or remove
                if 'response' in vuln_copy and 'content' in vuln_copy['response']:
                    # Remove binary content for JSON
                    vuln_copy['response'] = vuln_copy['response'].copy()
                    content = vuln_copy['response'].pop('content', b'')
                    vuln_copy['response']['content_preview'] = str(content[:200])
                
                json_data['vulnerabilities'].append(vuln_copy)
            
            return json_data
            
        except Exception as e:
            logger.error(f"Error preparing JSON data: {e}")
            return scan_results
    
    def _serialize_baseline(self, baseline) -> Optional[Dict]:
        """Serialize baseline metrics"""
        try:
            if not baseline:
                return None
            
            return {
                'avg_response_size': baseline.avg_response_size,
                'status_codes': baseline.status_codes,
                'content_hash': baseline.content_hash,
                'avg_response_time': baseline.avg_response_time,
                'headers_fingerprint': baseline.headers_fingerprint
            }
        except Exception as e:
            logger.error(f"Error serializing baseline: {e}")
            return None
    
    def _get_severity(self, vuln_type: str) -> str:
        """Get severity for vulnerability type"""
        severity_map = {
            'SSRF_OOB_CONFIRMED': 'CRITICAL',
            'SSRF_CLOUD_METADATA': 'CRITICAL',
            'SSRF_FILE_DISCLOSURE': 'CRITICAL',
            'SSRF_INTERNAL_SERVICE': 'HIGH',
            'SSRF_SENSITIVE_DATA': 'HIGH',
            'SSRF_ANOMALY_DETECTED': 'MEDIUM',
            'SSRF_NETWORK_ERROR': 'MEDIUM'
        }
        return severity_map.get(vuln_type, 'UNKNOWN')
    
    def _generate_html_content(self, scan_results: Dict) -> str:
        """Generate HTML report content"""
        try:
            vulnerabilities = scan_results.get('vulnerabilities', [])
            remediation = scan_results.get('remediation', {})
            
            # Build HTML
            html_parts = [
                '<!DOCTYPE html>',
                '<html lang="en">',
                '<head>',
                '    <meta charset="UTF-8">',
                '    <meta name="viewport" content="width=device-width, initial-scale=1.0">',
                '    <title>Elite SSRF Scan Report</title>',
                '    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;700;800&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">',
                '    <style>',
                self._get_html_styles(),
                '    </style>',
                '</head>',
                '<body>',
                '    <div class="container">',
                '        <header>',
                '            <h1>SSRF INTEL REPORT</h1>',
                '            <div class="scan-meta">',
                f'                <div class="meta-tag">Target: <strong>{html.escape(scan_results.get("scan_info", {}).get("target_url", "N/A"))}</strong></div>',
                f'                <div class="meta-tag">Nodes Scanned: <strong>{scan_results.get("total_requests", 0)}</strong></div>',
                f'                <div class="meta-tag">Generated: <strong>{scan_results.get("scan_end_time", "")}</strong></div>',
                '            </div>',
                '        </header>',
                
                # Summary
                '        <div class="section-header">Executive Briefing</div>',
                self._generate_summary_html(scan_results, remediation),
                
                # Technical Findings
                '        <div class="section-header">Target Vulnerabilities</div>',
                self._generate_vulnerabilities_html(vulnerabilities),
                
                # Mitigation
                '        <div class="section-header">Remediation Protocol</div>',
                self._generate_remediation_html(remediation),
                
                '    </div>',
                '</body>',
                '</html>'
            ]
            
            return '\n'.join(html_parts)
            
        except Exception as e:
            logger.error(f"Error generating HTML content: {e}")
            return f"<html><body><h1>Error generating report: {html.escape(str(e))}</h1></body></html>"
    
    def _get_html_styles(self) -> str:
        return '''
        :root {
            --neon-green: #00ff9d;
            --neon-blue: #00d2ff;
            --neon-red: #ff3e3e;
            --glow-green: rgba(0, 255, 157, 0.3);
            --bg-deep: #05050a;
            --panel-bg: rgba(15, 15, 25, 0.8);
            --border-glow: rgba(0, 210, 255, 0.2);
            --text-main: #e0e0e0;
            --text-dim: #707a8c;
            --mono: 'Fira Code', monospace;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background-color: var(--bg-deep);
            background-image: 
                radial-gradient(circle at 20% 20%, rgba(0, 210, 255, 0.05) 0%, transparent 40%),
                radial-gradient(circle at 80% 80%, rgba(0, 255, 157, 0.05) 0%, transparent 40%);
            color: var(--text-main);
            font-family: 'Space Grotesk', -apple-system, sans-serif;
            line-height: 1.5;
            padding: 50px 20px;
        }
        .container { max-width: 1000px; margin: 0 auto; position: relative; }
        
        /* Futuristic Header */
        header {
            border: 1px solid var(--border-glow);
            background: var(--panel-bg);
            padding: 40px;
            border-radius: 4px;
            position: relative;
            margin-bottom: 50px;
            box-shadow: 0 0 30px rgba(0, 0, 0, 0.5), inset 0 0 10px rgba(0, 210, 255, 0.1);
            clip-path: polygon(0 0, 100% 0, 100% 85%, 95% 100%, 0 100%);
        }
        h1 {
            font-size: 2.8rem;
            text-transform: uppercase;
            letter-spacing: 4px;
            background: linear-gradient(90deg, var(--neon-blue), var(--neon-green));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 15px;
            font-weight: 800;
        }
        .scan-meta { display: flex; gap: 30px; margin-top: 20px; flex-wrap: wrap; }
        .meta-tag { font-size: 0.8rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; }
        .meta-tag strong { color: var(--neon-blue); }

        /* Section Styling */
        .section-header {
            display: flex;
            align-items: center;
            gap: 20px;
            margin: 60px 0 30px;
            text-transform: uppercase;
            letter-spacing: 2px;
            font-weight: 700;
            color: var(--neon-blue);
        }
        .section-header::after { content: ""; flex: 1; height: 1px; background: linear-gradient(90deg, var(--border-glow), transparent); }

        /* Stat Cards */
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; }
        .stat-box {
            background: var(--panel-bg);
            border: 1px solid var(--border-glow);
            padding: 30px;
            border-radius: 4px;
            text-align: center;
            transition: all 0.3s;
        }
        .stat-box:hover { border-color: var(--neon-blue); box-shadow: 0 0 15px var(--border-glow); transform: translateY(-5px); }
        .stat-num { font-size: 3rem; font-weight: 800; line-height: 1; margin: 10px 0; font-family: var(--mono); }
        .stat-label { font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase; }

        /* Risk Gauge */
        .risk-overview {
            display: flex;
            align-items: center;
            gap: 40px;
            background: rgba(255,255,255,0.02);
            padding: 30px;
            border-radius: 4px;
            margin: 30px 0;
            border: 1px dashed var(--border-glow);
        }
        .gauge-container { width: 120px; height: 120px; position: relative; }
        .gauge-svg { transform: rotate(-90deg); }
        .gauge-bg { fill: none; stroke: rgba(255,255,255,0.05); stroke-width: 10; }
        .gauge-fill { fill: none; stroke: var(--neon-red); stroke-width: 10; stroke-dasharray: 251.2; stroke-linecap: round; }

        /* Vulnerability Cards */
        .finding-card {
            background: var(--panel-bg);
            border: 1px solid var(--border-glow);
            margin-bottom: 30px;
            border-radius: 4px;
            overflow: hidden;
            border-left: 2px solid var(--text-dim);
        }
        .finding-card.critical { border-left: 4px solid var(--neon-red); box-shadow: -10px 0 20px rgba(255, 62, 62, 0.1); }
        .finding-card.high { border-left: 4px solid #ff8000; }
        .finding-card.medium { border-left: 4px solid #ffcc00; }

        .card-header {
            padding: 20px 30px;
            background: rgba(255, 255, 255, 0.03);
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-glow);
        }
        .finding-id { font-family: var(--mono); font-weight: 700; color: var(--neon-blue); }
        .badge { padding: 4px 12px; font-size: 0.7rem; font-weight: 800; border-radius: 2px; text-transform: uppercase; }
        .badge.critical { background: var(--neon-red); color: white; box-shadow: 0 0 10px var(--neon-red); }
        
        .card-body { padding: 30px; }
        .field-group { display: grid; grid-template-columns: 180px 1fr; gap: 10px; margin-bottom: 25px; }
        .field-label { font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; padding-top: 5px; }
        .field-value { font-family: var(--mono); font-size: 0.9rem; background: rgba(0,0,0,0.3); padding: 10px 15px; border-radius: 4px; border: 1px solid rgba(255,255,255,0.05); }

        /* Technical Evidence */
        .evidence-block {
            margin-top: 30px;
            background: #000;
            border: 1px solid #1a1a1a;
            border-radius: 4px;
            overflow: hidden;
        }
        .evidence-header {
            padding: 10px 20px;
            background: #111;
            font-size: 0.7rem;
            text-transform: uppercase;
            color: var(--neon-green);
            display: flex;
            justify-content: space-between;
            border-bottom: 1px solid #222;
        }
        .evidence-content {
            padding: 20px;
            font-family: var(--mono);
            font-size: 0.8rem;
            color: #00ff41;
            white-space: pre-wrap;
            max-height: 400px;
            overflow-y: auto;
            scrollbar-width: thin;
        }
        
        .rec-item { 
            padding: 15px 20px; 
            background: rgba(0, 210, 255, 0.03); 
            border-left: 2px solid var(--neon-blue); 
            margin-bottom: 10px;
            font-size: 0.9rem;
        }

        @media (max-width: 768px) {
            .field-group { grid-template-columns: 1fr; }
            h1 { font-size: 1.8rem; }
            header { padding: 25px; }
        }
        '''
    def _generate_summary_html(self, scan_results: Dict, remediation: Dict) -> str:
        """Generate summary section HTML"""
        try:
            total_vulns = scan_results.get('vulnerabilities_found', 0)
            severity = remediation.get('severity_breakdown', {})
            critical_count = severity.get('CRITICAL', 0)
            
            # Risk score calculation
            risk_percent = min(100, (critical_count * 20) + (severity.get('HIGH', 0) * 10) + (severity.get('MEDIUM', 0) * 2))
            stroke_dash = 251.2 * (risk_percent / 100)

            return f'''
            <div class="risk-overview">
                <div class="gauge-container">
                    <svg class="gauge-svg" width="120" height="120">
                        <circle class="gauge-bg" cx="60" cy="60" r="40"/>
                        <circle class="gauge-fill" cx="60" cy="60" r="40" style="stroke-dashoffset: {251.2 - stroke_dash}"/>
                    </svg>
                    <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-weight: 800; color: var(--neon-red);">{risk_percent}%</div>
                </div>
                <div>
                    <h3 style="color: var(--neon-red); margin-bottom: 5px;">Threat Level: {'HIGH' if risk_percent > 60 else 'MODERATE' if risk_percent > 20 else 'LOW'}</h3>
                    <p style="color: var(--text-dim); max-width: 500px;">{html.escape(remediation.get('summary', 'Threat assessment pending.'))}</p>
                </div>
            </div>
            
            <div class="stat-grid">
                <div class="stat-box">
                    <div class="stat-label">Critical Findings</div>
                    <div class="stat-num" style="color: var(--neon-red);">{critical_count}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">High Risk</div>
                    <div class="stat-num" style="color: #ff8000;">{severity.get('HIGH', 0)}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Medium Risk</div>
                    <div class="stat-num" style="color: #ffcc00;">{severity.get('MEDIUM', 0)}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Total Probes</div>
                    <div class="stat-num">{scan_results.get('total_requests', 0)}</div>
                </div>
            </div>
            '''
        except Exception as e:
            logger.error(f"Error generating summary HTML: {e}")
            return "<p>Error generating summary</p>"
    
    def _generate_scan_info_html(self, scan_results: Dict) -> str:
        """Generate scan info HTML"""
        try:
            scan_info = scan_results.get('scan_info', {})
            
            return f'''
            <div class="stat-card">
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">Technique</div>
                        <div class="info-value">Full Behavioral Analysis</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Requests Sent</div>
                        <div class="info-value">{scan_results.get('total_requests', 0)} probes</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Duration</div>
                        <div class="info-value">{scan_results.get('duration_seconds', 0):.2f} seconds</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Timestamp (Start)</div>
                        <div class="info-value">{html.escape(scan_results.get('scan_start_time', 'N/A'))}</div>
                    </div>
                </div>
            </div>
            '''
        except Exception as e:
            logger.error(f"Error generating scan info HTML: {e}")
            return "<p>Error generating scan info</p>"
    
    def _generate_vulnerabilities_html(self, vulnerabilities: List[Dict]) -> str:
        """Generate vulnerabilities section HTML"""
        try:
            if not vulnerabilities:
                return '<p>No vulnerabilities detected.</p>'
            
            html_parts = []
            
            for i, vuln in enumerate(vulnerabilities, 1):
                severity = self._get_severity(vuln.get('vulnerability_type', ''))
                confidence = vuln.get('confidence', 0)
                
                html_parts.append(f'''
                <div class="finding-card {severity.lower()}">
                    <div class="card-header">
                        <div class="finding-id">FINDING_ID: SSRF-{i:03d}</div>
                        <div class="badge {severity.lower()}">{severity}</div>
                    </div>
                    
                    <div class="card-body">
                        <div class="field-group">
                            <div class="field-label">Threat Type</div>
                            <div class="field-value">{html.escape(vuln.get('vulnerability_type', 'UNKNOWN'))}</div>
                        </div>
                        <div class="field-group">
                            <div class="field-label">Injection Endpoint</div>
                            <div class="field-value" style="color: var(--neon-blue);">{html.escape(str(vuln.get('test_url', 'N/A')))}</div>
                        </div>

                        <!-- RAG Expert Analysis -->
                        <div class="field-group" style="margin-top: 15px; border-top: 1px solid rgba(0,255,157,0.1); padding-top: 15px;">
                            <div class="field-label" style="color: var(--neon-green); text-transform: uppercase; font-size: 0.7em; letter-spacing: 2px;">
                                <i class="ai-icon"></i> AI Expert Assessment (RAG)
                            </div>
                            <div class="rag-content" style="background: rgba(0,255,157,0.03); border: 1px solid rgba(0,255,157,0.1); padding: 12px; margin-top: 8px; font-family: 'Fira Code', monospace; font-size: 0.9em; line-height: 1.5;">
                                <div style="color: var(--neon-blue); margin-bottom: 5px;">> Analyzing against knowledge base...</div>
                                <div class="rag-summary" style="color: var(--text-main);">{html.escape(str(vuln.get('rag_analysis', 'Intelligence pending... Run with --ai-analyze for full assessment.')))}</div>
                            </div>
                        </div>
                        <div class="field-group">
                            <div class="field-label">Certainty Profile</div>
                            <div class="field-value">{confidence:.0%} match strength based on anomaly heuristics</div>
                        </div>

                        <div class="evidence-block">
                            <div class="evidence-header">
                                <span>Payload Evidence</span>
                                <span>RAW DATA</span>
                            </div>
                            <div class="evidence-content">{html.escape(str(vuln.get('payload', 'N/A')))}</div>
                        </div>
                        
                        {self._generate_anomaly_reasons_html(vuln.get('anomaly_reasons', []))}
                    </div>
                </div>
                ''')
            
            return '\n'.join(html_parts)
            
        except Exception as e:
            logger.error(f"Error generating vulnerabilities HTML: {e}")
            return "<p>Error generating vulnerabilities section</p>"
    
    def _generate_content_matches_html(self, matches: List[Dict]) -> str:
        """Generate content matches HTML"""
        if not matches:
            return ''
        
        items = [f"<li><strong>{html.escape(m['pattern'])}</strong>: {html.escape(m['matched'][:100])}</li>" 
                 for m in matches]
        
        return f'''
        <div style="margin-top: 15px;">
            <strong>Content Matches:</strong>
            <ul style="margin-left: 20px;">
                {''.join(items)}
            </ul>
        </div>
        '''
    
    def _generate_anomaly_reasons_html(self, reasons: List[str]) -> str:
        """Generate anomaly reasons HTML"""
        if not reasons:
            return ''
        
        items = [f"<li>{html.escape(r)}</li>" for r in reasons]
        
        return f'''
        <div style="margin-top: 15px;">
            <strong>Anomaly Indicators:</strong>
            <ul style="margin-left: 20px;">
                {''.join(items)}
            </ul>
        </div>
        '''
    
    def _generate_remediation_html(self, remediation: Dict) -> str:
        """Generate remediation section HTML"""
        try:
            recommendations = remediation.get('recommendations', [])
            
            if not recommendations:
                return '<p>No remediation recommendations available.</p>'
            
            html_parts = []
            
            for rec in recommendations:
                severity = rec.get('severity', 'UNKNOWN')
                
                html_parts.append(f'''
                <div class="finding-card {severity.lower()}">
                    <div class="card-header">
                        <div class="finding-id">{html.escape(rec.get('title', 'MITIGATION_REQUIRED'))}</div>
                        <div class="badge {severity.lower()}">{severity}</div>
                    </div>
                    <div class="card-body">
                        <p style="margin-bottom: 20px; color: var(--text-dim);">{html.escape(rec.get('description', ''))}</p>
                        
                        <div class="field-label" style="margin-bottom: 10px;">Execution Protocol:</div>
                        {''.join(f'<div class="rec-item">{html.escape(r)}</div>' for r in rec.get('recommendations', []))}
                        
                        {self._generate_code_example_html(rec.get('code_examples', {}))}
                    </div>
                </div>
                ''')
            
            return '\n'.join(html_parts)
            
        except Exception as e:
            logger.error(f"Error generating remediation HTML: {e}")
            return "<p>Error generating remediation section</p>"
    
    def _generate_code_example_html(self, code_examples: Dict) -> str:
        """Generate code examples HTML"""
        if not code_examples:
            return ''
        
        examples = []
        for lang, code in code_examples.items():
            examples.append(f'''
            <h4 style="margin-top: 15px;">Example ({lang}):</h4>
            <pre class="code-block"><code>{html.escape(code)}</code></pre>
            ''')
        
        return '\n'.join(examples)
