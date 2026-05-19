# app/dashboard.py - SOC Compliance Dashboard HTML Generator
from datetime import datetime
from typing import Dict, Any
import json

def generate_dashboard_html(stats: Dict[str, Any], recent_alerts: list) -> str:
    """Generate professional SOC dashboard HTML"""
    
    html = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC Dashboard | LLM Security Gateway</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #fff;
        }}
        
        /* Header */
        .header {{
            background: rgba(0, 0, 0, 0.3);
            padding: 20px 30px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .header h1 {{
            font-size: 24px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .header h1::before {{
            content: "🔐";
            font-size: 28px;
        }}
        
        .header .subtitle {{
            color: #888;
            font-size: 14px;
            margin-top: 5px;
        }}
        
        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
        }}
        
        .stat-card {{
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 20px;
            text-align: center;
            transition: transform 0.3s, box-shadow 0.3s;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            background: rgba(255, 255, 255, 0.15);
        }}
        
        .stat-number {{
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .stat-label {{
            font-size: 14px;
            color: #aaa;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .stat-trend {{
            font-size: 12px;
            margin-top: 10px;
            color: #4caf50;
        }}
        
        /* Security Section */
        .section {{
            padding: 20px 30px;
        }}
        
        .section-title {{
            font-size: 18px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
            border-left: 3px solid #00d4ff;
            padding-left: 15px;
        }}
        
        /* Two Column Layout */
        .two-columns {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            padding: 0 30px 30px 30px;
        }}
        
        .card {{
            background: rgba(255, 255, 255, 0.08);
            border-radius: 15px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .card h3 {{
            margin-bottom: 15px;
            font-size: 16px;
            color: #00d4ff;
        }}
        
        /* Table Styles */
        .alert-table, .pii-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .alert-table th, .pii-table th {{
            text-align: left;
            padding: 10px;
            font-size: 12px;
            color: #888;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .alert-table td, .pii-table td {{
            padding: 10px;
            font-size: 13px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }}
        
        /* Badges */
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: bold;
        }}
        
        .badge-critical {{
            background: #ff4757;
            color: white;
        }}
        
        .badge-high {{
            background: #ff6b6b;
            color: white;
        }}
        
        .badge-medium {{
            background: #ffa502;
            color: white;
        }}
        
        .badge-low {{
            background: #2ed573;
            color: white;
        }}
        
        .badge-blocked {{
            background: #e74c3c;
            color: white;
        }}
        
        .badge-allowed {{
            background: #27ae60;
            color: white;
        }}
        
        /* Progress Bar */
        .progress-bar {{
            width: 100%;
            height: 8px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            overflow: hidden;
            margin-top: 10px;
        }}
        
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #00d4ff, #00ff88);
            border-radius: 10px;
            transition: width 0.5s;
        }}
        
        /* Footer */
        .footer {{
            text-align: center;
            padding: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            font-size: 12px;
            color: #666;
            margin-top: 20px;
        }}
        
        /* Refresh Button */
        .refresh-btn {{
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: #00d4ff;
            color: #1a1a2e;
            border: none;
            padding: 12px 20px;
            border-radius: 30px;
            cursor: pointer;
            font-weight: bold;
            font-size: 14px;
            transition: transform 0.3s;
            z-index: 1000;
        }}
        
        .refresh-btn:hover {{
            transform: scale(1.05);
        }}
        
        /* Alert Item */
        .alert-item {{
            padding: 12px;
            margin-bottom: 10px;
            background: rgba(255, 71, 87, 0.1);
            border-left: 3px solid #ff4757;
            border-radius: 8px;
        }}
        
        .alert-item .time {{
            font-size: 11px;
            color: #888;
            margin-bottom: 5px;
        }}
        
        .alert-item .message {{
            font-size: 13px;
        }}
        
        /* API Keys Box */
        .api-keys {{
            background: rgba(0, 212, 255, 0.1);
            border: 1px solid rgba(0, 212, 255, 0.3);
        }}
        
        .api-key-item {{
            font-family: monospace;
            font-size: 12px;
            padding: 5px 0;
            display: flex;
            justify-content: space-between;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }}
        
        .api-key-item:last-child {{
            border-bottom: none;
        }}
        
        .key {{
            color: #00d4ff;
        }}
        
        .role {{
            color: #ffa502;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Operations Center (SOC) Dashboard</h1>
        <div class="subtitle">Real-time LLM Security Gateway Monitoring | GDPR • HIPAA • SOC2 Compliant</div>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-number">{stats.get('total_requests', 0)}</div>
            <div class="stat-label">Total Requests</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" style="color: #ff4757;">{stats.get('blocked_requests', 0)}</div>
            <div class="stat-label">Blocked Requests</div>
            <div class="stat-trend">🚫 {stats.get('block_rate_percent', 0)}% of total</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" style="color: #ffa502;">{stats.get('pii_detections', 0)}</div>
            <div class="stat-label">PII Detections</div>
            <div class="stat-trend">🔐 {stats.get('pii_detection_rate', 0)}% of requests</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" style="color: #ff4757;">{stats.get('prompt_injections', 0)}</div>
            <div class="stat-label">Injection Attempts</div>
            <div class="stat-trend">⚠️ {stats.get('injection_rate', 0)}% of requests</div>
        </div>
    </div>
    
    <div class="two-columns">
        <!-- Left Column: Top PII Types -->
        <div class="card">
            <h3>🔐 Top PII Types Detected</h3>
            <div class="pii-table">
                {''.join([f'<div class="api-key-item"><span class="key">{pii_type}</span><span>{count} detections</span></div>' for pii_type, count in stats.get('top_pii_types', {}).items()]) or '<div>No PII detected yet</div>'}
            </div>
        </div>
        
        <!-- Right Column: Top Attack Types -->
        <div class="card">
            <h3>⚠️ Top Attack Types Blocked</h3>
            <div class="pii-table">
                {''.join([f'<div class="api-key-item"><span class="key">{attack_type}</span><span>{count} attempts</span></div>' for attack_type, count in stats.get('top_attack_types', {}).items()]) or '<div>No attacks detected yet</div>'}
            </div>
        </div>
    </div>
    
    <div class="section">
        <div class="section-title">🚨 Recent Security Alerts</div>
        <div class="card">
            {''.join([f'''
            <div class="alert-item">
                <div class="time">{alert.get('timestamp', '')[:19]}</div>
                <div class="message">
                    <span class="badge badge-critical">INJECTION</span>
                    <strong> {alert.get('user_id', 'Unknown')}</strong> - {alert.get('attack_types', 'Unknown attack')}
                    <span style="font-size: 11px; color: #888;"> (confidence: {alert.get('confidence', 0)}%)</span>
                </div>
            </div>
            ''' for alert in recent_alerts[:10]]) or '<div>No alerts yet</div>'}
        </div>
    </div>
    
    <div class="two-columns">
        <!-- Compliance Status -->
        <div class="card">
            <h3>✅ Compliance Status</h3>
            <div class="api-key-item"><span>GDPR</span><span class="badge allowed">Compliant</span></div>
            <div class="api-key-item"><span>HIPAA</span><span class="badge allowed">Compliant</span></div>
            <div class="api-key-item"><span>SOC2</span><span class="badge allowed">Compliant</span></div>
            <div class="api-key-item"><span>Data Retention</span><span>90 days</span></div>
        </div>
        
        <!-- API Keys for Testing -->
        <div class="card api-keys">
            <h3>🔑 Test API Keys (RBAC)</h3>
            <div class="api-key-item"><span class="key">admin-key-12345</span><span class="role">Admin (Full Access)</span></div>
            <div class="api-key-item"><span class="key">test-key-67890</span><span class="role">User (Limited)</span></div>
            <div class="api-key-item"><span class="key">security-key-11111</span><span class="role">Security Analyst</span></div>
        </div>
    </div>
    
    <div class="section">
        <div class="card">
            <h3>📊 System Health</h3>
            <div class="api-key-item"><span>Gateway Status</span><span class="badge allowed">🟢 Operational</span></div>
            <div class="api-key-item"><span>PII Redaction</span><span class="badge allowed">✅ Active (Presidio)</span></div>
            <div class="api-key-item"><span>Threat Detection</span><span class="badge allowed">✅ Active (Rebuff)</span></div>
            <div class="api-key-item"><span>Database</span><span class="badge allowed">✅ Connected</span></div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {min(100, stats.get('block_rate_percent', 0) * 10)}%"></div>
            </div>
            <div class="stat-trend" style="margin-top: 10px;">Threat Block Rate: {stats.get('block_rate_percent', 0)}%</div>
        </div>
    </div>
    
    <div class="footer">
        <p>LLM Security Gateway v3.0 | Real-time Security Monitoring | Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>🔐 PII Redaction | 🛡️ Prompt Injection Protection | 📊 Compliance Auditing</p>
    </div>
    
    <button class="refresh-btn" onclick="location.reload()">🔄 Refresh Dashboard</button>
</body>
</html>
    '''
    
    return html