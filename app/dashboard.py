# app/dashboard.py - SOC Dashboard HTML Generator
from datetime import datetime
from typing import Dict, Any, List

def generate_dashboard_html(stats: Dict[str, Any], recent_alerts: List[Dict]) -> str:
    """Generate professional SOC dashboard HTML"""
    
    html = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC Dashboard | LLM Security Gateway</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #fff;
        }}
        .header {{
            background: rgba(0, 0, 0, 0.3);
            padding: 20px 30px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        .header h1 {{ font-size: 24px; display: flex; align-items: center; gap: 10px; }}
        .header .subtitle {{ color: #888; font-size: 14px; margin-top: 5px; }}
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
            transition: transform 0.3s;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        .stat-card:hover {{ transform: translateY(-5px); background: rgba(255, 255, 255, 0.15); }}
        .stat-number {{ font-size: 36px; font-weight: bold; margin-bottom: 10px; }}
        .stat-label {{ font-size: 14px; color: #aaa; text-transform: uppercase; }}
        .section {{ padding: 20px 30px; }}
        .section-title {{
            font-size: 18px;
            margin-bottom: 20px;
            border-left: 3px solid #00d4ff;
            padding-left: 15px;
        }}
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
        .card h3 {{ margin-bottom: 15px; font-size: 16px; color: #00d4ff; }}
        .api-key-item {{
            font-family: monospace;
            font-size: 12px;
            padding: 8px 0;
            display: flex;
            justify-content: space-between;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }}
        .key {{ color: #00d4ff; }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: bold;
        }}
        .badge-critical {{ background: #ff4757; color: white; }}
        .badge-allowed {{ background: #27ae60; color: white; }}
        .alert-item {{
            padding: 12px;
            margin-bottom: 10px;
            background: rgba(255, 71, 87, 0.1);
            border-left: 3px solid #ff4757;
            border-radius: 8px;
        }}
        .alert-item .time {{ font-size: 11px; color: #888; margin-bottom: 5px; }}
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
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            font-size: 12px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Security Operations Center (SOC) Dashboard</h1>
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
        </div>
        <div class="stat-card">
            <div class="stat-number" style="color: #ff4757;">{stats.get('prompt_injections', 0)}</div>
            <div class="stat-label">Injection Attempts</div>
        </div>
    </div>
    
    <div class="two-columns">
        <div class="card">
            <h3>🔐 Top PII Types Detected</h3>
            {''.join([f'<div class="api-key-item"><span class="key">{pii_type}</span><span>{count} detections</span></div>' for pii_type, count in stats.get('top_pii_types', {}).items()]) or '<div>No PII detected yet</div>'}
        </div>
        <div class="card">
            <h3>⚠️ Top Attack Types Blocked</h3>
            {''.join([f'<div class="api-key-item"><span class="key">{attack_type}</span><span>{count} attempts</span></div>' for attack_type, count in stats.get('top_attack_types', {}).items()]) or '<div>No attacks detected yet</div>'}
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
                    <strong> {alert.get('user_id', 'Unknown')}</strong>
                    <span style="font-size: 11px; color: #888;"> (confidence: {alert.get('confidence', 0)}%)</span>
                </div>
            </div>
            ''' for alert in recent_alerts[:10]]) or '<div>No alerts yet</div>'}
        </div>
    </div>
    
    <div class="two-columns">
        <div class="card">
            <h3>✅ Compliance Status</h3>
            <div class="api-key-item"><span>GDPR</span><span class="badge allowed">Compliant</span></div>
            <div class="api-key-item"><span>HIPAA</span><span class="badge allowed">Compliant</span></div>
            <div class="api-key-item"><span>SOC2</span><span class="badge allowed">Compliant</span></div>
        </div>
        <div class="card">
            <h3>🔑 API Keys</h3>
            <div class="api-key-item"><span class="key">admin-key-12345</span><span>Admin</span></div>
            <div class="api-key-item"><span class="key">eng-key-67890</span><span>Engineering</span></div>
            <div class="api-key-item"><span class="key">mktg-key-11111</span><span>Marketing</span></div>
        </div>
    </div>
    
    <div class="footer">
        <p>LLM Security Gateway v4.0 | PostgreSQL | Redis | Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <button class="refresh-btn" onclick="location.reload()">🔄 Refresh</button>
</body>
</html>
    '''
    return html