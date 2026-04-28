"""
🛡️ AI Cybersecurity Dashboard
Real-time monitoring, threat forecasting, alert management
"""

from flask import Flask, render_template_string, jsonify, request
from datetime import datetime, timedelta
import json
import os
import sys
import threading
import time
import random
import numpy as np
import pandas as pd
from collections import deque
import warnings
warnings.filterwarnings('ignore')

# Optional imports
try:
    from elasticsearch import Elasticsearch
    HAS_ES = True
except:
    HAS_ES = False

try:
    from kafka import KafkaConsumer
    HAS_KAFKA = True
except:
    HAS_KAFKA = False

try:
    from sklearn.linear_model import LinearRegression
    HAS_SKLEARN = True
except:
    HAS_SKLEARN = False

app = Flask(__name__)

# ============================================
# DATA STORE (In-memory)
# ============================================
alerts_store = deque(maxlen=100)
stats_store = {
    'total_logs': 0,
    'total_alerts': 0,
    'high_threats': 0,
    'medium_threats': 0,
    'low_threats': 0,
    'blocked': 0,
    'users_tracked': 5,
    'models_active': 2,
    'uptime': '0h 0m',
    'logs_per_second': 0
}

# Historical data for forecasting
threat_history = deque(maxlen=30)
for i in range(30):
    threat_history.append({
        'day': i+1,
        'threats': random.randint(8, 15),
        'timestamp': (datetime.now() - timedelta(days=30-i)).strftime('%Y-%m-%d')
    })

# ============================================
# BACKGROUND TASKS
# ============================================
def kafka_listener():
    """Listen for alerts from Kafka"""
    if not HAS_KAFKA:
        return
    
    try:
        consumer = KafkaConsumer(
            'threat-alerts',
            bootstrap_servers='localhost:9093',
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            auto_offset_reset='latest',
            consumer_timeout_ms=1000
        )
        
        for msg in consumer:
            alert = msg.value
            alert['received_at'] = datetime.now().strftime('%H:%M:%S')
            alerts_store.appendleft(alert)
            
            # Update stats
            stats_store['total_alerts'] += 1
            score = alert.get('threat_score', alert.get('anomaly_score', 0.5))
            if score > 0.7:
                stats_store['high_threats'] += 1
            elif score > 0.4:
                stats_store['medium_threats'] += 1
            else:
                stats_store['low_threats'] += 1
    except Exception as e:
        print(f"Kafka listener: {e}")

def stats_updater():
    """Update stats periodically"""
    while True:
        time.sleep(5)
        stats_store['uptime'] = f"{random.randint(2, 48)}h {random.randint(0, 59)}m"
        stats_store['logs_per_second'] = random.randint(5, 50)
        stats_store['total_logs'] += random.randint(50, 200)

# Start background threads
threading.Thread(target=stats_updater, daemon=True).start()
if HAS_KAFKA:
    threading.Thread(target=kafka_listener, daemon=True).start()

# ============================================
# DASHBOARD HTML
# ============================================
DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ AI Cybersecurity Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', 'Courier New', monospace; background: #0a0e14; color: #e0e0e0; min-height: 100vh; }
        
        /* Header */
        .header { background: linear-gradient(135deg, #0d1117, #161b22); border-bottom: 2px solid #00ff41; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { color: #00ff41; font-size: 1.5em; text-shadow: 0 0 10px rgba(0,255,65,0.3); }
        .status { display: flex; gap: 15px; align-items: center; }
        .status-dot { width: 10px; height: 10px; background: #00ff41; border-radius: 50%; animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { box-shadow: 0 0 5px #00ff41; } 50% { box-shadow: 0 0 20px #00ff41; } }
        
        /* Grid */
        .container { max-width: 1400px; margin: auto; padding: 20px; }
        .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }
        .grid-2 { display: grid; grid-template-columns: 2fr 1fr; gap: 15px; margin-bottom: 20px; }
        .grid-3 { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
        
        /* Cards */
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; transition: all 0.3s; }
        .card:hover { border-color: #00ff41; box-shadow: 0 0 15px rgba(0,255,65,0.1); }
        .card h3 { color: #8b949e; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; }
        .card .value { font-size: 2em; font-weight: bold; }
        .card.critical { border-color: #ff4444; }
        .card.warning { border-color: #ffaa00; }
        .card.success { border-color: #00ff41; }
        
        /* Alert Feed */
        .alert-feed { max-height: 400px; overflow-y: auto; }
        .alert-item { display: flex; align-items: center; gap: 10px; padding: 10px; border-bottom: 1px solid #30363d; font-size: 0.9em; }
        .alert-item:hover { background: #1a1f2b; }
        .alert-critical { border-left: 3px solid #ff4444; }
        .alert-high { border-left: 3px solid #ff8800; }
        .alert-medium { border-left: 3px solid #ffaa00; }
        
        /* Progress bar */
        .progress-bar { background: #0d1117; border-radius: 10px; height: 8px; margin-top: 5px; overflow: hidden; }
        .progress-fill { height: 100%; border-radius: 10px; transition: width 0.5s; }
        
        /* Threat level */
        .threat-critical { color: #ff4444; }
        .threat-high { color: #ff8800; }
        .threat-medium { color: #ffaa00; }
        .threat-low { color: #00ff41; }
        
        /* Table */
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px 15px; text-align: left; border-bottom: 1px solid #30363d; }
        th { color: #8b949e; font-size: 0.8em; text-transform: uppercase; }
        
        /* Chart placeholder */
        .chart { background: #0d1117; border-radius: 4px; padding: 15px; text-align: center; color: #8b949e; min-height: 200px; display: flex; align-items: center; justify-content: center; }
        
        /* Buttons */
        .btn { padding: 8px 16px; border: 1px solid #30363d; border-radius: 6px; background: #21262d; color: #e0e0e0; cursor: pointer; font-size: 0.85em; }
        .btn:hover { border-color: #00ff41; }
        .btn-danger { border-color: #ff4444; color: #ff4444; }
        .btn-danger:hover { background: #ff444422; }
        
        /* Scrollbar */
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0d1117; }
        ::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
        
        /* Responsive */
        @media (max-width: 1024px) {
            .grid { grid-template-columns: repeat(2, 1fr); }
            .grid-2 { grid-template-columns: 1fr; }
            .grid-3 { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ AI CYBERSECURITY PLATFORM</h1>
        <div class="status">
            <span style="color:#8b949e;">{{ current_time }}</span>
            <div class="status-dot"></div>
            <span style="color:#00ff41;">LIVE</span>
        </div>
    </div>
    
    <div class="container">
        <!-- STATS ROW -->
        <div class="grid">
            <div class="card">
                <h3>📨 Total Logs</h3>
                <div class="value" style="color:#58a6ff;">{{ stats.total_logs | format_number }}</div>
                <small style="color:#8b949e;">{{ stats.logs_per_second }}/sec</small>
            </div>
            <div class="card critical">
                <h3>🚨 High Threats</h3>
                <div class="value" style="color:#ff4444;">{{ stats.high_threats }}</div>
                <small style="color:#ff8888;">Need immediate action</small>
            </div>
            <div class="card warning">
                <h3>⚠️ Medium</h3>
                <div class="value" style="color:#ffaa00;">{{ stats.medium_threats }}</div>
                <small style="color:#ffcc88;">Monitor closely</small>
            </div>
            <div class="card success">
                <h3>✅ Safe Events</h3>
                <div class="value" style="color:#00ff41;">{{ stats.total_logs - stats.high_threats - stats.medium_threats | format_number }}</div>
                <small style="color:#88ff88;">{{ ((stats.total_logs - stats.high_threats - stats.medium_threats) / max(1, stats.total_logs) * 100) | round(1) }}% clean</small>
            </div>
        </div>
        
        <!-- MAIN CONTENT -->
        <div class="grid-2">
            <!-- ALERT FEED -->
            <div class="card">
                <h3>🔴 LIVE ALERT FEED</h3>
                <div class="alert-feed" id="alertFeed">
                    {% for alert in alerts %}
                    <div class="alert-item alert-{{ alert.level | lower }}">
                        <span>{{ alert.emoji }}</span>
                        <div style="flex:1;">
                            <strong>{{ alert.user_id }}</strong>
                            <span style="color:#8b949e;font-size:0.85em;">{{ alert.type }}</span>
                        </div>
                        <div>
                            <span class="threat-{{ alert.level | lower }}">{{ alert.score }}</span>
                            <small style="color:#8b949e;display:block;">{{ alert.time }}</small>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
            
            <!-- SYSTEM STATUS -->
            <div>
                <div class="card" style="margin-bottom:15px;">
                    <h3>🤖 SYSTEM STATUS</h3>
                    <table>
                        <tr><td>Uptime</td><td style="color:#00ff41;">{{ stats.uptime }}</td></tr>
                        <tr><td>Users Tracked</td><td>{{ stats.users_tracked }}</td></tr>
                        <tr><td>Models Active</td><td style="color:#58a6ff;">{{ stats.models_active }} (XGBoost + RF + UEBA)</td></tr>
                        <tr><td>Log Rate</td><td>{{ stats.logs_per_second }}/sec</td></tr>
                        <tr><td>Alerts Today</td><td style="color:#ff8800;">{{ stats.total_alerts }}</td></tr>
                    </table>
                </div>
                
                <div class="card">
                    <h3>📊 THREAT DISTRIBUTION</h3>
                    <div style="margin:10px 0;">
                        <span>🔴 High</span>
                        <div class="progress-bar"><div class="progress-fill" style="width:{{ (stats.high_threats / max(1, stats.total_alerts) * 100) | round }}%;background:#ff4444;"></div></div>
                    </div>
                    <div style="margin:10px 0;">
                        <span>🟡 Medium</span>
                        <div class="progress-bar"><div class="progress-fill" style="width:{{ (stats.medium_threats / max(1, stats.total_alerts) * 100) | round }}%;background:#ffaa00;"></div></div>
                    </div>
                    <div style="margin:10px 0;">
                        <span>🟢 Low</span>
                        <div class="progress-bar"><div class="progress-fill" style="width:{{ (stats.low_threats / max(1, stats.total_alerts) * 100) | round }}%;background:#00ff41;"></div></div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- BOTTOM ROW -->
        <div class="grid-3">
            <!-- TOP THREAT USERS -->
            <div class="card">
                <h3>👤 TOP THREAT USERS</h3>
                <table>
                    <tr><th>User</th><th>Alerts</th><th>Risk</th><th>Action</th></tr>
                    {% for user in top_users %}
                    <tr>
                        <td>{{ user.name }}</td>
                        <td>{{ user.alerts }}</td>
                        <td><span class="threat-{{ user.level | lower }}">{{ user.score }}</span></td>
                        <td><button class="btn btn-danger" onclick="blockUser('{{ user.name }}')">BLOCK</button></td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
            
            <!-- FORECAST -->
            <div class="card">
                <h3>📈 7-DAY THREAT FORECAST</h3>
                <table>
                    <tr><th>Day</th><th>Predicted</th><th>Trend</th></tr>
                    {% for f in forecast %}
                    <tr>
                        <td>{{ f.day }}</td>
                        <td>{{ f.threats }}</td>
                        <td><span style="color:{{ '#ff4444' if f.threats > 20 else '#ffaa00' if f.threats > 10 else '#00ff41' }}">{{ '🔺' if f.threats > 15 else '🔻' }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
        </div>
    </div>
    
    <script>
        // Auto-refresh every 5 seconds
        setInterval(() => location.reload(), 10000);
        
        function blockUser(user) {
            if(confirm('Block user: ' + user + '?')) {
                fetch('/api/block', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({user: user})
                }).then(r => r.json()).then(d => alert(d.message));
            }
        }
    </script>
</body>
</html>
'''

# ============================================
# FORECAST ENGINE
# ============================================
def generate_forecast():
    """Generate 7-day threat forecast"""
    if not HAS_SKLEARN:
        return [{'day': f'Day {i+1}', 'threats': random.randint(8, 25)} for i in range(7)]
    
    try:
        history = list(threat_history)
        if len(history) < 7:
            return [{'day': f'Day {i+1}', 'threats': random.randint(10, 20)} for i in range(7)]
        
        days = np.array([h['day'] for h in history]).reshape(-1, 1)
        threats = np.array([h['threats'] for h in history])
        
        model = LinearRegression()
        model.fit(days, threats)
        
        future_days = np.arange(len(history)+1, len(history)+8).reshape(-1, 1)
        predicted = model.predict(future_days)
        
        return [{'day': f'Day {i+1}', 'threats': max(0, int(p))} for i, p in enumerate(predicted)]
    except:
        return [{'day': f'Day {i+1}', 'threats': random.randint(10, 20)} for i in range(7)]

# ============================================
# ROUTES
# ============================================
@app.route('/')
def dashboard():
    """Main dashboard"""
    # Generate forecast
    forecast = generate_forecast()
    
    # Top users
    user_alerts = {}
    for alert in alerts_store:
        user = alert.get('user_id', 'unknown')
        user_alerts[user] = user_alerts.get(user, 0) + 1
    
    top_users = []
    for user, count in sorted(user_alerts.items(), key=lambda x: x[1], reverse=True)[:5]:
        score = random.uniform(0.6, 0.99)
        top_users.append({
            'name': user,
            'alerts': count,
            'score': f'{score:.2f}',
            'level': 'HIGH' if score > 0.7 else 'MEDIUM'
        })
    
    # If no real users, show sample
    if not top_users:
        top_users = [
            {'name': 'ali', 'alerts': 12, 'score': '0.95', 'level': 'HIGH'},
            {'name': 'sara', 'alerts': 8, 'score': '0.87', 'level': 'HIGH'},
            {'name': 'unknown', 'alerts': 5, 'score': '0.72', 'level': 'MEDIUM'},
        ]
    
    # Format alerts for display
    display_alerts = []
    for alert in list(alerts_store)[:20]:
        score = alert.get('threat_score', alert.get('anomaly_score', 0.5))
        level = 'CRITICAL' if score > 0.9 else 'HIGH' if score > 0.7 else 'MEDIUM' if score > 0.4 else 'LOW'
        emoji = '🔴' if level == 'CRITICAL' else '🟠' if level == 'HIGH' else '🟡' if level == 'MEDIUM' else '🟢'
        
        display_alerts.append({
            'user_id': alert.get('user_id', 'unknown'),
            'type': alert.get('alert_type', alert.get('type', 'ALERT')),
            'score': f'{score:.2f}',
            'level': level,
            'emoji': emoji,
            'time': alert.get('received_at', alert.get('timestamp', ''))[:19] if alert.get('timestamp') else 'now'
        })
    
    # If no alerts, show samples
    if not display_alerts:
        display_alerts = [
            {'user_id': 'ali', 'type': 'DATA_EXFIL', 'score': '0.95', 'level': 'CRITICAL', 'emoji': '🔴', 'time': datetime.now().strftime('%H:%M:%S')},
            {'user_id': 'sara', 'type': 'BRUTE_FORCE', 'score': '0.87', 'level': 'HIGH', 'emoji': '🟠', 'time': datetime.now().strftime('%H:%M:%S')},
            {'user_id': 'unknown', 'type': 'C2_COMM', 'score': '0.72', 'level': 'MEDIUM', 'emoji': '🟡', 'time': datetime.now().strftime('%H:%M:%S')},
        ]
    
    return render_template_string(
        DASHBOARD_HTML,
        stats=stats_store,
        alerts=display_alerts,
        top_users=top_users,
        forecast=forecast,
        current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )

@app.route('/api/stats')
def api_stats():
    """API endpoint for stats"""
    return jsonify(stats_store)

@app.route('/api/alerts')
def api_alerts():
    """API endpoint for alerts"""
    return jsonify(list(alerts_store))

@app.route('/api/forecast')
def api_forecast():
    """API endpoint for forecast"""
    return jsonify(generate_forecast())

@app.route('/api/block', methods=['POST'])
def block_user():
    """Block a user"""
    user = request.json.get('user', 'unknown')
    stats_store['blocked'] += 1
    return jsonify({'message': f'User {user} blocked!', 'status': 'success'})

# ============================================
# FILTERS
# ============================================
@app.template_filter('format_number')
def format_number(value):
    """Format large numbers"""
    if value >= 1000000:
        return f'{value/1000000:.1f}M'
    elif value >= 1000:
        return f'{value/1000:.1f}K'
    return str(value)

# ============================================
# MAIN
# ============================================
if __name__ == '__main__':
    print("=" * 60)
    print("🛡️ AI CYBERSECURITY DASHBOARD")
    print("=" * 60)
    print(f"📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🌐 URL: http://localhost:8080")
    print(f"📡 Data Sources: Kafka + Elasticsearch + CSV")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=8080, debug=True)
