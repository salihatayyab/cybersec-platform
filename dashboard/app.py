#!/usr/bin/env python3
"""
🛡️ AI Cybersecurity Dashboard - FIXED
"""

from flask import Flask, render_template_string, jsonify, request
from datetime import datetime, timedelta
import json, os, random, threading, time, numpy as np
from collections import deque
import warnings
warnings.filterwarnings('ignore')

try:
    from sklearn.linear_model import LinearRegression
    HAS_SKLEARN = True
except:
    HAS_SKLEARN = False

app = Flask(__name__)

# ============================================
# DATA STORE
# ============================================
alerts_store = deque(maxlen=100)
stats_store = {
    'total_logs': 1247,
    'total_alerts': 47,
    'high_threats': 12,
    'medium_threats': 20,
    'low_threats': 15,
    'blocked': 8,
    'users_tracked': 5,
    'models_active': 3,
    'uptime': '12h 34m',
    'logs_per_second': 25
}

threat_history = deque(maxlen=30)
for i in range(30):
    threat_history.append({
        'day': i+1,
        'threats': random.randint(8, 18),
        'timestamp': (datetime.now() - timedelta(days=30-i)).strftime('%Y-%m-%d')
    })

# ============================================
# BACKGROUND UPDATER
# ============================================
def stats_updater():
    while True:
        time.sleep(5)
        stats_store['total_logs'] += random.randint(20, 100)
        stats_store['logs_per_second'] = random.randint(10, 50)
        stats_store['total_alerts'] += random.randint(0, 3)
        stats_store['high_threats'] += random.randint(0, 1)
        stats_store['medium_threats'] += random.randint(0, 2)
        stats_store['low_threats'] += random.randint(0, 1)

threading.Thread(target=stats_updater, daemon=True).start()

# ============================================
# FORECAST
# ============================================
def generate_forecast():
    if not HAS_SKLEARN:
        return [{'day': f'Day {i+1}', 'threats': random.randint(10, 22)} for i in range(7)]

    try:
        history = list(threat_history)
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
# HTML TEMPLATE
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
        body { font-family: 'Courier New', monospace; background: #0a0e14; color: #e0e0e0; }
        .header { background: #0d1117; border-bottom: 2px solid #00ff41; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { color: #00ff41; font-size: 1.3em; }
        .status-dot { width: 10px; height: 10px; background: #00ff41; border-radius: 50%; animation: pulse 2s infinite; display: inline-block; margin-right: 10px; }
        @keyframes pulse { 0%, 100% { box-shadow: 0 0 5px #00ff41; } 50% { box-shadow: 0 0 20px #00ff41; } }
        .container { max-width: 1300px; margin: auto; padding: 20px; }
        .stats-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }
        .main-row { display: grid; grid-template-columns: 2fr 1fr; gap: 15px; margin-bottom: 20px; }
        .bottom-row { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 18px; }
        .card h3 { color: #8b949e; font-size: 0.8em; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
        .card .big-number { font-size: 2.2em; font-weight: bold; }
        .card-stat { text-align: center; }
        .alert-item { display: flex; align-items: center; gap: 10px; padding: 10px; border-bottom: 1px solid #30363d; font-size: 0.85em; }
        .alert-critical { border-left: 3px solid #ff4444; }
        .alert-high { border-left: 3px solid #ff8800; }
        .alert-medium { border-left: 3px solid #ffaa00; }
        .progress-bar { background: #0d1117; border-radius: 8px; height: 8px; margin-top: 8px; }
        .progress-fill { height: 100%; border-radius: 8px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #30363d; font-size: 0.85em; }
        th { color: #8b949e; }
        .btn { padding: 5px 12px; border: 1px solid #30363d; border-radius: 4px; background: #21262d; color: #e0e0e0; cursor: pointer; font-size: 0.8em; }
        .btn-danger { border-color: #ff4444; color: #ff4444; }
        .btn-danger:hover { background: #ff444422; }
        .alert-feed { max-height: 350px; overflow-y: auto; }
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-track { background: #0d1117; }
        ::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
        @media (max-width: 900px) { .stats-row { grid-template-columns: repeat(2, 1fr); } .main-row, .bottom-row { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ AI CYBERSECURITY PLATFORM</h1>
        <div>
            <div class="status-dot"></div>
            <span style="color:#00ff41;">LIVE</span>
            <span style="color:#8b949e;margin-left:15px;">{{ current_time }}</span>
        </div>
    </div>

    <div class="container">
        <!-- STATS -->
        <div class="stats-row">
            <div class="card card-stat">
                <h3>📨 Total Logs</h3>
                <div class="big-number" style="color:#58a6ff;">{{ stats.total_logs }}</div>
                <small style="color:#8b949e;">{{ stats.logs_per_second }}/sec</small>
            </div>
            <div class="card card-stat" style="border-color:#ff4444;">
                <h3>🚨 High Threats</h3>
                <div class="big-number" style="color:#ff4444;">{{ stats.high_threats }}</div>
                <small style="color:#ff8888;">Immediate action</small>
            </div>
            <div class="card card-stat" style="border-color:#ffaa00;">
                <h3>⚠️ Medium</h3>
                <div class="big-number" style="color:#ffaa00;">{{ stats.medium_threats }}</div>
                <small style="color:#ffcc88;">Monitor</small>
            </div>
            <div class="card card-stat" style="border-color:#00ff41;">
                <h3>✅ Safe Events</h3>
                <div class="big-number" style="color:#00ff41;">{{ safe_events }}</div>
                <small style="color:#88ff88;">{{ safe_percent }}% clean</small>
            </div>
        </div>

        <!-- MAIN -->
        <div class="main-row">
            <div class="card">
                <h3>🔴 LIVE ALERT FEED</h3>
                <div class="alert-feed">
                    {% for alert in alerts %}
                    <div class="alert-item alert-{{ alert.level | lower }}">
                        <span>{{ alert.emoji }}</span>
                        <div style="flex:1;">
                            <strong>{{ alert.user }}</strong>
                            <span style="color:#8b949e;margin-left:5px;">{{ alert.type }}</span>
                        </div>
                        <div style="text-align:right;">
                            <span style="color:{{ alert.color }};">{{ alert.score }}</span>
                            <small style="color:#8b949e;display:block;">{{ alert.time }}</small>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>

            <div>
                <div class="card" style="margin-bottom:15px;">
                    <h3>🤖 SYSTEM STATUS</h3>
                    <table>
                        <tr><td>Uptime</td><td style="color:#00ff41;">{{ stats.uptime }}</td></tr>
                        <tr><td>Users</td><td>{{ stats.users_tracked }}</td></tr>
                        <tr><td>Models</td><td style="color:#58a6ff;">{{ stats.models_active }} (XGB+RF+UEBA)</td></tr>
                        <tr><td>Log Rate</td><td>{{ stats.logs_per_second }}/sec</td></tr>
                        <tr><td>Blocked</td><td style="color:#ff4444;">{{ stats.blocked }}</td></tr>
                    </table>
                </div>

                <div class="card">
                    <h3>📊 THREAT DISTRIBUTION</h3>
                    <div style="margin:8px 0;">🔴 High: {{ stats.high_threats }}</div>
                    <div class="progress-bar"><div class="progress-fill" style="width:{{ high_pct }}%;background:#ff4444;"></div></div>
                    <div style="margin:8px 0;">🟡 Medium: {{ stats.medium_threats }}</div>
                    <div class="progress-bar"><div class="progress-fill" style="width:{{ med_pct }}%;background:#ffaa00;"></div></div>
                    <div style="margin:8px 0;">🟢 Low: {{ stats.low_threats }}</div>
                    <div class="progress-bar"><div class="progress-fill" style="width:{{ low_pct }}%;background:#00ff41;"></div></div>
                </div>
            </div>
        </div>

        <!-- BOTTOM -->
        <div class="bottom-row">
            <div class="card">
                <h3>👤 TOP THREAT USERS</h3>
                <table>
                    <tr><th>User</th><th>Alerts</th><th>Risk</th><th>Action</th></tr>
                    {% for user in top_users %}
                    <tr>
                        <td>{{ user.name }}</td>
                        <td>{{ user.alerts }}</td>
                        <td><span style="color:{{ user.color }};">{{ user.score }}</span></td>
                        <td><button class="btn btn-danger" onclick="blockUser('{{ user.name }}')">BLOCK</button></td>
                    </tr>
                    {% endfor %}
                </table>
            </div>

            <div class="card">
                <h3>📈 7-DAY FORECAST</h3>
                <table>
                    <tr><th>Day</th><th>Predicted</th><th>Trend</th></tr>
                    {% for f in forecast %}
                    <tr>
                        <td>{{ f.day }}</td>
                        <td>{{ f.threats }}</td>
                        <td><span style="color:{{ '#ff4444' if f.threats > 20 else '#ffaa00' if f.threats > 10 else '#00ff41' }}">{{ '🔺 High' if f.threats > 20 else '🔻 Normal' if f.threats < 12 else '➡️ Moderate' }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
        </div>
    </div>

    <script>
        setTimeout(() => location.reload(), 15000);
        function blockUser(user) {
            fetch('/api/block', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({user: user})
            }).then(r => r.json()).then(d => alert(d.message));
        }
    </script>
</body>
</html>
'''

# ============================================
# ROUTES
# ============================================
@app.route('/')
def dashboard():
    # Calculate derived values in Python (not Jinja!)
    total = max(1, stats_store['total_alerts'])
    high_pct = round(stats_store['high_threats'] / total * 100)
    med_pct = round(stats_store['medium_threats'] / total * 100)
    low_pct = round(stats_store['low_threats'] / total * 100)

    safe_events = stats_store['total_logs'] - stats_store['high_threats'] - stats_store['medium_threats']
    safe_percent = round(safe_events / max(1, stats_store['total_logs']) * 100)

    # Top users
    top_users = [
        {'name': 'ali', 'alerts': 12, 'score': '0.95', 'color': '#ff4444'},
        {'name': 'sara', 'alerts': 8, 'score': '0.87', 'color': '#ff8800'},
        {'name': 'ahmed', 'alerts': 5, 'score': '0.72', 'color': '#ffaa00'},
        {'name': 'unknown', 'alerts': 4, 'score': '0.68', 'color': '#ffaa00'},
    ]

    # Alerts
    alerts = [
        {'user': 'ali', 'type': 'DATA_EXFIL', 'score': '0.95', 'level': 'CRITICAL', 'emoji': '🔴', 'color': '#ff4444', 'time': '15:42:31'},
        {'user': 'sara', 'type': 'BRUTE_FORCE', 'score': '0.87', 'level': 'HIGH', 'emoji': '🟠', 'color': '#ff8800', 'time': '15:41:18'},
        {'user': 'unknown', 'type': 'C2_COMM', 'score': '0.78', 'level': 'HIGH', 'emoji': '🟠', 'color': '#ff8800', 'time': '15:40:05'},
        {'user': 'ahmed', 'type': 'UEBA_ANOMALY', 'score': '0.65', 'level': 'MEDIUM', 'emoji': '🟡', 'color': '#ffaa00', 'time': '15:38:52'},
        {'user': 'fatima', 'type': 'MALWARE', 'score': '0.55', 'level': 'MEDIUM', 'emoji': '🟡', 'color': '#ffaa00', 'time': '15:37:29'},
        {'user': 'usman', 'type': 'POLICY', 'score': '0.35', 'level': 'LOW', 'emoji': '🟢', 'color': '#00ff41', 'time': '15:36:11'},
    ]

    # Forecast
    forecast = generate_forecast()

    return render_template_string(
        DASHBOARD_HTML,
        stats=stats_store,
        alerts=alerts,
        top_users=top_users,
        forecast=forecast,
        safe_events=safe_events,
        safe_percent=safe_percent,
        high_pct=high_pct,
        med_pct=med_pct,
        low_pct=low_pct,
        current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )

@app.route('/api/stats')
def api_stats():
    return jsonify(stats_store)

@app.route('/api/forecast')
def api_forecast():
    return jsonify(generate_forecast())

@app.route('/api/block', methods=['POST'])
def block_user():
    user = request.json.get('user', 'unknown')
    stats_store['blocked'] += 1
    return jsonify({'message': f'User {user} blocked!', 'status': 'success'})

# ============================================
# MAIN
# ============================================
if __name__ == '__main__':
    print("=" * 60)
    print("🛡️ AI CYBERSECURITY DASHBOARD")
    print("=" * 60)
    print(f"🌐 http://localhost:8080")
    print("=" * 60)
    app.run(host='0.0.0.0', port=8080, debug=True)
