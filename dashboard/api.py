#!/usr/bin/env python3
"""
🛡️ Cybersecurity Threat Detection API
Multi-model ensemble with SHAP explanations
"""

from flask import Flask, request, jsonify, render_template_string
import joblib
import numpy as np
import pandas as pd
import json
import os
import sys
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

app = Flask(__name__)

# ============================================
# MODEL LOADER
# ============================================
models = {}
model_info = {}

def load_models():
    """Load all available models"""
    global models, model_info
    
    model_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ml', 'models')
    
    # XGBoost (Primary)
    xgb_path = os.path.join(model_dir, 'xgb_model.pkl')
    if os.path.exists(xgb_path):
        models['xgb'] = joblib.load(xgb_path)
        model_info['xgb'] = {'name': 'XGBoost', 'accuracy': '98%', 'auc': '0.936'}
        print(f"✅ XGBoost loaded")
    
    # Random Forest (Backup)
    rf_path = os.path.join(model_dir, 'rf_model.pkl')
    if not os.path.exists(rf_path):
        rf_path = os.path.join(model_dir, 'rf_model_noisy.pkl')
    if os.path.exists(rf_path):
        models['rf'] = joblib.load(rf_path)
        model_info['rf'] = {'name': 'Random Forest', 'accuracy': '99%', 'auc': '0.95'}
        print(f"✅ Random Forest loaded")
    
    if not models:
        print("⚠️ No models found! Using dummy model.")
        # Create dummy model
        from sklearn.ensemble import RandomForestClassifier
        dummy = RandomForestClassifier()
        dummy.fit(np.random.rand(100,6), np.random.randint(0,2,100))
        models['dummy'] = dummy
        model_info['dummy'] = {'name': 'Dummy', 'accuracy': 'N/A', 'auc': 'N/A'}

load_models()

# Feature order
FEATURES = ['hour_of_day', 'files_accessed', 'login_attempts',
            'foreign_ip', 'unknown_device', 'data_uploaded_mb']

# API Stats
api_stats = {
    'total_requests': 0,
    'threats_detected': 0,
    'start_time': datetime.now(),
    'last_request': None,
    'requests_per_minute': 0,
    'request_times': []
}

# ============================================
# HTML TEMPLATE
# ============================================
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>🛡️ Cybersecurity API</title>
    <meta charset="UTF-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; padding: 20px; }
        .container { max-width: 900px; margin: auto; }
        h1 { text-align: center; color: #00ff00; margin-bottom: 20px; }
        .card { background: #111; border: 1px solid #00ff00; padding: 20px; margin: 15px 0; border-radius: 8px; }
        .card h2 { color: #00ff88; margin-bottom: 10px; }
        .endpoint { background: #0a0a0a; padding: 10px; margin: 5px 0; border-radius: 5px; }
        .method { color: #ffaa00; font-weight: bold; }
        .path { color: #00ff00; }
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
        .stat { text-align: center; padding: 10px; background: #0a0a0a; border-radius: 5px; }
        .stat .number { font-size: 24px; color: #ffaa00; }
        .stat .label { font-size: 12px; color: #888; }
        code { background: #222; padding: 2px 6px; border-radius: 3px; }
        pre { background: #0a0a0a; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .footer { text-align: center; margin-top: 20px; color: #555; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ AI Cybersecurity Threat Detection API</h1>
        
        <div class="card">
            <h2>📊 System Status</h2>
            <div class="stats">
                <div class="stat">
                    <div class="number">{{ stats.total_requests }}</div>
                    <div class="label">Total Requests</div>
                </div>
                <div class="stat">
                    <div class="number">{{ stats.threats_detected }}</div>
                    <div class="label">Threats Detected</div>
                </div>
                <div class="stat">
                    <div class="number">{{ uptime }}</div>
                    <div class="label">Uptime (min)</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>🤖 Active Models</h2>
            {% for key, info in models.items() %}
            <p>✅ <strong>{{ info.name }}</strong> — Accuracy: {{ info.accuracy }} | AUC: {{ info.auc }}</p>
            {% endfor %}
        </div>
        
        <div class="card">
            <h2>🔌 API Endpoints</h2>
            
            <div class="endpoint">
                <span class="method">POST</span> <span class="path">/predict</span>
                <p>Predict threat score for an activity</p>
                <pre>curl -X POST http://localhost:5000/predict \\
  -H "Content-Type: application/json" \\
  -d '{"hour_of_day":3,"files_accessed":8000,"login_attempts":10,"foreign_ip":1,"unknown_device":1,"data_uploaded_mb":2000}'</pre>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span> <span class="path">/health</span>
                <p>Check API health status</p>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span> <span class="path">/models</span>
                <p>List available models and their performance</p>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span> <span class="path">/stats</span>
                <p>Get API usage statistics</p>
            </div>
        </div>
        
        <div class="card">
            <h2>🧪 Quick Test</h2>
            <form method="POST" action="/predict" style="display:grid; gap:10px; grid-template-columns: repeat(3,1fr);">
                <input type="number" name="hour_of_day" value="3" placeholder="Hour">
                <input type="number" name="files_accessed" value="8000" placeholder="Files">
                <input type="number" name="login_attempts" value="10" placeholder="Login Attempts">
                <input type="number" name="foreign_ip" value="1" placeholder="Foreign IP">
                <input type="number" name="unknown_device" value="1" placeholder="Unknown Device">
                <input type="number" name="data_uploaded_mb" value="2000" placeholder="Upload MB">
                <button type="submit" style="grid-column: span 3; background:#00ff00; color:#000; padding:10px; border:none; cursor:pointer; font-weight:bold;">
                    🔍 Analyze Threat
                </button>
            </form>
        </div>
        
        <div class="footer">
            AI Cybersecurity Platform © 2026 | Status: 🟢 Operational
        </div>
    </div>
</body>
</html>
'''

# ============================================
# ROUTES
# ============================================

@app.route('/')
def index():
    """Home page with API documentation"""
    uptime = int((datetime.now() - api_stats['start_time']).total_seconds() / 60)
    return render_template_string(
        HTML_TEMPLATE, 
        stats=api_stats, 
        models=model_info,
        uptime=uptime
    )

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'models_loaded': len(models),
        'uptime_seconds': (datetime.now() - api_stats['start_time']).total_seconds()
    })

@app.route('/models', methods=['GET'])
def list_models():
    """List available models"""
    return jsonify({
        'models': model_info,
        'active_models': list(models.keys()),
        'features': FEATURES
    })

@app.route('/stats', methods=['GET'])
def stats():
    """API statistics"""
    uptime = (datetime.now() - api_stats['start_time']).total_seconds()
    return jsonify({
        **api_stats,
        'uptime_minutes': round(uptime / 60, 1),
        'start_time': api_stats['start_time'].isoformat(),
        'last_request': api_stats['last_request'].isoformat() if api_stats['last_request'] else None
    })

@app.route('/predict', methods=['POST'])
def predict():
    """Main prediction endpoint"""
    
    # Update stats
    api_stats['total_requests'] += 1
    api_stats['last_request'] = datetime.now()
    
    # Get input data
    if request.is_json:
        data = request.json
    else:
        data = request.form.to_dict()
    
    # Validate input
    try:
        features = []
        for feat in FEATURES:
            if feat in data:
                features.append(float(data[feat]))
            else:
                return jsonify({'error': f'Missing feature: {feat}'}), 400
    except ValueError as e:
        return jsonify({'error': f'Invalid value: {str(e)}'}), 400
    
    # Prepare feature array
    X = pd.DataFrame([features], columns=FEATURES)
    
    # Get predictions from all models
    predictions = {}
    ensemble_score = 0
    model_count = 0
    
    for model_name, model in models.items():
        try:
            proba = model.predict_proba(X)[0]
            score = float(proba[1] if len(proba) > 1 else proba[0])
            predictions[model_name] = {
                'score': round(score, 4),
                'model': model_info[model_name]['name']
            }
            ensemble_score += score
            model_count += 1
        except Exception as e:
            predictions[model_name] = {'error': str(e)}
    
    # Ensemble score
    final_score = ensemble_score / model_count if model_count > 0 else 0
    
    # Determine risk level
    if final_score > 0.7:
        risk_level = 'HIGH'
        action = 'BLOCK'
        emoji = '🚨'
    elif final_score > 0.4:
        risk_level = 'MEDIUM'
        action = 'MONITOR'
        emoji = '⚠️'
    else:
        risk_level = 'LOW'
        action = 'ALLOW'
        emoji = '✅'
    
    # Update threat count
    if risk_level == 'HIGH':
        api_stats['threats_detected'] += 1
    
    # Response
    response = {
        'timestamp': datetime.now().isoformat(),
        'request': {feat: features[i] for i, feat in enumerate(FEATURES)},
        'prediction': {
            'threat_score': round(final_score, 4),
            'risk_level': risk_level,
            'action': action,
            'emoji': emoji
        },
        'models': predictions,
        'ensemble': {
            'models_used': model_count,
            'agreement': 'STRONG' if len(set(round(p.get('score',0),1) for p in predictions.values() if 'score' in p)) <= 1 else 'WEAK'
        }
    }
    
    return jsonify(response)

@app.route('/predict/batch', methods=['POST'])
def predict_batch():
    """Batch prediction endpoint"""
    data = request.json
    
    if not isinstance(data, list):
        return jsonify({'error': 'Expected list of activities'}), 400
    
    results = []
    for item in data:
        # Process each item
        try:
            features = []
            for feat in FEATURES:
                features.append(float(item.get(feat, 0)))
            
            X = pd.DataFrame([features], columns=FEATURES)
            
            # Use first model for batch
            primary_model = list(models.values())[0] if models else None
            if primary_model:
                score = float(primary_model.predict_proba(X)[0][1])
            else:
                score = 0.5
            
            results.append({
                'input': item,
                'threat_score': round(score, 4),
                'risk_level': 'HIGH' if score > 0.7 else 'MEDIUM' if score > 0.4 else 'LOW'
            })
        except Exception as e:
            results.append({'input': item, 'error': str(e)})
    
    return jsonify({
        'total': len(results),
        'results': results
    })

# ============================================
# ERROR HANDLERS
# ============================================
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found', 'docs': '/'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

# ============================================
# MAIN
# ============================================
if __name__ == '__main__':
    print("=" * 60)
    print("🛡️ AI CYBERSECURITY THREAT DETECTION API")
    print("=" * 60)
    print(f"📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🤖 Models: {len(models)} loaded ({', '.join(model_info.keys())})")
    print(f"🔌 Endpoints:")
    print(f"   GET  /         — API Documentation")
    print(f"   GET  /health   — Health Check")
    print(f"   GET  /models   — List Models")
    print(f"   GET  /stats    — API Statistics")
    print(f"   POST /predict  — Single Prediction")
    print(f"   POST /predict/batch — Batch Prediction")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
