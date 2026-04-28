from kafka import KafkaConsumer, KafkaProducer
import json, joblib, numpy as np
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Kafka config - INTERNAL access
KAFKA_SERVER = 'localhost:9093'
INPUT_TOPIC = 'user-activity'
ALERT_TOPIC = 'threat-alerts'

# Consumer
consumer = KafkaConsumer(
    INPUT_TOPIC,
    bootstrap_servers=KAFKA_SERVER,
    value_deserializer=lambda x: json.loads(x.decode('utf-8')),
    auto_offset_reset='latest',
    consumer_timeout_ms=60000
)

# Producer for alerts
producer = KafkaProducer(
    bootstrap_servers=KAFKA_SERVER,
    value_serializer=lambda x: json.dumps(x, default=str).encode('utf-8')
)

# Load model
try:
    model = joblib.load('/home/wind/cybersec-platform/ml/models/rf_model_noisy.pkl')
    print("✅ Loaded: Random Forest Model")
except:
    print("⚠️  Model not found, using threshold-based detection")
    model = None

print("╔══════════════════════════════════════════════╗")
print("║   🔴 REAL-TIME THREAT DETECTOR              ║")
print("║   Kafka: localhost:9093                     ║")
print("║   Input: user-activity                      ║")
print("║   Alerts: threat-alerts                     ║")
print("╚══════════════════════════════════════════════╝")
print("")

alert_count = 0
total_count = 0

for message in consumer:
    try:
        log = message.value

        # Skip test messages
        if log.get('test'):
            continue

        total_count += 1

        # Extract features
        try:
            hour = datetime.fromisoformat(log['timestamp']).hour
        except:
            hour = datetime.now().hour

        files_accessed = log.get('files_accessed', 0)
        login_attempts = log.get('login_attempts', 1)
        location = log.get('location', 'Pakistan')
        device = log.get('device', 'laptop')
        data_mb = log.get('data_mb', 0)

        # Feature engineering
        foreign_ip = 1 if location not in ['Pakistan', 'UAE'] else 0
        unknown_device = 1 if device in ['unknown', 'server', 'tor-node'] else 0

        features = [[
            hour,
            files_accessed,
            login_attempts,
            foreign_ip,
            unknown_device,
            data_mb
        ]]

        # Get threat score
        if model:
            try:
                score = model.predict_proba(features)[0][1]
            except:
                # Fallback: rule-based scoring
                score = 0.0
                if foreign_ip == 1:
                    score += 0.3
                if unknown_device == 1:
                    score += 0.2
                if files_accessed > 1000:
                    score += 0.3
                if login_attempts > 5:
                    score += 0.2
                if hour < 6 or hour > 22:
                    score += 0.1
        else:
            # Rule-based detection
            score = 0.0
            if foreign_ip == 1:
                score += 0.3
            if unknown_device == 1:
                score += 0.2
            if files_accessed > 1000:
                score += 0.3
            if login_attempts > 5:
                score += 0.2
            if hour < 6 or hour > 22:
                score += 0.1

        # Generate alert if high risk
        if score > 0.7:
            alert_count += 1
            alert = {
                'user_id': log['user_id'],
                'threat_score': round(float(score), 3),
                'risk_level': 'HIGH',
                'timestamp': log['timestamp'],
                'action': log.get('action', 'unknown'),
                'location': location,
                'files_accessed': files_accessed,
                'device': device,
                'reason': 'High threat score detected'
            }
            producer.send(ALERT_TOPIC, value=alert)
            producer.flush()

            print(f"🚨 ALERT! [{total_count}] {log['user_id']:8s} | "
                  f"Score: {score:.3f} | {log.get('action','?'):12s} | "
                  f"{location:10s} | {files_accessed:6d} files")
        else:
            print(f"✅ SAFE  [{total_count}] {log['user_id']:8s} | "
                  f"Score: {score:.3f} | {log.get('action','?'):12s} | "
                  f"{location:10s} | {files_accessed:6d} files")

        # Stats every 50
        if total_count % 50 == 0:
            print(f"\n📊 Stats: Total={total_count} | Alerts={alert_count} | "
                  f"Alert Rate={alert_count/total_count*100:.1f}%\n")

    except Exception as e:
        print(f"❌ Error processing message: {e}")
        continue
