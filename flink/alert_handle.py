from kafka import KafkaConsumer
import json

consumer = KafkaConsumer(
    'threat-alerts',
    bootstrap_servers='localhost:9093',
    value_deserializer=lambda x: json.loads(x.decode('utf-8'))
)

print("🔔 Alert system ready...")
for message in consumer:
    alert = message.value
    print(f"""
╔══════════════════════════════════╗
║         🚨 THREAT ALERT!        ║
╠══════════════════════════════════╣
║ User:  {alert['user_id']:<26} ║
║ Score: {alert['threat_score']:<26} ║
║ Time:  {alert['timestamp'][:19]:<26} ║
╚══════════════════════════════════╝
    """)
