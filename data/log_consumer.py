# ~/cybersec-platform/data/log_consumer.py

from kafka import KafkaConsumer
import json

consumer = KafkaConsumer(
    'user-activity',
    bootstrap_servers='localhost:9092',
    value_deserializer=lambda x: json.loads(x.decode('utf-8')),
    auto_offset_reset='earliest'
)

print("Logs sun raha hun...")
for message in consumer:
    log = message.value
    print(f"Mila: {log['user_id']} ne {log['action']} kiya - Files: {log['files_accessed']}")
