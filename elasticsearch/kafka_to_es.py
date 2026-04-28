
from kafka import KafkaConsumer
from elasticsearch import Elasticsearch
import json

consumer = KafkaConsumer(
    'user-activity',
    bootstrap_servers='localhost:9092',
    value_deserializer=lambda x: json.loads(x.decode('utf-8'))
)

es = Elasticsearch(['http://localhost:9200'])

print("Elasticsearch mein save kar raha hun...")
for message in consumer:
    log = message.value
    es.index(index='security-logs', document=log)
    print(f"Saved: {log['user_id']} - {log['action']}")
