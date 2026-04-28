# ~/cybersec-platform/data/log_generator.py

from kafka import KafkaProducer
from faker import Faker
import json, random, time
from datetime import datetime

fake = Faker()
producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda x: json.dumps(x).encode('utf-8')
)

users = ['ali', 'sara', 'ahmed', 'fatima', 'usman']
actions = ['login', 'logout', 'file_access', 'download', 'upload']

def generate_log():
    return {
        'timestamp': datetime.now().isoformat(),
        'user_id': random.choice(users),
        'ip_address': fake.ipv4(),
        'action': random.choice(actions),
        'files_accessed': random.randint(1, 100),
        'location': fake.country(),
        'device': random.choice(['laptop', 'mobile', 'unknown']),
        'success': random.choice([True, True, True, False])
    }

def generate_suspicious_log():
    # Suspicious activity
    return {
        'timestamp': datetime.now().isoformat(),
        'user_id': 'ali',
        'ip_address': fake.ipv4(),
        'action': 'download',
        'files_accessed': random.randint(5000, 10000),  # bohot zyada!
        'location': 'Russia',  # unusual location
        'device': 'unknown',   # unknown device
        'success': True
    }

print("Log generator chalu hai...")
count = 0
while True:
    # Har 20 logs mein 1 suspicious
    if count % 20 == 0:
        log = generate_suspicious_log()
        producer.send('user-activity', value=log)
        print(f"🚨 Suspicious log bheja: {log['user_id']}")
    else:
        log = generate_log()
        producer.send('user-activity', value=log)
        print(f"✅ Normal log bheja: {log['user_id']}")
    
    count += 1
    time.sleep(1)
