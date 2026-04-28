# ~/cybersec-platform/ml/training/create_dataset.py

import pandas as pd
import numpy as np
import random
from datetime import datetime

def create_security_dataset(n_samples=10000):
    data = []
    
    users = ['ali', 'sara', 'ahmed', 'fatima', 'usman']
    actions = ['login', 'logout', 'file_access', 'download', 'upload']
    locations_normal = ['Pakistan', 'Pakistan', 'Pakistan', 'UAE', 'UK']  # Weighted
    locations_suspicious = ['Russia', 'China', 'North Korea', 'Iran']
    devices = ['laptop', 'mobile', 'unknown']
    
    for i in range(n_samples):
        is_threat = random.random() < 0.15  # 15% threats matching your log generator
        
        if is_threat:
            # Suspicious - matches your generate_suspicious_log()
            timestamp = datetime.now().replace(
                hour=random.randint(0, 5),  # Raat ko
                minute=random.randint(0, 59)
            )
            record = {
                'timestamp': timestamp.isoformat(),
                'user_id': random.choice(users),
                'ip_address': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                'action': random.choice(['download', 'upload']),
                'files_accessed': random.randint(1000, 10000),  # Bohot zyada
                'location': random.choice(locations_suspicious),
                'device': random.choice(['unknown', 'unknown', 'mobile']),  # Mostly unknown
                'success': random.choice([True, False, False]),  # Mostly fail
                
                # ML Features
                'hour_of_day': random.randint(0, 5),
                'login_attempts': random.randint(5, 20),
                'foreign_ip': 1,
                'unknown_device': 1,
                'data_uploaded_mb': random.randint(500, 5000),
                'is_threat': 1
            }
        else:
            # Normal - matches your generate_log()
            timestamp = datetime.now().replace(
                hour=random.randint(8, 18),  # Office hours
                minute=random.randint(0, 59)
            )
            record = {
                'timestamp': timestamp.isoformat(),
                'user_id': random.choice(users),
                'ip_address': f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
                'action': random.choice(actions),
                'files_accessed': random.randint(1, 100),
                'location': random.choice(locations_normal),
                'device': random.choice(['laptop', 'mobile', 'laptop', 'laptop']),  # Mostly laptop
                'success': random.choice([True, True, True, False]),  # Mostly true
                
                # ML Features
                'hour_of_day': random.randint(8, 18),
                'login_attempts': random.randint(1, 2),
                'foreign_ip': 0,
                'unknown_device': 0,
                'data_uploaded_mb': random.randint(1, 50),
                'is_threat': 0
            }
        data.append(record)
    
    df = pd.DataFrame(data)
    df.to_csv('security_dataset.csv', index=False)
    
    print(f"✅ Dataset ready: {len(df)} records")
    print(f"🚨 Threats: {df['is_threat'].sum()} ({100*df['is_threat'].sum()/len(df):.1f}%)")
    print(f"✅ Normal:  {len(df) - df['is_threat'].sum()}")
    print(f"\n📊 Features: {list(df.columns)}")
    print(f"\n📋 Sample threat:")
    print(df[df['is_threat']==1].head(1).to_dict('records')[0])
    print(f"\n📋 Sample normal:")
    print(df[df['is_threat']==0].head(1).to_dict('records')[0])
    
    return df

if __name__ == "__main__":
    create_security_dataset()
