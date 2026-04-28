# ~/cybersec-platform/ml/training/create_noisy_dataset.py

import pandas as pd
import numpy as np
import random

def create_noisy_dataset(n_samples=10000):
    """
    Realistic dataset with OVERLAP between normal and threat
    """
    data = []
    users = ['ali', 'sara', 'ahmed', 'fatima', 'usman']

    for i in range(n_samples):
        is_threat = random.random() < 0.10

        if is_threat:
            # THREAT - but mixed patterns
            threat_style = random.choice(['noisy_normal', 'slightly_high', 'extreme', 'odd_hours'])

            if threat_style == 'noisy_normal':
                # Looks EXACTLY like normal user but is threat
                record = {
                    'hour_of_day': random.randint(8, 18),
                    'files_accessed': random.randint(10, 80),
                    'login_attempts': random.randint(1, 2),
                    'foreign_ip': 0,
                    'unknown_device': 0,
                    'data_uploaded_mb': random.randint(5, 40),
                    'is_threat': 1
                }
            elif threat_style == 'slightly_high':
                # Thoda sa unusual
                record = {
                    'hour_of_day': random.randint(7, 20),
                    'files_accessed': random.randint(80, 300),
                    'login_attempts': random.randint(1, 4),
                    'foreign_ip': random.choice([0, 0, 1]),
                    'unknown_device': random.choice([0, 0, 1]),
                    'data_uploaded_mb': random.randint(40, 200),
                    'is_threat': 1
                }
            elif threat_style == 'extreme':
                # Obviously threat
                record = {
                    'hour_of_day': random.randint(0, 6),
                    'files_accessed': random.randint(1000, 10000),
                    'login_attempts': random.randint(8, 20),
                    'foreign_ip': 1,
                    'unknown_device': 1,
                    'data_uploaded_mb': random.randint(500, 5000),
                    'is_threat': 1
                }
            else:  # odd_hours
                record = {
                    'hour_of_day': random.choice([0,1,2,3,4,5,22,23]),
                    'files_accessed': random.randint(10, 200),
                    'login_attempts': random.randint(1, 5),
                    'foreign_ip': random.choice([0, 1]),
                    'unknown_device': random.choice([0, 1]),
                    'data_uploaded_mb': random.randint(20, 300),
                    'is_threat': 1
                }
        else:
            # NORMAL - with occasional outliers
            normal_style = random.choice(['typical', 'busy', 'late_worker', 'traveler'])

            if normal_style == 'typical':
                record = {
                    'hour_of_day': random.randint(9, 17),
                    'files_accessed': random.randint(5, 50),
                    'login_attempts': 1,
                    'foreign_ip': 0,
                    'unknown_device': 0,
                    'data_uploaded_mb': random.randint(1, 20),
                    'is_threat': 0
                }
            elif normal_style == 'busy':
                # Busy employee - high but normal
                record = {
                    'hour_of_day': random.randint(8, 19),
                    'files_accessed': random.randint(100, 500),  # HIGH!
                    'login_attempts': random.randint(1, 3),
                    'foreign_ip': 0,
                    'unknown_device': 0,
                    'data_uploaded_mb': random.randint(50, 300),
                    'is_threat': 0
                }
            elif normal_style == 'late_worker':
                # Working late - suspicious hours but normal
                record = {
                    'hour_of_day': random.choice([21,22,23,0,1,5,6]),
                    'files_accessed': random.randint(10, 80),
                    'login_attempts': random.randint(1, 3),
                    'foreign_ip': 0,
                    'unknown_device': 0,
                    'data_uploaded_mb': random.randint(5, 50),
                    'is_threat': 0
                }
            else:  # traveler
                # Traveling - foreign IP but normal
                record = {
                    'hour_of_day': random.randint(7, 22),
                    'files_accessed': random.randint(5, 40),
                    'login_attempts': random.randint(1, 2),
                    'foreign_ip': 1,  # FOREIGN!
                    'unknown_device': random.choice([0, 0, 1]),
                    'data_uploaded_mb': random.randint(1, 30),
                    'is_threat': 0
                }

        data.append(record)

    df = pd.DataFrame(data)
    df.to_csv('security_dataset_noisy.csv', index=False)

    print(f"✅ Noisy dataset: {len(df)} records")
    print(f"🚨 Threats: {df['is_threat'].sum()} ({100*df['is_threat'].sum()/len(df):.1f}%)")

    print(f"\n🔀 OVERLAP ANALYSIS:")
    print(f"  Threats looking normal (files<100): {len(df[(df['is_threat']==1)&(df['files_accessed']<100)])}")
    print(f"  Normals looking suspicious (files>200): {len(df[(df['is_threat']==0)&(df['files_accessed']>200)])}")
    print(f"  Threats with local IP: {len(df[(df['is_threat']==1)&(df['foreign_ip']==0)])}")
    print(f"  Normals with foreign IP: {len(df[(df['is_threat']==0)&(df['foreign_ip']==1)])}")
    print(f"  Late night normals: {len(df[(df['is_threat']==0)&(df['hour_of_day'].isin([0,1,2,3,4,5]))])}")

    return df

create_noisy_dataset()
