import json
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
from kafka import KafkaConsumer, KafkaProducer

class UEBAAnalyzer:
    """User and Entity Behavior Analytics - Real-Time"""

    def __init__(self):
        # Dynamic user profiles (Kafka se seekhega)
        self.user_profiles = defaultdict(lambda: {
            'login_hours': [],
            'files_accessed': [],
            'upload_mb': [],
            'locations': defaultdict(int),
            'devices': defaultdict(int),
            'actions': defaultdict(int),
            'total_events': 0,
            'first_seen': datetime.now(),
            'last_seen': datetime.now(),
            'threat_count': 0
        })

        # Anomaly thresholds
        self.thresholds = {
            'time_deviation': 3,
            'files_multiplier': 3,
            'upload_multiplier': 5,
            'new_location_score': 25,
            'new_device_score': 20,
            'off_hours_score': 30,
            'high_files_score': 35,
            'high_upload_score': 25,
            'anomaly_threshold': 50  # Thoda lower for demo
        }

        # Kafka setup
        self.consumer = KafkaConsumer(
            'user-activity',
            bootstrap_servers='localhost:9093',
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            auto_offset_reset='latest'
        )

        self.producer = KafkaProducer(
            bootstrap_servers='localhost:9093',
            value_serializer=lambda x: json.dumps(x, default=str).encode('utf-8')
        )

        print("=" * 60)
        print("🧠 UEBA ANALYZER - Real-Time Behavior Analytics")
        print("=" * 60)
        print(f"📡 Listening: user-activity topic")
        print(f"🚨 Alerting: threat-alerts topic")
        print(f"⚡ Threshold: {self.thresholds['anomaly_threshold']}")
        print(f"📚 Learning: First 10 events per user")
        print("=" * 60)

    def update_profile(self, user_id, activity):
        """Learn user behavior from each event"""
        profile = self.user_profiles[user_id]
        timestamp = datetime.fromisoformat(activity.get('timestamp', datetime.now().isoformat()))

        profile['login_hours'].append(timestamp.hour)
        profile['files_accessed'].append(activity.get('files_accessed', 0))
        profile['upload_mb'].append(activity.get('data_uploaded_mb', 0))
        profile['locations'][activity.get('location', 'Unknown')] += 1
        profile['devices'][activity.get('device', 'unknown')] += 1
        profile['actions'][activity.get('action', 'unknown')] += 1
        profile['total_events'] += 1
        profile['last_seen'] = timestamp

        # Keep only last 1000 events
        if len(profile['login_hours']) > 1000:
            profile['login_hours'] = profile['login_hours'][-1000:]
            profile['files_accessed'] = profile['files_accessed'][-1000:]
            profile['upload_mb'] = profile['upload_mb'][-1000:]

    def get_baseline(self, user_id):
        """Calculate normal behavior baseline"""
        profile = self.user_profiles[user_id]

        if profile['total_events'] < 10:
            return None

        usual_location = max(profile['locations'], key=profile['locations'].get) if profile['locations'] else 'Unknown'
        usual_device = max(profile['devices'], key=profile['devices'].get) if profile['devices'] else 'unknown'

        return {
            'avg_login_hour': np.mean(profile['login_hours']),
            'std_login_hour': np.std(profile['login_hours']) if len(profile['login_hours']) > 1 else 1,
            'avg_files': np.mean(profile['files_accessed']),
            'std_files': np.std(profile['files_accessed']) if len(profile['files_accessed']) > 1 else 1,
            'avg_upload': np.mean(profile['upload_mb']),
            'usual_location': usual_location,
            'usual_device': usual_device,
            'total_events': profile['total_events']
        }

    def analyze_activity(self, user_id, activity):
        """Score an activity for anomalies"""
        baseline = self.get_baseline(user_id)

        if not baseline:
            return {
                'user_id': user_id,
                'anomaly_score': 0,
                'is_anomaly': False,
                'reasons': ['Learning phase - need 10+ events'],
                'activity_summary': {
                    'action': activity.get('action', 'unknown'),
                    'files': activity.get('files_accessed', 0),
                    'location': activity.get('location', 'unknown'),
                    'device': activity.get('device', 'unknown'),
                    'hour': datetime.fromisoformat(activity.get('timestamp', datetime.now().isoformat())).hour
                }
            }

        score = 0
        reasons = []
        current_hour = datetime.fromisoformat(
            activity.get('timestamp', datetime.now().isoformat())
        ).hour

        # 1. Time anomaly
        time_diff = abs(current_hour - baseline['avg_login_hour'])
        if time_diff > self.thresholds['time_deviation']:
            score += self.thresholds['off_hours_score']
            reasons.append(f"⏰ Off-hours: {current_hour}h (usual: {baseline['avg_login_hour']:.0f}h)")

        # 2. Files anomaly
        files = activity.get('files_accessed', 0)
        if files > baseline['avg_files'] * self.thresholds['files_multiplier']:
            score += self.thresholds['high_files_score']
            reasons.append(f"📁 High files: {files} (avg: {baseline['avg_files']:.0f})")

        # 3. Upload anomaly
        upload = activity.get('data_uploaded_mb', 0)
        if upload > baseline['avg_upload'] * self.thresholds['upload_multiplier']:
            score += self.thresholds['high_upload_score']
            reasons.append(f"📤 High upload: {upload}MB (avg: {baseline['avg_upload']:.0f}MB)")

        # 4. New location
        if activity.get('location') != baseline['usual_location']:
            score += self.thresholds['new_location_score']
            reasons.append(f"🌍 New location: {activity.get('location')} (usual: {baseline['usual_location']})")

        # 5. New device
        if activity.get('device') != baseline['usual_device']:
            score += self.thresholds['new_device_score']
            reasons.append(f"💻 New device: {activity.get('device')} (usual: {baseline['usual_device']})")

        # 6. Login attempts
        if activity.get('login_attempts', 1) > 3:
            score += 20
            reasons.append(f"🔑 Multiple logins: {activity.get('login_attempts')}")

        # 7. Foreign IP
        if activity.get('foreign_ip', 0) == 1:
            score += 15
            reasons.append(f"🌐 Foreign IP detected")

        is_anomaly = score >= self.thresholds['anomaly_threshold']

        return {
            'user_id': user_id,
            'anomaly_score': score,
            'is_anomaly': is_anomaly,
            'reasons': reasons,
            'baseline': baseline,
            'activity_summary': {
                'action': activity.get('action'),
                'files': files,
                'location': activity.get('location'),
                'device': activity.get('device'),
                'hour': current_hour
            }
        }

    def run(self):
        """Main loop"""
        print("🔄 Running... (Ctrl+C to stop)\n")

        stats = {'total': 0, 'anomalies': 0, 'users_tracked': 0}

        try:
            for msg in self.consumer:
                activity = msg.value
                user_id = activity.get('user_id', 'unknown')

                # Update & analyze
                self.update_profile(user_id, activity)
                result = self.analyze_activity(user_id, activity)

                stats['total'] += 1
                stats['users_tracked'] = len(self.user_profiles)

                if result['is_anomaly']:
                    stats['anomalies'] += 1

                    # Create alert
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'alert_type': 'UEBA_ANOMALY',
                        'user_id': user_id,
                        'anomaly_score': result['anomaly_score'],
                        'reasons': result['reasons'],
                        'activity': result['activity_summary'],
                        'baseline': {
                            'avg_files': round(result['baseline']['avg_files'], 1),
                            'usual_location': result['baseline']['usual_location'],
                            'total_events': result['baseline']['total_events']
                        }
                    }

                    self.producer.send('threat-alerts', value=alert)
                    self.user_profiles[user_id]['threat_count'] += 1

                    print(f"🚨 UEBA ALERT [{user_id}] Score: {result['anomaly_score']}/100")
                    for reason in result['reasons']:
                        print(f"   {reason}")
                    print()

                else:
                    # Show 10% of normal events for visibility
                    if stats['total'] % 10 == 0:
                        if result['reasons'][0].startswith('Learning'):
                            progress = self.user_profiles[user_id]['total_events']
                            print(f"📚 [{user_id}] Learning ({progress}/10 events) | Users: {stats['users_tracked']}")
                        else:
                            print(f"✅ [{user_id}] Normal | Score: {result['anomaly_score']} | "
                                  f"Files: {result['activity_summary']['files']} | "
                                  f"Users: {stats['users_tracked']}")

                # Stats every 50 events
                if stats['total'] % 50 == 0:
                    print(f"\n📊 STATS: {stats['total']} events | "
                          f"{stats['anomalies']} anomalies | "
                          f"{stats['users_tracked']} users\n")

        except KeyboardInterrupt:
            print(f"\n\n🛑 UEBA Stopped")
            print("=" * 60)
            print(f"📊 FINAL STATS:")
            print(f"   Total events processed: {stats['total']}")
            print(f"   Anomalies detected: {stats['anomalies']}")
            print(f"   Users tracked: {stats['users_tracked']}")
            print(f"   Anomaly rate: {100*stats['anomalies']/max(1,stats['total']):.1f}%")
            print("=" * 60)

if __name__ == "__main__":
    analyzer = UEBAAnalyzer()
    analyzer.run()
