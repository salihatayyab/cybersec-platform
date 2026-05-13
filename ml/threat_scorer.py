import joblib
import numpy as np
import pandas as pd
import json
import os
from datetime import datetime
from kafka import KafkaConsumer, KafkaProducer

class ThreatScorer:
    """Ensemble Threat Scoring - XGBoost + Random Forest"""

    def __init__(self):
        # Fix paths - models folder se load karo
        model_dir = os.path.join(os.path.dirname(__file__), 'models')

        print("🔄 Loading models...")
        self.xgb_model = joblib.load(f'{model_dir}/xgb_model_noisy.pkl')
        print("   ✅ XGBoost loaded (98% accuracy, 0.936 AUC)")

        self.rf_model = joblib.load(f'{model_dir}/rf_model_noisy.pkl')
        print("   ✅ Random Forest loaded (99% accuracy)")

        # Model weights based on performance
        self.weights = {
            'xgb': 0.6,  # Better AUC
            'rf': 0.4    # Slightly higher accuracy but overfit
        }

        # Risk thresholds
        self.thresholds = {
            'HIGH': 0.3,
            'MEDIUM': 0.1,
            'LOW': 0.0
        }

    def calculate_score(self, activity):
        """Calculate ensemble threat score"""
        features = pd.DataFrame([[
            activity.get('hour_of_day', 0),
            activity.get('files_accessed', 0),
            activity.get('login_attempts', 1),
            activity.get('foreign_ip', 0),
            activity.get('unknown_device', 0),
            activity.get('data_uploaded_mb', 0)
        ]], columns=['hour_of_day', 'files_accessed', 'login_attempts',
                     'foreign_ip', 'unknown_device', 'data_uploaded_mb'])

        # Get probabilities from both models
        xgb_prob = self.xgb_model.predict_proba(features)[0][1]
        rf_prob = self.rf_model.predict_proba(features)[0][1]

        # Weighted ensemble
        final_score = (xgb_prob * self.weights['xgb'] +
                      rf_prob * self.weights['rf'])

        # Determine risk level
        if final_score > self.thresholds['HIGH']:
            risk_level = 'HIGH'
            action = 'BLOCK'
            emoji = '🚨'
        elif final_score > self.thresholds['MEDIUM']:
            risk_level = 'MEDIUM'
            action = 'MONITOR'
            emoji = '⚠️'
        else:
            risk_level = 'LOW'
            action = 'ALLOW'
            emoji = '✅'

        return {
            'timestamp': datetime.now().isoformat(),
            'threat_score': round(float(final_score), 3),
            'xgb_score': round(float(xgb_prob), 3),
            'rf_score': round(float(rf_prob), 3),
            'risk_level': risk_level,
            'action': action,
            'emoji': emoji,
            'model_agreement': 'STRONG' if abs(xgb_prob - rf_prob) < 0.2 else 'WEAK',
            'features_analyzed': activity
        }

# ============================================
# Real-Time Scoring from Kafka
# ============================================
class RealTimeScorer:
    """Kafka-integrated real-time threat scorer"""

    def __init__(self):
        self.scorer = ThreatScorer()

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

        # Stats
        self.stats = {
            'total': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

        print("\n" + "=" * 60)
        print("🛡️ ENSEMBLE THREAT SCORER - LIVE")
        print("=" * 60)
        print(f"   Models: XGBoost (60%) + Random Forest (40%)")
        print(f"   Thresholds: HIGH>{self.scorer.thresholds['HIGH']}, MEDIUM>{self.scorer.thresholds['MEDIUM']}")
        print("=" * 60)

    def run(self):
        """Main scoring loop"""
        print("🔄 Processing events...\n")

        try:
            for msg in self.consumer:
                activity = msg.value

                # Score the activity
                result = self.scorer.calculate_score(activity)

                # Update stats
                self.stats['total'] += 1
                self.stats[result['risk_level'].lower()] += 1

                # Print based on risk
                user = activity.get('user_id', 'unknown')

                if result['risk_level'] == 'HIGH':
                    # Send alert to Kafka
                    alert = {
                        'type': 'ENSEMBLE_THREAT',
                        **result
                    }
                    self.producer.send('threat-alerts', value=alert)

                    print(f"{result['emoji']} HIGH [{user}] Score: {result['threat_score']:.2f}")
                    print(f"   XGB: {result['xgb_score']:.2f} | RF: {result['rf_score']:.2f}")
                    print(f"   Action: {result['action']} | Agreement: {result['model_agreement']}")
                    print()

                elif result['risk_level'] == 'MEDIUM':
                    if self.stats['total'] % 5 == 0:
                        print(f"{result['emoji']} MEDIUM [{user}] Score: {result['threat_score']:.2f} | "
                              f"Files: {activity.get('files_accessed')} | Location: {activity.get('location')}")

                else:  # LOW
                    if self.stats['total'] % 20 == 0:
                        print(f"{result['emoji']} LOW [{user}] Score: {result['threat_score']:.2f} | "
                              f"Action: {activity.get('action')}")

                # Periodic stats
                if self.stats['total'] % 50 == 0:
                    print(f"\n📊 STATS: {self.stats['total']} scored | "
                          f"🔴{self.stats['high']} 🟡{self.stats['medium']} 🟢{self.stats['low']}\n")

        except KeyboardInterrupt:
            print(f"\n🛑 Scorer Stopped")
            print(f"   Total: {self.stats['total']}")
            print(f"   🔴 HIGH: {self.stats['high']} ({100*self.stats['high']/max(1,self.stats['total']):.1f}%)")
            print(f"   🟡 MEDIUM: {self.stats['medium']} ({100*self.stats['medium']/max(1,self.stats['total']):.1f}%)")
            print(f"   🟢 LOW: {self.stats['low']} ({100*self.stats['low']/max(1,self.stats['total']):.1f}%)")

# ============================================
# Test Mode
# ============================================
def test_scorer():
    """Quick test with sample data"""
    print("=" * 60)
    print("🧪 TESTING THREAT SCORER")
    print("=" * 60)

    scorer = ThreatScorer()

    test_cases = [
        {
            'name': 'Normal Office Worker',
            'data': {
                'hour_of_day': 10, 'files_accessed': 30,
                'login_attempts': 1, 'foreign_ip': 0,
                'unknown_device': 0, 'data_uploaded_mb': 10
            }
        },
        {
            'name': 'Late Night Worker',
            'data': {
                'hour_of_day': 23, 'files_accessed': 200,
                'login_attempts': 2, 'foreign_ip': 0,
                'unknown_device': 0, 'data_uploaded_mb': 100
            }
        },
        {
            'name': 'Suspicious Download',
            'data': {
                'hour_of_day': 3, 'files_accessed': 5000,
                'login_attempts': 10, 'foreign_ip': 1,
                'unknown_device': 1, 'data_uploaded_mb': 2000
            }
        },
        {
            'name': 'Foreign Traveler',
            'data': {
                'hour_of_day': 14, 'files_accessed': 50,
                'login_attempts': 1, 'foreign_ip': 1,
                'unknown_device': 0, 'data_uploaded_mb': 20
            }
        }
    ]

    for test in test_cases:
        result = scorer.calculate_score(test['data'])
        print(f"\n{result['emoji']} {test['name']}:")
        print(f"   Score: {result['threat_score']} | Level: {result['risk_level']} | Action: {result['action']}")
        print(f"   XGB: {result['xgb_score']} | RF: {result['rf_score']} | Agreement: {result['model_agreement']}")

# ============================================
# Main
# ============================================
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        # Test mode
        test_scorer()
    elif len(sys.argv) > 1 and sys.argv[1] == 'live':
        # Live Kafka mode
        scorer = RealTimeScorer()
        scorer.run()
    else:
        # Default: test first, then ask
        test_scorer()
        print("\n" + "=" * 60)
        print("💡 Usage:")
        print("   python3 threat_scorer.py test   → Test mode")
        print("   python3 threat_scorer.py live   → Live Kafka mode")
        print("=" * 60)
