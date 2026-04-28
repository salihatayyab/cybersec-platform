#!/usr/bin/env python3
"""
🔍 Automated User Investigation Tool
Multi-source: Elasticsearch, Kafka, CSV
Generates risk score + behavioral analysis + recommendations
"""

import pandas as pd
import numpy as np
import json
import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

# Optional imports
try:
    from elasticsearch import Elasticsearch
    HAS_ES = True
except:
    HAS_ES = False

try:
    from kafka import KafkaConsumer
    HAS_KAFKA = True
except:
    HAS_KAFKA = False

# ============================================
# CONFIGURATION
# ============================================
RISK_WEIGHTS = {
    'night_activity': 25,      # Raat 12-5AM activity
    'foreign_location': 20,    # Pakistan se bahar
    'high_files': 30,          # 1000+ files
    'unknown_device': 15,      # Unknown device
    'multiple_logins': 10,     # 5+ login attempts
    'high_upload': 15,         # 500MB+ upload
    'foreign_ip': 20,          # Foreign IP
    'new_location': 20,        # Naya location
    'off_hours': 15,           # Unusual hours
}

THREAT_THRESHOLDS = {
    'CRITICAL': 80,
    'HIGH': 60,
    'MEDIUM': 40,
    'LOW': 20
}

# ============================================
# DATA LOADER
# ============================================
class DataLoader:
    def __init__(self):
        self.data = None
        self.source = None

    def load(self):
        """Try multiple data sources"""
        methods = [
            self._from_elasticsearch,
            self._from_csv,
            self._from_kafka,
        ]

        for method in methods:
            try:
                result = method()
                if result is not None and len(result) > 0:
                    self.data = result
                    return True
            except Exception as e:
                continue

        return False

    def _from_elasticsearch(self):
        if not HAS_ES:
            return None
        es = Elasticsearch(['http://localhost:9200'])
        if not es.ping():
            return None
        result = es.search(
            index='security-logs',
            body={"query": {"match_all": {}}, "size": 5000}
        )
        hits = result['hits']['hits']
        if hits:
            self.source = 'Elasticsearch'
            return pd.DataFrame([h['_source'] for h in hits])
        return None

    def _from_csv(self):
        paths = [
            '../ml/training/security_dataset.csv',
            '../ml/training/security_dataset_noisy.csv',
            './security_dataset.csv'
        ]
        for path in paths:
            if os.path.exists(path):
                self.source = f'CSV ({os.path.basename(path)})'
                return pd.read_csv(path)
        return None

    def _from_kafka(self):
        if not HAS_KAFKA:
            return None
        consumer = KafkaConsumer(
            'user-activity',
            bootstrap_servers='localhost:9093',
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            consumer_timeout_ms=5000,
            max_poll_records=500,
            auto_offset_reset='earliest'
        )
        messages = []
        for msg in consumer:
            messages.append(msg.value)
            if len(messages) >= 500:
                break
        if messages:
            self.source = f'Kafka ({len(messages)} messages)'
            return pd.DataFrame(messages)
        return None


# ============================================
# RISK CALCULATOR
# ============================================
class RiskCalculator:
    def __init__(self, weights=RISK_WEIGHTS):
        self.weights = weights
        self.risk_factors = []
        self.total_score = 0

    def analyze(self, user_data):
        """Analyze user activity and calculate risk"""
        self.risk_factors = []
        self.total_score = 0

        # 1. Night Activity (12AM-5AM)
        night_hours = [0, 1, 2, 3, 4, 5]
        if 'hour_of_day' in user_data.columns:
            night_count = len(user_data[user_data['hour_of_day'].isin(night_hours)])
            night_pct = 100 * night_count / len(user_data)
            if night_pct > 30:
                score = self.weights['night_activity']
                self.risk_factors.append({
                    'factor': 'Night Activity',
                    'detail': f'{night_pct:.0f}% activity at night (12-5AM)',
                    'score': score,
                    'severity': 'HIGH'
                })
                self.total_score += score

        # 2. Foreign Location
        if 'location' in user_data.columns:
            foreign = user_data[user_data['location'] != 'Pakistan']
            foreign_pct = 100 * len(foreign) / len(user_data)
            if foreign_pct > 20:
                score = self.weights['foreign_location']
                risk_countries = ['Russia', 'China', 'North Korea', 'Iran']
                high_risk = foreign[foreign['location'].isin(risk_countries)]

                self.risk_factors.append({
                    'factor': 'Foreign Location',
                    'detail': f'{foreign_pct:.0f}% foreign access',
                    'score': score + (10 if len(high_risk) > 0 else 0),
                    'severity': 'CRITICAL' if len(high_risk) > 0 else 'HIGH',
                    'locations': foreign['location'].value_counts().to_dict() if len(foreign) > 0 else {}
                })
                self.total_score += score
                if len(high_risk) > 0:
                    self.total_score += 10

        # 3. High File Access
        if 'files_accessed' in user_data.columns:
            avg_files = user_data['files_accessed'].mean()
            max_files = user_data['files_accessed'].max()
            high_file_count = len(user_data[user_data['files_accessed'] > 1000])

            if max_files > 5000:
                score = self.weights['high_files']
                self.risk_factors.append({
                    'factor': 'Excessive File Access',
                    'detail': f'Max {max_files:.0f} files, Avg {avg_files:.0f}, {high_file_count} events >1000',
                    'score': score,
                    'severity': 'CRITICAL'
                })
                self.total_score += score
            elif max_files > 1000:
                score = self.weights['high_files'] // 2
                self.risk_factors.append({
                    'factor': 'High File Access',
                    'detail': f'Max {max_files:.0f} files, Avg {avg_files:.0f}',
                    'score': score,
                    'severity': 'MEDIUM'
                })
                self.total_score += score

        # 4. Unknown Device
        if 'unknown_device' in user_data.columns:
            unknown_count = user_data['unknown_device'].sum()
            unknown_pct = 100 * unknown_count / len(user_data)
            if unknown_pct > 30:
                score = self.weights['unknown_device']
                self.risk_factors.append({
                    'factor': 'Unknown Device',
                    'detail': f'{unknown_pct:.0f}% from unknown devices',
                    'score': score,
                    'severity': 'HIGH'
                })
                self.total_score += score

        # 5. Multiple Login Attempts
        if 'login_attempts' in user_data.columns:
            high_attempts = len(user_data[user_data['login_attempts'] > 5])
            if high_attempts > 0:
                score = min(self.weights['multiple_logins'], high_attempts * 2)
                self.risk_factors.append({
                    'factor': 'Multiple Logins',
                    'detail': f'{high_attempts} events with >5 login attempts',
                    'score': score,
                    'severity': 'MEDIUM'
                })
                self.total_score += score

        # 6. High Data Upload
        if 'data_uploaded_mb' in user_data.columns:
            high_upload = len(user_data[user_data['data_uploaded_mb'] > 500])
            if high_upload > 0:
                avg_upload = user_data['data_uploaded_mb'].mean()
                score = self.weights['high_upload']
                self.risk_factors.append({
                    'factor': 'High Data Upload',
                    'detail': f'{high_upload} events >500MB, Avg {avg_upload:.0f}MB',
                    'score': score,
                    'severity': 'HIGH' if avg_upload > 1000 else 'MEDIUM'
                })
                self.total_score += score

        # 7. Foreign IP
        if 'foreign_ip' in user_data.columns:
            foreign_ips = user_data['foreign_ip'].sum()
            foreign_ip_pct = 100 * foreign_ips / len(user_data)
            if foreign_ip_pct > 20:
                score = self.weights['foreign_ip']
                self.risk_factors.append({
                    'factor': 'Foreign IP',
                    'detail': f'{foreign_ip_pct:.0f}% from foreign IPs',
                    'score': score,
                    'severity': 'HIGH'
                })
                self.total_score += score

        # Sort by score
        self.risk_factors.sort(key=lambda x: x['score'], reverse=True)

        return self.get_verdict()

    def get_verdict(self):
        """Get risk level based on total score"""
        score = min(100, self.total_score)

        if score >= THREAT_THRESHOLDS['CRITICAL']:
            level = 'CRITICAL'
            emoji = '🔴'
            action = 'IMMEDIATE BLOCK + Investigation'
        elif score >= THREAT_THRESHOLDS['HIGH']:
            level = 'HIGH'
            emoji = '🟠'
            action = 'Block suspicious activity, enable MFA'
        elif score >= THREAT_THRESHOLDS['MEDIUM']:
            level = 'MEDIUM'
            emoji = '🟡'
            action = 'Monitor closely, review access'
        elif score >= THREAT_THRESHOLDS['LOW']:
            level = 'LOW'
            emoji = '🟢'
            action = 'Continue routine monitoring'
        else:
            level = 'CLEAN'
            emoji = '✅'
            action = 'No action needed'

        return {
            'total_score': score,
            'risk_level': level,
            'emoji': emoji,
            'action': action,
            'risk_factors': self.risk_factors
        }


# ============================================
# REPORT GENERATOR
# ============================================
class ReportGenerator:
    def __init__(self, user_id, user_data, verdict, source):
        self.user_id = user_id
        self.user_data = user_data
        self.verdict = verdict
        self.source = source

    def generate(self):
        """Generate comprehensive investigation report"""
        report = []
        report.append("=" * 70)
        report.append("🔍 USER INVESTIGATION REPORT")
        report.append("=" * 70)
        report.append(f"🕐 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"👤 User: {self.user_id}")
        report.append(f"📁 Source: {self.source}")
        report.append(f"📊 Records: {len(self.user_data)}")
        report.append("")

        # Risk Verdict
        report.append("=" * 70)
        report.append(f"{self.verdict['emoji']} RISK VERDICT: {self.verdict['risk_level']}")
        report.append("=" * 70)
        report.append(f"  Risk Score: {self.verdict['total_score']}/100")
        report.append(f"  Action: {self.verdict['action']}")
        report.append("")

        # Risk Factors
        if self.verdict['risk_factors']:
            report.append("-" * 70)
            report.append("⚠️  RISK FACTORS FOUND:")
            report.append("-" * 70)
            for i, factor in enumerate(self.verdict['risk_factors'], 1):
                sev_emoji = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢'}.get(factor['severity'], '⚪')
                report.append(f"  {i}. [{factor['severity']:8s}] {sev_emoji} {factor['factor']}")
                report.append(f"     {factor['detail']}")
                report.append(f"     Risk Contribution: +{factor['score']}")
                if 'locations' in factor:
                    report.append(f"     Locations: {factor['locations']}")
                report.append("")
        else:
            report.append("  ✅ No significant risk factors found")
            report.append("")

        # Activity Statistics
        report.append("-" * 70)
        report.append("📊 ACTIVITY STATISTICS")
        report.append("-" * 70)

        stats = self._calculate_stats()
        for key, value in stats.items():
            report.append(f"  {key}: {value}")

        report.append("")

        # Behavioral Patterns
        report.append("-" * 70)
        report.append("🧠 BEHAVIORAL PATTERNS")
        report.append("-" * 70)
        patterns = self._analyze_patterns()
        for pattern in patterns:
            report.append(f"  {pattern}")

        report.append("")

        # Recommendations
        report.append("-" * 70)
        report.append("💡 RECOMMENDATIONS")
        report.append("-" * 70)
        recs = self._get_recommendations()
        for i, rec in enumerate(recs, 1):
            report.append(f"  {i}. {rec}")

        report.append("")
        report.append("=" * 70)
        report.append("✅ INVESTIGATION COMPLETE")
        report.append("=" * 70)

        return "\n".join(report)

    def _calculate_stats(self):
        stats = {}
        data = self.user_data

        stats['Total Events'] = len(data)

        if 'hour_of_day' in data.columns:
            stats['Peak Hour'] = f"{data['hour_of_day'].mode().iloc[0] if len(data['hour_of_day'].mode()) > 0 else 'N/A'}:00"
            night_count = len(data[data['hour_of_day'].between(0, 5)])
            stats['Night Activity'] = f"{night_count} events ({100*night_count/len(data):.0f}%)"

        if 'location' in data.columns:
            unique_locs = data['location'].nunique()
            top_loc = data['location'].mode().iloc[0] if len(data['location'].mode()) > 0 else 'N/A'
            stats['Locations'] = f"{unique_locs} unique (Most: {top_loc})"

        if 'files_accessed' in data.columns:
            stats['Avg Files'] = f"{data['files_accessed'].mean():.0f}"
            stats['Max Files'] = f"{data['files_accessed'].max():.0f}"

        if 'threat_score' in data.columns:
            stats['Avg Threat Score'] = f"{data['threat_score'].mean():.2f}"
            stats['Max Threat Score'] = f"{data['threat_score'].max():.2f}"

        if 'device' in data.columns:
            stats['Devices Used'] = str(data['device'].value_counts().to_dict())

        if 'login_attempts' in data.columns:
            stats['Avg Logins'] = f"{data['login_attempts'].mean():.1f}"

        if 'data_uploaded_mb' in data.columns:
            stats['Total Upload'] = f"{data['data_uploaded_mb'].sum():.0f} MB"

        return stats

    def _analyze_patterns(self):
        patterns = []
        data = self.user_data

        # Time pattern
        if 'hour_of_day' in data.columns:
            night_pct = 100 * len(data[data['hour_of_day'].between(0, 5)]) / len(data)
            if night_pct > 30:
                patterns.append(f"🔴 Night owl: {night_pct:.0f}% activity during 12AM-5AM")
            elif night_pct > 10:
                patterns.append(f"🟡 Occasional late work: {night_pct:.0f}% night activity")
            else:
                patterns.append(f"🟢 Normal working hours")

        # Location pattern
        if 'location' in data.columns:
            unique_locs = data['location'].nunique()
            if unique_locs > 3:
                patterns.append(f"🔴 High mobility: {unique_locs} different locations")
            elif unique_locs > 1:
                patterns.append(f"🟡 Travel pattern: {unique_locs} locations")
            else:
                patterns.append(f"🟢 Single location")

        # File access pattern
        if 'files_accessed' in data.columns:
            if data['files_accessed'].std() > 1000:
                patterns.append(f"🔴 Erratic file access (high variance)")
            else:
                patterns.append(f"🟢 Consistent file access pattern")

        # Device pattern
        if 'unknown_device' in data.columns:
            unknown_pct = 100 * data['unknown_device'].sum() / len(data)
            if unknown_pct > 20:
                patterns.append(f"🔴 {unknown_pct:.0f}% unknown devices - possible security bypass")
            elif unknown_pct > 0:
                patterns.append(f"🟡 {unknown_pct:.0f}% unknown devices")
            else:
                patterns.append(f"🟢 All known devices")

        return patterns

    def _get_recommendations(self):
        recs = []
        score = self.verdict['total_score']
        data = self.user_data

        if score >= 80:
            recs.append("🚨 IMMEDIATE: Disable account and initiate security investigation")
            recs.append("📞 Escalate to SOC Manager immediately")

        if score >= 60:
            recs.append("🔐 Enable MFA immediately")
            recs.append("📋 Review all recent activity logs")

        if 'location' in data.columns:
            foreign = data[data['location'].isin(['Russia', 'China', 'North Korea', 'Iran'])]
            if len(foreign) > 0:
                recs.append(f"🌍 Block access from high-risk countries ({len(foreign)} events)")

        if 'files_accessed' in data.columns:
            if data['files_accessed'].max() > 5000:
                recs.append("📁 Review data loss prevention (DLP) policies")

        if 'unknown_device' in data.columns:
            if data['unknown_device'].sum() > 0:
                recs.append("💻 Enforce device compliance policy")

        if not recs:
            recs.append("✅ No immediate action required")

        recs.append("📊 Schedule next review in 24 hours")
        return recs

    def save(self, filename=None):
        """Save report to file"""
        if filename is None:
            filename = f"investigation_{self.user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        report = self.generate()

        # Print to console
        print(report)

        # Save to file
        os.makedirs('reports', exist_ok=True)
        filepath = os.path.join('reports', filename)
        with open(filepath, 'w') as f:
            f.write(report)

        print(f"\n📄 Report saved: {filepath}")
        return filepath


# ============================================
# MAIN INVESTIGATOR
# ============================================
class AutoInvestigator:
    def __init__(self):
        self.loader = DataLoader()
        self.calculator = RiskCalculator()
        print("🔍 Auto-Investigator Initialized")
        print("=" * 50)

    def investigate(self, user_id):
        """Investigate a specific user"""
        print(f"\n🔍 INVESTIGATING: {user_id}")
        print("-" * 50)

        # Load data
        if self.loader.data is None:
            success = self.loader.load()
            if not success:
                print("❌ No data source available!")
                return None

        # Filter user data
        data = self.loader.data
        if 'user_id' in data.columns:
            user_data = data[data['user_id'] == user_id]
        else:
            print(f"❌ No 'user_id' column in data!")
            return None

        if len(user_data) == 0:
            print(f"❌ No records found for user: {user_id}")
            return None

        print(f"✅ Found {len(user_data)} records")

        # Calculate risk
        verdict = self.calculator.analyze(user_data)

        # Generate report
        reporter = ReportGenerator(
            user_id=user_id,
            user_data=user_data,
            verdict=verdict,
            source=self.loader.source
        )

        return reporter.save()

    def investigate_all(self):
        """Investigate all users and rank by risk"""
        print("\n🔍 BATCH INVESTIGATION - ALL USERS")
        print("=" * 50)

        if self.loader.data is None:
            self.loader.load()

        data = self.loader.data

        if data is None or 'user_id' not in data.columns:
            print("❌ No user data available")
            return

        users = data['user_id'].unique()
        print(f"👥 Investigating {len(users)} users...\n")

        results = []
        for user in users:
            user_data = data[data['user_id'] == user]
            verdict = self.calculator.analyze(user_data)
            results.append({
                'user_id': user,
                'score': verdict['total_score'],
                'level': verdict['risk_level'],
                'events': len(user_data)
            })

        # Sort by risk score
        results.sort(key=lambda x: x['score'], reverse=True)

        # Print ranking
        print("\n👤 USER RISK RANKING:")
        print("-" * 60)
        print(f"  {'Rank':<6s} {'User':<15s} {'Score':<8s} {'Level':<12s} {'Events':<8s}")
        print("-" * 60)

        for i, r in enumerate(results, 1):
            emoji = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢','CLEAN':'✅'}.get(r['level'], '⚪')
            print(f"  {i:<6d} {r['user_id']:<15s} {r['score']:<8d} {emoji} {r['level']:<10s} {r['events']:<8d}")

        print("-" * 60)

        # Generate summary report
        critical = [r for r in results if r['level'] == 'CRITICAL']
        high = [r for r in results if r['level'] == 'HIGH']

        if critical:
            print(f"\n🔴 CRITICAL USERS ({len(critical)}): {', '.join(r['user_id'] for r in critical)}")
        if high:
            print(f"🟠 HIGH RISK USERS ({len(high)}): {', '.join(r['user_id'] for r in high)}")

        return results

    def investigate_high_risk(self):
        """Only investigate high-risk users"""
        all_results = self.investigate_all()
        if all_results is None:
            return

        critical = [r for r in all_results if r['level'] in ['CRITICAL', 'HIGH']]

        if not critical:
            print("\n✅ No high-risk users found!")
            return

        print(f"\n🔴 AUTO-INVESTIGATING {len(critical)} HIGH-RISK USERS...")
        for r in critical:
            self.investigate(r['user_id'])


# ============================================
# CLI
# ============================================
if __name__ == "__main__":
    investigator = AutoInvestigator()

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == 'all':
            investigator.investigate_all()
        elif command == 'high-risk':
            investigator.investigate_high_risk()
        elif command == 'user' and len(sys.argv) > 2:
            investigator.investigate(sys.argv[2])
        else:
            print(f"Unknown command: {command}")
            print("Usage:")
            print("  python3 auto_investigator.py all          # Investigate all users")
            print("  python3 auto_investigator.py high-risk    # Only high-risk users")
            print("  python3 auto_investigator.py user <name>  # Specific user")
    else:
        # Default: investigate ali
        print("💡 Tip: Run 'python3 auto_investigator.py all' for batch mode\n")
        investigator.investigate('ali')

        # Also run batch if data available
        if len(investigator.loader.data['user_id'].unique()) > 1:
            print("\n" + "=" * 70)
            investigator.investigate_all()
