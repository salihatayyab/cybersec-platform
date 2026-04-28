#!/usr/bin/env python3
"""
📊 Automated Threat Report Generator
Generates daily/weekly/monthly cybersecurity reports
Sources: Kafka, Elasticsearch, CSV, ML Models
"""

import json
import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import pandas as pd
import numpy as np
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
# DATA COLLECTOR
# ============================================
class DataCollector:
    def __init__(self):
        self.stats = {
            'total_alerts': 0,
            'high_risk_users': 0,
            'threats_blocked': 0,
            'threats_by_type': defaultdict(int),
            'threats_by_user': defaultdict(int),
            'threats_by_hour': defaultdict(int),
            'threats_by_location': defaultdict(int),
            'top_threats': [],
            'alert_timeline': [],
            'model_stats': {}
        }

    def collect_from_kafka(self, topic='threat-alerts', max_messages=500):
        """Collect alerts from Kafka"""
        if not HAS_KAFKA:
            return

        try:
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers='localhost:9093',
                value_deserializer=lambda x: json.loads(x.decode('utf-8')),
                consumer_timeout_ms=5000,
                auto_offset_reset='earliest',
                max_poll_records=max_messages
            )

            print(f"📡 Collecting from Kafka topic: {topic}")

            for msg in consumer:
                alert = msg.value
                self._process_alert(alert)

            print(f"   ✅ Collected {self.stats['total_alerts']} alerts")
        except Exception as e:
            print(f"   ⚠️ Kafka error: {e}")

    def collect_from_elasticsearch(self, index='security-logs', hours=24):
        """Collect alerts from Elasticsearch"""
        if not HAS_ES:
            return

        try:
            es = Elasticsearch(['http://localhost:9200'])
            if not es.ping():
                return

            # Last N hours
            since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()

            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"threat_score": {"gte": 0.5}}},
                            {"range": {"timestamp": {"gte": since}}}
                        ]
                    }
                },
                "size": 1000,
                "sort": [{"threat_score": "desc"}]
            }

            print(f"📡 Querying Elasticsearch (last {hours}h)...")
            result = es.search(index=index, body=query)
            hits = result['hits']['hits']

            for hit in hits:
                alert = hit['_source']
                alert['threat_score'] = alert.get('threat_score', 0.5)
                self._process_alert(alert)

            print(f"   ✅ Collected {len(hits)} alerts from ES")
        except Exception as e:
            print(f"   ⚠️ ES error: {e}")

    def collect_from_csv(self, path='../ml/training/security_dataset.csv'):
        """Collect from CSV dataset"""
        try:
            df = pd.read_csv(path)

            if 'threat_score' in df.columns:
                high_threats = df[df['threat_score'] > 0.5]
            elif 'is_threat' in df.columns:
                high_threats = df[df['is_threat'] == 1]
            else:
                return

            print(f"📡 Loading from CSV: {len(high_threats)} threats")

            for _, row in high_threats.iterrows():
                alert = row.to_dict()
                alert['threat_score'] = alert.get('threat_score', 0.7)
                self._process_alert(alert)
        except Exception as e:
            print(f"   ⚠️ CSV error: {e}")

    def collect_all(self):
        """Try all sources"""
        print("\n📡 COLLECTING THREAT DATA...")
        print("-" * 50)

        # Try Kafka first
        self.collect_from_kafka()

        # Try Elasticsearch
        if self.stats['total_alerts'] == 0:
            self.collect_from_elasticsearch()

        # Fallback to CSV
        if self.stats['total_alerts'] == 0:
            self.collect_from_csv()

        # If nothing, generate sample
        if self.stats['total_alerts'] == 0:
            self._generate_sample_data()

        print(f"\n📊 Total alerts collected: {self.stats['total_alerts']}")
        return self.stats

    def _process_alert(self, alert):
        """Process a single alert"""
        self.stats['total_alerts'] += 1

        # User
        user = alert.get('user_id', alert.get('user', 'unknown'))
        self.stats['threats_by_user'][user] += 1

        # Type
        alert_type = alert.get('alert_type', alert.get('type', 'UNKNOWN'))
        self.stats['threats_by_type'][alert_type] += 1

        # Location
        location = alert.get('location', 'Unknown')
        self.stats['threats_by_location'][location] += 1

        # Time
        timestamp = alert.get('timestamp', datetime.now().isoformat())
        try:
            hour = pd.to_datetime(timestamp).hour
            self.stats['threats_by_hour'][hour] += 1
        except:
            pass

        # Threat score
        score = alert.get('threat_score', alert.get('anomaly_score', 0.5))
        self.stats['alert_timeline'].append({
            'timestamp': timestamp,
            'user': user,
            'score': score,
            'type': alert_type
        })

        # Model info
        model = alert.get('model', alert.get('detector', 'Unknown'))
        self.stats['model_stats'][model] = self.stats['model_stats'].get(model, 0) + 1

    def _generate_sample_data(self):
        """Generate sample data for demo"""
        print("   ⚠️ No data source - generating sample")
        np.random.seed(42)
        users = ['ali', 'sara', 'ahmed', 'fatima', 'usman', 'unknown']
        types = ['DATA_EXFIL', 'BRUTE_FORCE', 'MALWARE', 'PRIVILEGE_ESCALATION', 'UEBA_ANOMALY', 'C2_COMMUNICATION']

        for i in range(47):
            alert = {
                'user_id': np.random.choice(users),
                'alert_type': np.random.choice(types),
                'threat_score': np.random.uniform(0.5, 1.0),
                'location': np.random.choice(['Pakistan', 'Russia', 'China', 'Iran', 'Unknown']),
                'timestamp': (datetime.now() - timedelta(hours=np.random.randint(0, 24))).isoformat()
            }
            self._process_alert(alert)

    def get_summary(self):
        """Get processed summary"""
        # Top threats
        top_users = sorted(self.stats['threats_by_user'].items(),
                          key=lambda x: x[1], reverse=True)[:5]

        self.stats['top_threats'] = [
            {'user': user, 'count': count}
            for user, count in top_users
        ]

        # High risk users (with score if available)
        self.stats['high_risk_users'] = len(top_users)

        # Blocked (high score)
        if self.stats['alert_timeline']:
            blocked = sum(1 for a in self.stats['alert_timeline'] if a.get('score', 0) > 0.8)
            self.stats['threats_blocked'] = blocked

        return self.stats


# ============================================
# REPORT GENERATOR
# ============================================
class ThreatReportGenerator:
    def __init__(self, stats, report_type='daily'):
        self.stats = stats
        self.report_type = report_type
        self.report_time = datetime.now()

    def generate(self):
        """Generate comprehensive report"""
        report = []

        # Header
        report.extend(self._generate_header())

        # Executive Summary
        report.extend(self._generate_executive_summary())

        # Threat Breakdown
        report.extend(self._generate_threat_breakdown())

        # Top Threats
        report.extend(self._generate_top_threats())

        # Timeline Analysis
        report.extend(self._generate_timeline())

        # Model Performance
        report.extend(self._generate_model_stats())

        # Recommendations
        report.extend(self._generate_recommendations())

        # Footer
        report.extend(self._generate_footer())

        return "\n".join(report)

    def _generate_header(self):
        lines = []
        lines.append("╔" + "═" * 68 + "╗")
        lines.append("║" + " " * 15 + "CYBERSECURITY THREAT REPORT" + " " * 23 + "║")
        lines.append("║" + " " * 18 + f"{self.report_type.upper()} ANALYSIS" + " " * 28 + "║")
        lines.append("╠" + "═" * 68 + "╣")
        lines.append("║" + f"  Generated: {self.report_time.strftime('%Y-%m-%d %H:%M:%S')}" + " " * 23 + "║")
        lines.append("║" + f"  Report Type: {self.report_type.capitalize()} Threat Report" + " " * 23 + "║")
        lines.append("║" + f"  Classification: CONFIDENTIAL" + " " * 37 + "║")
        lines.append("╚" + "═" * 68 + "╝")
        lines.append("")
        return lines

    def _generate_executive_summary(self):
        lines = []
        lines.append("┌" + "─" * 68 + "┐")
        lines.append("│" + " " * 22 + "EXECUTIVE SUMMARY" + " " * 27 + "│")
        lines.append("├" + "─" * 68 + "┤")

        total = self.stats['total_alerts']
        high_risk = self.stats['high_risk_users']
        blocked = self.stats['threats_blocked']

        lines.append(f"│  Total Alerts (24h):     {total:>6d}                         │")
        lines.append(f"│  High Risk Users:        {high_risk:>6d}                         │")
        lines.append(f"│  Threats Blocked:        {blocked:>6d}                         │")

        # Risk level
        if total > 100:
            risk_level = "🔴 CRITICAL - Immediate action required"
        elif total > 50:
            risk_level = "🟠 HIGH - Escalate to security team"
        elif total > 20:
            risk_level = "🟡 MEDIUM - Monitor closely"
        else:
            risk_level = "🟢 LOW - Routine monitoring"

        lines.append(f"│  Overall Risk Level:     {risk_level:<30s} │")
        lines.append("└" + "─" * 68 + "┘")
        lines.append("")
        return lines

    def _generate_threat_breakdown(self):
        lines = []
        lines.append("┌" + "─" * 68 + "┐")
        lines.append("│" + " " * 21 + "THREAT BREAKDOWN" + " " * 29 + "│")
        lines.append("├" + "─" * 68 + "┤")

        # By type
        if self.stats['threats_by_type']:
            lines.append("│  📊 By Alert Type:" + " " * 49 + "│")
            for alert_type, count in sorted(self.stats['threats_by_type'].items(),
                                            key=lambda x: x[1], reverse=True)[:5]:
                bar_len = min(30, count * 30 // max(1, max(self.stats['threats_by_type'].values())))
                bar = "█" * bar_len
                lines.append(f"│    {alert_type:<30s} {count:>4d} {bar} │")

        lines.append("│" + " " * 68 + "│")

        # By location
        if self.stats['threats_by_location']:
            lines.append("│  🌍 By Location:" + " " * 51 + "│")
            # Show only non-Pakistan top locations
            foreign = {k:v for k,v in self.stats['threats_by_location'].items() if k != 'Pakistan'}
            for loc, count in sorted(foreign.items(), key=lambda x: x[1], reverse=True)[:3]:
                lines.append(f"│    {loc:<30s} {count:>4d}                │")

        lines.append("└" + "─" * 68 + "┘")
        lines.append("")
        return lines

    def _generate_top_threats(self):
        lines = []
        lines.append("┌" + "─" * 68 + "┐")
        lines.append("│" + " " * 23 + "TOP THREATS" + " " * 33 + "│")
        lines.append("├" + "─" * 68 + "┤")

        for i, threat in enumerate(self.stats['top_threats'][:10], 1):
            user = threat['user']
            count = threat['count']
            severity = "🔴" if count > 10 else "🟠" if count > 5 else "🟡"
            lines.append(f"│  {i:2d}. {severity} {user:<25s} {count:>4d} alerts          │")

        lines.append("└" + "─" * 68 + "┘")
        lines.append("")
        return lines

    def _generate_timeline(self):
        lines = []
        if not self.stats['threats_by_hour']:
            return lines

        lines.append("┌" + "─" * 68 + "┐")
        lines.append("│" + " " * 20 + "HOURLY DISTRIBUTION" + " " * 28 + "│")
        lines.append("├" + "─" * 68 + "┤")

        max_count = max(self.stats['threats_by_hour'].values()) if self.stats['threats_by_hour'] else 1

        for hour in range(24):
            count = self.stats['threats_by_hour'].get(hour, 0)
            bar_len = int(count * 40 / max_count) if max_count > 0 else 0
            bar = "█" * bar_len
            night = " 🌙" if hour < 6 or hour > 22 else ""
            lines.append(f"│  {hour:02d}:00 {bar:<40s} {count:>4d}{night} │")

        lines.append("└" + "─" * 68 + "┘")
        lines.append("")
        return lines

    def _generate_model_stats(self):
        lines = []
        if not self.stats['model_stats']:
            return lines

        lines.append("┌" + "─" * 68 + "┐")
        lines.append("│" + " " * 20 + "DETECTION ENGINES" + " " * 29 + "│")
        lines.append("├" + "─" * 68 + "┤")

        for model, count in self.stats['model_stats'].items():
            lines.append(f"│  🤖 {model:<30s} {count:>4d} detections     │")

        lines.append("└" + "─" * 68 + "┘")
        lines.append("")
        return lines

    def _generate_recommendations(self):
        lines = []
        lines.append("┌" + "─" * 68 + "┐")
        lines.append("│" + " " * 20 + "RECOMMENDED ACTIONS" + " " * 28 + "│")
        lines.append("├" + "─" * 68 + "┤")

        recs = []
        total = self.stats['total_alerts']

        if total > 100:
            recs.append("🔴 CRITICAL: Activate incident response team")
            recs.append("🔴 Block all suspicious IP ranges immediately")

        if total > 50:
            recs.append("🟠 Review high-risk user accounts immediately")
            recs.append("🟠 Enable MFA for all flagged accounts")

        if self.stats['high_risk_users'] > 5:
            recs.append("🟡 Schedule security awareness training")

        recs.extend([
            "📋 Escalate critical findings to SOC Manager",
            "📊 Schedule automated hourly monitoring",
            "🔐 Review and update firewall rules",
            "📁 Backup and secure sensitive data",
            "📈 Generate follow-up report in 24 hours"
        ])

        for i, rec in enumerate(recs[:8], 1):
            lines.append(f"│  {i}. {rec:<60s} │")

        lines.append("└" + "─" * 68 + "┘")
        lines.append("")
        return lines

    def _generate_footer(self):
        lines = []
        lines.append("╔" + "═" * 68 + "╗")
        lines.append("║" + " " * 10 + "Report generated by AI Cybersecurity Platform" + " " * 9 + "║")
        lines.append("║" + " " * 15 + f"© {self.report_time.year} - All Rights Reserved" + " " * 19 + "║")
        lines.append("╚" + "═" * 68 + "╝")
        return lines

    def save(self, filename=None):
        """Save report to file"""
        if filename is None:
            timestamp = self.report_time.strftime('%Y%m%d_%H%M%S')
            filename = f"threat_report_{self.report_type}_{timestamp}.txt"

        report = self.generate()

        # Print
        print(report)

        # Save
        os.makedirs('reports', exist_ok=True)
        filepath = os.path.join('reports', filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report)

        # Also save JSON
        json_path = filepath.replace('.txt', '.json')
        with open(json_path, 'w') as f:
            json.dump(self.stats, f, indent=2, default=str)

        print(f"\n📄 Text report: {filepath}")
        print(f"📄 JSON data:   {json_path}")

        return filepath


# ============================================
# MAIN
# ============================================
def main():
    print("=" * 70)
    print("📊 CYBERSECURITY THREAT REPORT GENERATOR")
    print("=" * 70)

    # Determine report type
    report_type = 'daily'
    if len(sys.argv) > 1:
        report_type = sys.argv[1]

    print(f"📋 Report Type: {report_type.upper()}")
    print()

    # Collect data
    collector = DataCollector()
    stats = collector.collect_all()

    if stats['total_alerts'] == 0:
        print("\n⚠️ No alerts found! Generating sample report...")
        collector._generate_sample_data()
        stats = collector.stats

    # Get summary
    stats = collector.get_summary()

    # Generate report
    generator = ThreatReportGenerator(stats, report_type)
    generator.save()

    print(f"\n✅ {report_type.capitalize()} report generated successfully!")


if __name__ == "__main__":
    main()
