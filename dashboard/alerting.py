import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import json
import os

# Config file se credentials load karo (secure!)
ALERT_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': '',      # ⬅️ Add sender Gmail 
    'sender_password': '',       # ⬅️ Add Gmail App Password 
    'receiver_email': '', # ⬅️ Security team ka email
    'slack_webhook': '',  # Optional: Slack webhook URL
    'teams_webhook': ''   # Optional: Microsoft Teams webhook
}

# File se credentials load karne ke liye (more secure)
def load_config():
    config_file = os.path.expanduser('~/.alert_config.json')
    if os.path.exists(config_file):
        with open(config_file) as f:
            return json.load(f)
    return ALERT_CONFIG


def send_email_alert(threat_data):
    """Send email alert for high threat"""
    config = load_config()

    if not config.get('sender_password') or config['sender_password'] == 'your-app-password':
        print("⚠️  Email not configured. Set credentials in ~/.alert_config.json")
        return False

    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"🚨 THREAT ALERT - {threat_data['user_id']} - Score: {threat_data['threat_score']}"
        msg['From'] = config['sender_email']
        msg['To'] = config['receiver_email']

        # HTML Email body (better looking)
        html_body = f"""
        <html>
        <body style="font-family: Arial; background: #f5f5f5; padding: 20px;">
            <div style="background: #fff; border-left: 5px solid #ff0000; padding: 20px; border-radius: 5px;">
                <h2 style="color: #ff0000;">🚨 Security Threat Detected!</h2>

                <table style="width: 100%; border-collapse: collapse;">
                    <tr><td style="padding: 8px; font-weight: bold;">User ID:</td><td>{threat_data['user_id']}</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold;">Threat Score:</td><td style="color: red; font-size: 24px;">{threat_data['threat_score']}</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold;">Risk Level:</td><td style="color: red;">{threat_data.get('risk_level', 'HIGH')}</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold;">Location:</td><td>{threat_data.get('location', 'N/A')}</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold;">Device:</td><td>{threat_data.get('device', 'N/A')}</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold;">Files Accessed:</td><td>{threat_data.get('files_accessed', 'N/A')}</td></tr>
                    <tr><td style="padding: 8px; font-weight: bold;">Time:</td><td>{threat_data.get('timestamp', datetime.now().isoformat())}</td></tr>
                </table>

                <div style="background: #ffe6e6; padding: 15px; margin-top: 15px; border-radius: 5px;">
                    <strong>⚠️ Immediate Action Required!</strong><br>
                    - Block user account<br>
                    - Investigate IP address<br>
                    - Review accessed files<br>
                    - Escalate to SOC team
                </div>

                <p style="color: #666; font-size: 12px; margin-top: 20px;">
                    This is an automated alert from AI Cybersecurity Platform
                </p>
            </div>
        </body>
        </html>
        """

        msg.attach(MIMEText(html_body, 'html'))

        # Send email
        server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
        server.starttls()
        server.login(config['sender_email'], config['sender_password'])
        server.send_message(msg)
        server.quit()

        print(f"📧 Email alert sent to {config['receiver_email']}")
        return True

    except smtplib.SMTPAuthenticationError:
        print("❌ Email auth failed! Check Gmail App Password")
        return False
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        return False


def send_slack_alert(threat_data):
    """Send Slack notification"""
    config = load_config()
    webhook = config.get('slack_webhook', '')

    if not webhook:
        return False

    try:
        import requests

        message = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "🚨 Security Alert!"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*User:* {threat_data['user_id']}"},
                        {"type": "mrkdwn", "text": f"*Score:* {threat_data['threat_score']}"},
                        {"type": "mrkdwn", "text": f"*Location:* {threat_data.get('location', 'N/A')}"},
                        {"type": "mrkdwn", "text": f"*Device:* {threat_data.get('device', 'N/A')}"}
                    ]
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": "@channel Immediate action required!"}
                }
            ]
        }

        requests.post(webhook, json=message)
        print(f"💬 Slack alert sent!")
        return True
    except:
        return False


def send_alert(threat_data):
    """Main alert function - tries all channels"""
    print(f"\n🚨 HIGH THREAT DETECTED!")
    print(f"   User: {threat_data['user_id']}")
    print(f"   Score: {threat_data['threat_score']}")

    # Try all alert channels
    channels = []

    if send_email_alert(threat_data):
        channels.append('Email')

    if send_slack_alert(threat_data):
        channels.append('Slack')

    # Log to file
    with open('threat_alerts.log', 'a') as f:
        f.write(f"{datetime.now().isoformat()} | {threat_data['user_id']} | {threat_data['threat_score']} | {channels}\n")

    if channels:
        print(f"   ✅ Alerted via: {', '.join(channels)}")
    else:
        print(f"   ⚠️  No alert channels configured!")

    return len(channels) > 0


# ============ CONFIGURATION GUIDE ============
def setup_guide():
    """Print setup instructions"""
    print("""
╔══════════════════════════════════════════════╗
║     📧 ALERT SYSTEM CONFIGURATION GUIDE       ║
╚══════════════════════════════════════════════╝

1. GMAIL SETUP:
   - Go to: https://myaccount.google.com/apppasswords
   - Generate App Password for 'Mail'
   - Save config:

   cat > ~/.alert_config.json << 'ENDCONFIG'
   {
     "smtp_server": "smtp.gmail.com",
     "smtp_port": 587,
     "sender_email": "YOUR_GMAIL@gmail.com",
     "sender_password": "YOUR_16_CHAR_APP_PASSWORD",
     "receiver_email": "security@company.com",
     "slack_webhook": "",
     "teams_webhook": ""
   }
   ENDCONFIG

2. SLACK SETUP (Optional):
   - Go to: https://api.slack.com/messaging/webhooks
   - Create incoming webhook
   - Add URL to config file

3. TEST:
   python3 alerting.py --test
""")


if __name__ == '__main__':
    import sys

    if '--setup' in sys.argv:
        setup_guide()
    else:
        # Test alert
        test_threat = {
            'user_id': 'ali',
            'threat_score': 0.987,
            'risk_level': 'HIGH',
            'location': 'Russia',
            'device': 'unknown',
            'files_accessed': 8000,
            'timestamp': datetime.now().isoformat()
        }

        print("🧪 Testing alert system...")
        send_alert(test_threat)

