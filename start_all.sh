
#!/bin/bash
echo "🚀 Starting Cybersecurity Platform..."

echo "1. Kafka starting..."
cd ~/cybersec-platform/kafka && docker-compose up -d

echo "2. Elasticsearch starting..."
cd ~/cybersec-platform/elasticsearch && docker-compose up -d

echo "3. Grafana starting..."
cd ~/cybersec-platform/dashboard && docker-compose up -d

sleep 10

echo "4. Log Generator starting..."
source ~/cybersec-platform/cybersec-env/bin/activate
python3 ~/cybersec-platform/data/log_generator.py &

echo "5. Kafka to ES Bridge starting..."
python3 ~/cybersec-platform/elasticsearch/kafka_to_es.py &

echo "6. Real-time Detector starting..."
python3 ~/cybersec-platform/flink/realtime_detector.py &

echo "7. Alert Handler starting..."
python3 ~/cybersec-platform/flink/alert_handler.py &

echo "8. API starting..."
python3 ~/cybersec-platform/dashboard/api.py &

echo "9. Dashboard starting..."
python3 ~/cybersec-platform/dashboard/app.py &

echo ""
echo "✅ Platform is LIVE!"
echo "Dashboard:     http://localhost:8080"
echo "Kibana:        http://localhost:5601"
echo "Grafana:       http://localhost:3000"
echo "API:           http://localhost:5000"
echo "Jupyter:       http://localhost:8888"
echo "Flink:         http://localhost:8081"

# chmod +x ~/cybersec-platform/start_all.sh
# ./start_all.sh
