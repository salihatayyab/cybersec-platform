AI-Driven Cybersecurity Analytics Platform
EduQual Level 6 — Diploma in Artificial Intelligence Operations
Developed by: Saliha Tayyab
Al-Nafi International College
---
Overview
This project implements a comprehensive AI-driven cybersecurity analytics platform that supports real-time threat detection, behavioral analysis, predictive security forecasting, and explainable AI decision support. The platform combines machine learning, deep learning, big data streaming, and visualization technologies to detect, classify, and explain security threats in real time.
The platform is designed to address the limitations of traditional rule-based security systems, which can only detect known attack patterns. By leveraging multiple AI models working in parallel, this system detects both known and unknown threats, explains every decision, and forecasts future attack volumes for proactive security planning.
---
Architecture
```
Security Logs
      |
      v
Apache Kafka          (Real-time log ingestion and streaming)
      |
      v
Apache Spark          (Data cleaning, normalization, risk scoring)
      |
      v
Data Lake             (Processed CSV storage)
      |
      |-----> Isolation Forest   (Anomaly Detection / UEBA)
      |-----> XGBoost            (Ensemble Classification - Boosting)
      |-----> Random Forest      (Ensemble Classification - Bagging)
      |-----> LSTM               (Sequential Pattern Detection)
      |-----> Prophet            (Predictive Analytics / Forecasting)
      |
      v
SHAP + LIME           (Explainable AI - Feature Importance)
      |
      v
Elasticsearch         (Data indexing and storage)
      |
      v
Kibana Dashboard      (Real-time visualization and monitoring)
```
---
Key Features
AI-Powered Threat Detection
Isolation Forest — Unsupervised anomaly detection that learns from normal traffic and flags deviations, implementing UEBA (User and Entity Behavior Analytics)
XGBoost — Gradient boosting ensemble classifier achieving 82.11% accuracy and 0.9668 AUC-ROC
Random Forest — Bagging ensemble classifier achieving 0.9707 AUC-ROC, validating results across different algorithmic approaches
LSTM Neural Network — Sequential pattern detection achieving 99% accuracy and 0.9997 AUC-ROC by recognizing attack build-up patterns over time
Consensus Voting — Final verdict requires majority agreement (2 out of 4 models) to reduce false positives
Predictive Security Analytics
Prophet — Time-series forecasting model trained on 180 days of historical attack data
Detects weekly seasonality patterns (higher attack volumes on weekdays)
Generates 14-day attack volume forecasts for proactive security planning
Explainable AI
SHAP (SHapley Additive exPlanations) — Game-theory-based feature importance showing why each prediction was made
LIME (Local Interpretable Model-agnostic Explanations) — Local linear approximation providing alternative per-prediction explanations
Both tools cross-validate findings (top identified feature: `src_bytes`)
Big Data Pipeline
Apache Kafka — Real-time security event streaming with dedicated topics for logs and alerts
Apache Spark — Micro-batch stream processing, data cleaning, and preliminary risk scoring every 15 seconds
Data Lake — Structured CSV storage of Spark-processed events
Live Web Dashboards
Kafka Live Viewer (port 5050) — Real-time browser dashboard showing incoming Kafka events, color-coded by classification, with live attack/normal counters
Live AI Detection Monitor (port 5051) — Real-time browser dashboard showing all four models evaluating each event simultaneously with risk score bars and consensus verdict
Kibana Dashboard (port 5601) — Comprehensive analytics dashboard with attack distribution pie chart, risk score timeline, risk heat map, severity breakdown, top suspicious IPs, and alerts table
---
Model Performance Summary
Model	Type	Accuracy	AUC-ROC
Isolation Forest	Unsupervised Anomaly Detection	79.28%	0.9397
XGBoost	Ensemble (Boosting)	82.11%	0.9668
Random Forest	Ensemble (Bagging)	76.00%	0.9707
LSTM	Deep Learning (Sequential)	99.00%	0.9997

Prophet	Time-Series Forecasting	N/A	N/A
SHAP + LIME	Explainability Layer	N/A	N/A
Dataset: NSL-KDD (125,973 training samples, 22,544 test samples, 41 features)
---
Technology Stack
AI / Machine Learning
TensorFlow / Keras (LSTM)
scikit-learn (Isolation Forest, Random Forest)
XGBoost 1.7.6
Prophet
SHAP 0.49.1
LIME
Big Data & Streaming
Apache Kafka 3.5.0
Apache Spark 3.4.1 (PySpark)
Storage & Visualization
Elasticsearch 8.9.0
Kibana 8.9.0
Web Dashboards
Flask (Python)
Custom HTML/CSS dashboards
Infrastructure
Ubuntu Server 22.04 (VM)
Docker & Docker Compose
Java 11 (OpenJDK)
Python 3.10
---
Project Structure
```
cybersec-platform/
|
|-- scripts/
|   |-- log_generator.py           # Realistic security log generator (Kafka producer)
|   |-- spark_consumer.py          # Spark streaming consumer (Kafka -> Data Lake)
|   |-- preprocess.py              # NSL-KDD dataset preprocessing
|   |-- train_isolation_forest.py  # Isolation Forest training
|   |-- train_xgboost.py           # XGBoost training
|   |-- train_random_forest.py     # Random Forest training
|   |-- train_lstm.py              # LSTM neural network training
|   |-- train_prophet.py           # Prophet forecasting model training
|   |-- run_shap.py                # SHAP explainability analysis
|   |-- run_lime.py                # LIME explainability analysis
|   |-- pipeline_runner.py         # Full AI detection pipeline (batch)
|   |-- setup_elasticsearch.py     # Elasticsearch index setup
|   |-- kafka_web_viewer.py        # Kafka live web dashboard (port 5050)
|   |-- live_ai_monitor.py         # Live AI detection monitor (port 5051)
|   |-- performance_report.py      # Complete model performance report
|   |-- verify_es.py               # Elasticsearch data verification
|
|-- models/                        # Saved trained models (.pkl, .keras)
|-- data/
|   |-- raw/                       # NSL-KDD dataset files
|   |-- processed/                 # Preprocessed numpy arrays, CSV files
|   |-- lake/                      # Spark Data Lake output (CSV)
|
|-- logs/                          # Kafka, Zookeeper service logs
|-- config/                        # Configuration files
|-- docker-compose.yml             # Elasticsearch + Kibana Docker setup
|-- requirements.txt               # Python dependencies
```
---
Installation & Setup
Prerequisites
Ubuntu 22.04 Server
Python 3.10+
Java 11 (OpenJDK)
Docker & Docker Compose
Minimum 8GB RAM
Step 1 — Clone the Repository
```bash
git clone https://github.com/your-username/ai-cybersecurity-platform.git
cd ai-cybersecurity-platform
```
Step 2 — Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
Step 3 — Install Apache Kafka
```bash
wget https://archive.apache.org/dist/kafka/3.5.0/kafka_2.13-3.5.0.tgz
tar -xzf kafka_2.13-3.5.0.tgz
sudo mv kafka_2.13-3.5.0 /opt/kafka
echo 'export KAFKA_HOME=/opt/kafka' >> ~/.bashrc
echo 'export PATH=$PATH:$KAFKA_HOME/bin' >> ~/.bashrc
source ~/.bashrc
```
Step 4 — Install Apache Spark
```bash
wget https://archive.apache.org/dist/spark/spark-3.4.1/spark-3.4.1-bin-hadoop3.tgz
tar -xzf spark-3.4.1-bin-hadoop3.tgz
sudo mv spark-3.4.1-bin-hadoop3 /opt/spark
echo 'export SPARK_HOME=/opt/spark' >> ~/.bashrc
echo 'export PATH=$PATH:$SPARK_HOME/bin' >> ~/.bashrc
source ~/.bashrc
```
Step 5 — Download NSL-KDD Dataset
```bash
cd data/raw
wget -O KDDTrain.txt "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
wget -O KDDTest.txt "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"
```
Step 6 — Preprocess Data and Train Models
```bash
python3 scripts/preprocess.py
python3 scripts/train_isolation_forest.py
python3 scripts/train_xgboost.py
python3 scripts/train_random_forest.py
python3 scripts/train_lstm.py
python3 scripts/train_prophet.py
python3 scripts/run_shap.py
python3 scripts/run_lime.py
```
---
Running the Platform
Start All Services
```bash
# Start Elasticsearch and Kibana
docker-compose up -d
sleep 90

# Start Kafka and Zookeeper
/opt/kafka/bin/zookeeper-server-start.sh /opt/kafka/config/zookeeper.properties > logs/zookeeper.log 2>&1 &
sleep 8
/opt/kafka/bin/kafka-server-start.sh /opt/kafka/config/server.properties > logs/kafka.log 2>&1 &
sleep 10

# Setup Elasticsearch indexes
python3 scripts/setup_elasticsearch.py
```
Start Live Monitoring
```bash
# Terminal 1: Log Generator
python3 scripts/log_generator.py

# Terminal 2: Kafka Web Viewer
python3 scripts/kafka_web_viewer.py

# Terminal 3: Live AI Detection Monitor
python3 scripts/live_ai_monitor.py

# Terminal 4: Run AI Pipeline (populates Kibana dashboard)
python3 scripts/pipeline_runner.py
```
Access Dashboards
Dashboard	URL	Description
Kafka Live Viewer	http://localhost:5050	Raw event stream with live counters
AI Detection Monitor	http://localhost:5051	All 4 models evaluating events in real time
Kibana Dashboard	http://localhost:5601	Full analytics and alert management
View Performance Report
```bash
python3 scripts/performance_report.py
```
Stop All Services
```bash
pkill -f log_generator.py
pkill -f kafka_web_viewer.py
pkill -f live_ai_monitor.py
/opt/kafka/bin/kafka-server-stop.sh
sleep 5
/opt/kafka/bin/zookeeper-server-stop.sh
docker-compose down
```
---
How It Works
1. Log Ingestion
The `log_generator.py` script simulates realistic network security events including brute force attacks, port scans, data exfiltration, DDoS, and insider threats. Events are sent to Apache Kafka's `security-logs` topic at configurable intervals.
2. Stream Processing
Apache Spark consumes the Kafka stream in 15-second micro-batches, cleans the data (removing nulls and invalid entries), calculates a preliminary rule-based risk score, and writes structured CSV files to the Data Lake.
3. AI Detection Pipeline
The `pipeline_runner.py` processes events through the complete AI pipeline:
Isolation Forest calculates an anomaly score based on deviation from normal behavior
XGBoost uses the original features plus the IF anomaly score as an additional feature for classification
SHAP explains why each prediction was made, identifying the most influential features
4. Real-Time Consensus
The `live_ai_monitor.py` runs all four models (Isolation Forest, XGBoost, Random Forest, LSTM) on each incoming event and uses majority voting for the final verdict — requiring at least 2 of 4 models to agree before flagging an event as an attack.
5. Forecasting
Prophet analyzes historical attack volume data to detect temporal patterns and generate 14-day forecasts, enabling proactive security resource allocation.
6. Visualization
All results are indexed into Elasticsearch and displayed on the Kibana dashboard, providing security analysts with real-time threat monitoring, risk heat maps, severity distributions, and alert management.
---
Key Learning Objectives Covered
Objective	Implementation
Deep learning for threat detection	LSTM neural network with 99% accuracy
Ensemble methods	XGBoost (boosting) + Random Forest (bagging)
Neural networks for anomaly detection	LSTM + Isolation Forest
UEBA	Isolation Forest behavioral baseline modeling
Predictive analytics	Prophet time-series forecasting
Time-series analysis	Prophet with weekly seasonality detection
Big data platforms	Apache Kafka + Apache Spark
Real-time streaming analytics	Kafka streaming + Spark micro-batching
Data lake configuration	Spark-processed CSV Data Lake
Explainable AI	SHAP (global + local) + LIME (local)
Feature importance analysis	SHAP TreeExplainer
Real-time dashboard	Kibana + 2 custom Flask dashboards
---
Dataset
NSL-KDD — The improved version of the KDD Cup 1999 dataset, widely used for network intrusion detection research.
Training samples: 125,973
Test samples: 22,544
Features: 41
Classes: Normal traffic + 4 attack categories (DoS, Probe, R2L, U2R)
Source: https://github.com/defcom17/NSL_KDD
---
Limitations and Future Work
Current Limitations
Uses NSL-KDD benchmark dataset and synthetically generated logs rather than live production network traffic
LSTM in the live monitor uses single-event approximation rather than true historical sequences
Single-node deployment — not horizontally scalable in current form
Future Enhancements
Integration with real network infrastructure (firewalls, IDS sensors)
HELK (Hunting ELK) integration for advanced automated threat hunting
Kubernetes deployment for horizontal scalability
Continuous model retraining pipeline on live traffic data
CNN-based packet payload analysis for deeper threat classification
Integration with threat intelligence feeds (MISP, OpenCTI)
---
Project Information
Field	Details
Student	Saliha Tayyab
Email	salihatayyab188@gmail.com
Institution	Al-Nafi International College
Diploma	Diploma in Artificial Intelligence Operations
Level	EduQual Level 6
Topic	Topic 96 — AI-Driven Cybersecurity Analytics Platform

---
License
This project was developed for academic purposes as part of the EduQual Level 6 Diploma in Artificial Intelligence Operations at Al-Nafi International College.
