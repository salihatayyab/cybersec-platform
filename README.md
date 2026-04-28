# 🛡️ AI-Driven Cybersecurity Analytics Platform

> Real-time threat detection, behavioral analysis, and predictive security using Machine Learning and Big Data technologies.

![Platform](https://img.shields.io/badge/Platform-Ubuntu%2022.04-orange?style=flat-square&logo=ubuntu)
![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Kafka](https://img.shields.io/badge/Apache-Kafka-231F20?style=flat-square&logo=apachekafka)
![Elasticsearch](https://img.shields.io/badge/Elastic-Search-005571?style=flat-square&logo=elasticsearch)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.x-FF6F00?style=flat-square&logo=tensorflow)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Prerequisites](#-prerequisites)
- [Installation & Setup](#-installation--setup)
- [How to Run](#-how-to-run)
- [Components Explained](#-components-explained)
- [Screenshots](#-screenshots)
- [API Reference](#-api-reference)
- [What I Learned](#-what-i-learned)
- [Future Improvements](#-future-improvements)

---

## 🔍 Overview

This project is a **comprehensive AI-driven cybersecurity analytics platform** that combines real-time data streaming, machine learning, and big data technologies to detect, analyze, and predict security threats.

The platform simulates a real-world Security Operations Center (SOC) environment where:

- Logs flow in **real-time** from multiple sources via Apache Kafka
- **AI/ML models** analyze behavior and detect threats instantly
- **UEBA (User and Entity Behavior Analytics)** builds user baselines and flags anomalies
- **Explainable AI** using SHAP and LIME tells the security team *why* something was flagged
- A **live dashboard** shows threat scores, alerts, and 7-day forecasts

### Real-World Use Case Example

```
Ali logs in at 3:00 AM (normally 9 AM) from Russia (normally Pakistan)
and downloads 8,000 files (normally ~50/day).

→ Kafka receives the log instantly
→ XGBoost model scores it: 0.95 (HIGH THREAT)
→ SHAP explains: "Night login +40%, Excessive files +35%, Foreign IP +25%"
→ Alert fires → Access blocked → SOC team notified
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    DATA INGESTION LAYER                      │
│         Apache Kafka  ·  Apache NiFi / Logstash             │
│   [Network Logs]  [User Activity]  [System Events]          │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                   STORAGE LAYER                              │
│      Elasticsearch  ·  Apache Spark  ·  Kibana              │
│   [security-logs index]  [Batch Analysis]  [Dashboards]     │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                  AI / ML ENGINE                              │
│   XGBoost · TensorFlow · scikit-learn · LSTM · UEBA         │
│   [Threat Classifier] [Deep Learning] [Behavior Analysis]   │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│              EXPLAINABLE AI LAYER                            │
│                  SHAP  ·  LIME                               │
│        [Why was this flagged?] [Feature Importance]         │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│           REAL-TIME STREAMING & HUNTING                      │
│     Apache Flink · Airflow · HELK · Jupyter Notebooks       │
│   [Live Detection] [Scheduling] [Threat Investigation]      │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│            DASHBOARD & ALERTING                              │
│          Flask API  ·  Grafana  ·  Kibana                   │
│   [Threat Scores] [Forecasting] [SOC Dashboard] [Alerts]   │
└─────────────────────────────────────────────────────────────┘
```

---

## ✨ Features

### 🤖 AI-Powered Threat Detection
- **XGBoost ensemble model** — 94%+ accuracy on threat classification
- **TensorFlow deep neural network** — multi-layer threat pattern recognition
- **scikit-learn Random Forest** — baseline model for comparison
- **Ensemble scoring** — combines multiple models for reduced false positives

### 👤 User & Entity Behavior Analytics (UEBA)
- Builds individual **behavioral baselines** for every user
- Detects **insider threats** — unusual login times, locations, devices
- **Anomaly scoring** — quantifies how far behavior deviates from normal
- **LSTM time-series model** — detects patterns over time

### 🔮 Predictive Security
- **7-day threat forecast** using linear regression on historical data
- **Trend analysis** — identifies rising threat patterns early
- Early warning system for security teams

### 🔍 Explainable AI (XAI)
- **SHAP values** — explains every alert with feature contributions
- **LIME** — local interpretable model explanations
- Security teams understand *why* the AI flagged something
- Auto-generated HTML explanation reports

### 🎯 Automated Threat Hunting
- **Jupyter notebooks** — interactive threat investigation
- **Auto-investigator** — automatically correlates evidence
- **Report generator** — produces formatted threat reports

### 📊 Real-Time Dashboard
- Flask REST API with `/predict` and `/health` endpoints
- Live SOC dashboard showing recent alerts
- Grafana integration for metric visualization
- Kibana for log search and exploration

---

## 🛠️ Tech Stack

| Category | Technologies |
|----------|-------------|
| **Data Ingestion** | Apache Kafka, Apache NiFi, Logstash |
| **Storage** | Elasticsearch 8.x, Apache Spark 3.5 |
| **Visualization** | Kibana, Grafana |
| **AI/ML** | TensorFlow 2.x, XGBoost, scikit-learn, LSTM |
| **Explainability** | SHAP, LIME, InterpretML |
| **Streaming** | Apache Flink 1.18, Kafka Streams |
| **Orchestration** | Apache Airflow |
| **Threat Hunting** | Jupyter Notebooks, Pandas |
| **API** | Flask (Python) |
| **Infrastructure** | Docker, Docker Compose |
| **Language** | Python 3.10+ |
| **OS** | Ubuntu 22.04 LTS |

---

## 📁 Project Structure

```
cybersec-platform/
│
├── 📂 data/
│   ├── log_generator.py        # Fake log generator for testing
│   ├── log_consumer.py         # Kafka consumer
│   └── raw/                    # Raw log storage
│
├── 📂 kafka/
│   └── docker-compose.yml      # Kafka + Zookeeper setup
│
├── 📂 elasticsearch/
│   ├── docker-compose.yml      # ES + Kibana setup
│   └── kafka_to_es.py          # Kafka → Elasticsearch bridge
│
├── 📂 spark/
│   └── analyze_logs.py         # Batch analysis with Spark
│
├── 📂 ml/
│   ├── training/
│   │   ├── create_dataset.py       # Dataset generation
│   │   ├── baseline_model.py       # Random Forest model
│   │   ├── xgboost_model.py        # XGBoost model
│   │   ├── deep_learning_model.py  # TensorFlow model
│   │   └── lstm_model.py           # LSTM time-series model
│   ├── models/                     # Saved model files (.pkl, .h5)
│   ├── explainability/
│   │   ├── shap_explainer.py       # SHAP explanations
│   │   └── lime_explainer.py       # LIME explanations
│   └── threat_scorer.py            # Ensemble threat scoring
│
├── 📂 ueba/
│   └── behavior_analyzer.py    # User behavior analytics
│
├── 📂 flink/
│   ├── realtime_detector.py    # Live threat detection stream
│   └── alert_handler.py        # Alert consumer
│
├── 📂 threat-hunting/
│   ├── notebooks/
│   │   └── threat_hunting_101.ipynb
│   ├── auto_investigator.py    # Automated investigation
│   └── report_generator.py     # Threat report generator
│
│
├── 📂 dashboard/
│   ├── api.py                  # Flask REST API
│   ├── app.py                  # Web dashboard
│   └── docker-compose.yml      # Grafana setup
│
├── 📂 pipeline/
│   └── data_pipeline.py        # Python ETL pipeline
│
├── 📂 logstash/
│   └── pipeline/
│       └── security.conf       # Logstash config
│
├── 📂 tests/
│   ├── e2e_test.py             # End-to-end tests
│   ├── model_evaluation.py     # Model performance check
│   └── load_test.py            # Stress testing
│
│
├── docker-compose-full.yml     # All services in one file
├── start_all.sh                # One-click startup script
├── .env                        # Environment variables
├── requirements.txt            # Python dependencies
└── README.md
```

---

## ⚙️ Prerequisites

Make sure you have these installed:

```bash
# Check versions
docker --version          # Docker 20.x+
docker-compose --version  # 1.29+
python3 --version         # Python 3.10+
java -version             # Java 17+
git --version
```

**System Requirements:**

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 8 GB | 16 GB |
| Storage | 50 GB | 100 GB |
| CPU Cores | 4 | 8 |
| OS | Ubuntu 20.04 | Ubuntu 22.04 |

---

## 🚀 Installation & Setup

### Step 1 — Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/cybersec-platform.git
cd cybersec-platform
```

### Step 2 — Create Virtual Environment

```bash
python3 -m venv cybersec-env
source cybersec-env/bin/activate
```

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Create Docker Network

```bash
docker network create cybersec-network
```

### Step 5 — Configure Environment

```bash
cp .env.example .env
# Edit .env if needed
```

---

## ▶️ How to Run

### Option A — One Command (Recommended)

```bash
chmod +x start_all.sh
./start_all.sh
```

### Option B — Step by Step

```bash
# 1. Start Kafka
cd kafka && docker-compose up -d && cd ..

# 2. Start Elasticsearch + Kibana
cd elasticsearch && docker-compose up -d && cd ..

# 3. Start Grafana
cd dashboard && docker-compose up -d && cd ..

# Wait for services to start
sleep 15

# 4. Activate environment
source cybersec-env/bin/activate

# 5. Train ML models
cd ml/training
python3 create_dataset.py
python3 baseline_model.py
python3 xgboost_model.py
python3 deep_learning_model.py
python3 create_dataset_noisy.py
python3 baseline_model_noisy.py
python3 xgboost_model_noisy.py
python3 deep_learning_model_noisy.py
cd ../..

# 6. Start data pipeline
python3 data/log_generator.py &
python3 elasticsearch/kafka_to_es.py &

# 7. Start real-time detector
python3 flink/realtime_detector.py &
python3 flink/alert_handler.py &

# 8. Start API + Dashboard
python3 dashboard/api.py &
python3 dashboard/app.py &
```

### Access the Platform

| Service | URL | Credentials |
|---------|-----|-------------|
| 🖥️ SOC Dashboard | http://localhost:8080 | — |
| 🔌 REST API | http://localhost:5000 | — |
| 📊 Kibana | http://localhost:5601 | — |
| 📈 Grafana | http://localhost:3000 | admin / admin123 |
| 📓 Jupyter | http://localhost:8888 | — |
| ⚙️ Flink UI | http://localhost:8081 | — |
| 🔄 Airflow | http://localhost:8080 | admin / admin123 |

---

## 🧩 Components Explained

### 1. Data Ingestion (Kafka)

Apache Kafka acts as the central message bus. Three topics handle different log types:

```
network-logs    → Firewall, IDS/IPS logs
user-activity   → Login, file access, downloads
system-events   → OS level events, process creation
```

### 2. AI/ML Models

Three models work together in an ensemble:

```python
final_score = (xgboost_prob × 0.6) + (random_forest_prob × 0.4)

Risk Levels:
  score > 0.70  →  HIGH   →  BLOCK
  score > 0.40  →  MEDIUM →  MONITOR
  score ≤ 0.40  →  LOW    →  ALLOW
```

### 3. UEBA — Behavioral Baselines

The system learns each user's normal behavior:

```
Ali's baseline:
  Login time:    9 AM – 5 PM
  Files/day:     ~50
  Location:      Pakistan
  Device:        Office laptop

Deviation triggers alert:
  Login at 3 AM  → +30 anomaly points
  10,000 files   → +40 anomaly points
  Foreign IP     → +20 anomaly points
  Unknown device → +10 anomaly points

Score > 50 = ANOMALY DETECTED
```

### 4. Explainable AI

Every alert comes with a human-readable explanation:

```
Alert: Ali flagged as HIGH THREAT

SHAP Explanation:
  files_accessed:  8000  →  +0.42 threat contribution
  hour_of_day:     3     →  +0.31 threat contribution
  foreign_ip:      1     →  +0.18 threat contribution
  unknown_device:  1     →  +0.09 threat contribution
```

---

## 📸 Screenshots
<img width="1599" height="741" alt="image" src="https://github.com/user-attachments/assets/38a0324b-4468-4c35-8094-087b6b608982" />
<img width="1600" height="855" alt="image" src="https://github.com/user-attachments/assets/77f2a23a-2d5d-4cdc-a55f-12830f9fd422" />
<img width="775" height="220" alt="image" src="https://github.com/user-attachments/assets/d52d7f71-6500-48e2-acbc-e28d31641801" />
<img width="715" height="196" alt="image" src="https://github.com/user-attachments/assets/eaac7e2e-1c0b-4dad-94b7-5161cb3580bd" />
<img width="1149" height="643" alt="image" src="https://github.com/user-attachments/assets/07a8694d-1041-43c3-901c-488a3e3c7675" />
<img width="1323" height="693" alt="image" src="https://github.com/user-attachments/assets/74f92a5e-36c1-4e0a-adfd-829223b450e4" />
<img width="1556" height="598" alt="image" src="https://github.com/user-attachments/assets/2f740992-34a1-487a-9e99-bf53bce0ad4a" />
<img width="1600" height="733" alt="image" src="https://github.com/user-attachments/assets/81666903-f839-4a12-bd1a-8fc8fd63fbd4" />


```
📁 screenshots is in /screenshots/
---

## 📡 API Reference

### Health Check

```http
GET /health
```

```json
{
  "status": "running"
}
```

### Threat Prediction

```http
POST /predict
Content-Type: application/json
```

**Request Body:**

```json
{
  "hour_of_day": 3,
  "files_accessed": 8000,
  "login_attempts": 10,
  "foreign_ip": 1,
  "unknown_device": 1,
  "data_uploaded_mb": 2000
}
```

**Response:**

```json
{
  "threat_score": 0.951,
  "risk_level": "HIGH",
  "action": "BLOCK"
}
```

### Test the API

```bash
# Normal user
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"hour_of_day":10,"files_accessed":45,"login_attempts":1,"foreign_ip":0,"unknown_device":0,"data_uploaded_mb":8}'

# Suspicious user
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"hour_of_day":3,"files_accessed":8000,"login_attempts":10,"foreign_ip":1,"unknown_device":1,"data_uploaded_mb":2000}'
```

---

## 📚 What I Learned

Working on this project gave me hands-on experience with:

**Big Data Engineering** — Setting up and connecting Kafka, Elasticsearch, and Spark into a working pipeline taught me how enterprise data flows actually work at scale.

**Machine Learning in Security** — Training XGBoost and TensorFlow models on behavioral data and understanding why ensemble methods reduce false positives in security contexts.

**Explainable AI** — Implementing SHAP and LIME made me realize how important model transparency is — security analysts cannot act on a black-box "threat detected" without knowing why.

**Real-Time Systems** — Building a pipeline where a log generated by Kafka is detected, scored, and alerted within milliseconds gave me appreciation for streaming architecture design.

**Docker & DevOps** — Managing 7+ services with Docker Compose, networking them together, and debugging cross-container communication issues.

---

## 🔮 Future Improvements

- [ ] Integrate real network traffic datasets (CICIDS2017)
- [ ] Add HTTPS and authentication to Flask API
- [ ] Deploy on AWS (MSK + OpenSearch + SageMaker)
- [ ] Add Graph Neural Networks for attack path analysis
- [ ] Implement MITRE ATT&CK framework mapping
- [ ] Add automated incident response playbooks
- [ ] Multi-node Elasticsearch cluster for production scale
- [ ] Integrate threat intelligence feeds (VirusTotal API)

---

## 👨‍💻 Author

**Your Name**
- GitHub: (https://github.com/salihatayyab)
- LinkedIn: (https://www.linkedin.com/in/saliha-tayyab-268294324/)

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Apache Kafka Documentation](https://kafka.apache.org/documentation/)
- [Elasticsearch Guide](https://www.elastic.co/guide/)
- [SHAP Library](https://shap.readthedocs.io/)
- [HELK Project](https://github.com/Cyb3rWard0g/HELK)

---

> ⭐ If you found this project helpful, please give it a star on GitHub!
