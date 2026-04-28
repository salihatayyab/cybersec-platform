#!/usr/bin/env python3
"""
🧪 End-to-End Test Suite
Tests: Kafka → API → Dashboard → Models → Alerts
"""

import requests
import json
import time
import subprocess
import sys
import os
from datetime import datetime

# ============================================
# CONFIG
# ============================================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_URL = "http://localhost:5000"
DASHBOARD_URL = "http://localhost:8080"
KAFKA_BOOTSTRAP = "localhost:9093"
ES_URL = "http://localhost:9200"

# Colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'

passed = 0
failed = 0
total = 0

def test(name, condition, detail=""):
    global passed, failed, total
    total += 1
    if condition:
        passed += 1
        print(f"{GREEN}✅ PASS{RESET} {name} {detail}")
    else:
        failed += 1
        print(f"{RED}❌ FAIL{RESET} {name} {detail}")
    return condition

# ============================================
# TEST SUITE
# ============================================
def run_tests():
    global passed, failed, total
    
    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}🧪 END-TO-END TEST SUITE{RESET}")
    print(f"{BOLD}{'='*70}{RESET}")
    print(f"🕐 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📂 Base:    {BASE_DIR}")
    
    # ========================================
    # 1. INFRASTRUCTURE TESTS
    # ========================================
    print(f"\n{BOLD}{BLUE}📡 1. INFRASTRUCTURE CHECKS{RESET}")
    print("-" * 50)
    
    # Kafka
    kafka_running = False
    try:
        result = subprocess.run(
            ['docker', 'ps', '--filter', 'name=kafka', '--format', '{{.Status}}'],
            capture_output=True, text=True, timeout=5
        )
        kafka_running = 'Up' in result.stdout
    except:
        pass
    test("Kafka Broker", kafka_running, "(Docker container)")
    
    # Elasticsearch
    es_running = False
    try:
        r = requests.get(ES_URL, timeout=3)
        es_running = r.status_code == 200
    except:
        pass
    test("Elasticsearch", es_running, f"({ES_URL})")
    
    # API Server
    api_running = False
    try:
        r = requests.get(f"{API_URL}/health", timeout=3)
        api_running = r.status_code == 200
    except:
        pass
    test("Flask API Server", api_running, f"({API_URL})")
    
    # Dashboard
    dashboard_running = False
    try:
        r = requests.get(DASHBOARD_URL, timeout=3)
        dashboard_running = r.status_code == 200
    except:
        pass
    test("Dashboard", dashboard_running, f"({DASHBOARD_URL})")
    
    # ========================================
    # 2. API ENDPOINT TESTS
    # ========================================
    print(f"\n{BOLD}{BLUE}🔌 2. API ENDPOINT TESTS{RESET}")
    print("-" * 50)
    
    if api_running:
        # Health check
        try:
            r = requests.get(f"{API_URL}/health", timeout=5)
            data = r.json()
            test("GET /health (status)", data.get('status') == 'healthy')
            test("GET /health (models)", data.get('models_loaded', 0) > 0)
        except Exception as e:
            test("GET /health", False, str(e))
        
        # Models endpoint
        try:
            r = requests.get(f"{API_URL}/models", timeout=5)
            data = r.json()
            test("GET /models", 'models' in data, f"({len(data.get('models',{}))} models)")
        except Exception as e:
            test("GET /models", False, str(e))
        
        # Stats endpoint
        try:
            r = requests.get(f"{API_URL}/stats", timeout=5)
            data = r.json()
            test("GET /stats", 'total_requests' in data)
        except Exception as e:
            test("GET /stats", False, str(e))
    else:
        print(f"{YELLOW}⚠️  API not running - skipping API tests{RESET}")
    
    # ========================================
    # 3. THREAT DETECTION TESTS
    # ========================================
    print(f"\n{BOLD}{BLUE}🚨 3. THREAT DETECTION TESTS{RESET}")
    print("-" * 50)
    
    if api_running:
        # Test 1: Obvious Threat
        try:
            payload = {
                'hour_of_day': 3, 'files_accessed': 8000,
                'login_attempts': 10, 'foreign_ip': 1,
                'unknown_device': 1, 'data_uploaded_mb': 2000
            }
            r = requests.post(f"{API_URL}/predict", json=payload, timeout=5)
            result = r.json()
            score = result['prediction']['threat_score']
            level = result['prediction']['risk_level']
            
            test("Obvious Threat - HIGH", level == 'HIGH', f"(Score: {score:.2f})")
            test("Obvious Threat - BLOCK", result['prediction']['action'] == 'BLOCK')
            test("Obvious Threat - Score > 0.7", score > 0.7, f"(Score: {score:.3f})")
        except Exception as e:
            test("Obvious Threat", False, str(e))
        
        # Test 2: Normal Activity
        try:
            payload = {
                'hour_of_day': 10, 'files_accessed': 30,
                'login_attempts': 1, 'foreign_ip': 0,
                'unknown_device': 0, 'data_uploaded_mb': 10
            }
            r = requests.post(f"{API_URL}/predict", json=payload, timeout=5)
            result = r.json()
            score = result['prediction']['threat_score']
            level = result['prediction']['risk_level']
            
            test("Normal Activity - LOW", level == 'LOW', f"(Score: {score:.2f})")
            test("Normal Activity - ALLOW", result['prediction']['action'] == 'ALLOW')
            test("Normal Activity - Score < 0.4", score < 0.4, f"(Score: {score:.3f})")
        except Exception as e:
            test("Normal Activity", False, str(e))
        
        # Test 3: Borderline Case
        try:
            payload = {
                'hour_of_day': 23, 'files_accessed': 200,
                'login_attempts': 3, 'foreign_ip': 0,
                'unknown_device': 0, 'data_uploaded_mb': 100
            }
            r = requests.post(f"{API_URL}/predict", json=payload, timeout=5)
            result = r.json()
            score = result['prediction']['threat_score']
            level = result['prediction']['risk_level']
            
            test("Borderline - Not LOW", level != 'LOW', f"(Level: {level}, Score: {score:.2f})")
            test("Borderline - Score > 0.2", score > 0.2, f"(Score: {score:.3f})")
        except Exception as e:
            test("Borderline Case", False, str(e))
        
        # Test 4: Batch Prediction
        try:
            batch = [
                {'hour_of_day':3,'files_accessed':8000,'login_attempts':10,'foreign_ip':1,'unknown_device':1,'data_uploaded_mb':2000},
                {'hour_of_day':10,'files_accessed':30,'login_attempts':1,'foreign_ip':0,'unknown_device':0,'data_uploaded_mb':10}
            ]
            r = requests.post(f"{API_URL}/predict/batch", json=batch, timeout=5)
            result = r.json()
            test("Batch Prediction", result['total'] == 2)
        except Exception as e:
            test("Batch Prediction", False, str(e))
    else:
        print(f"{YELLOW}⚠️  API not running - skipping detection tests{RESET}")
    
    # ========================================
    # 4. DASHBOARD TESTS
    # ========================================
    print(f"\n{BOLD}{BLUE}📊 4. DASHBOARD TESTS{RESET}")
    print("-" * 50)
    
    if dashboard_running:
        try:
            r = requests.get(DASHBOARD_URL, timeout=5)
            html = r.text
            
            test("Dashboard loads", r.status_code == 200)
            test("Has 'LIVE' indicator", 'LIVE' in html)
            test("Has 'Total Logs'", 'Total Logs' in html)
            test("Has 'High Threats'", 'High Threats' in html)
            test("Has 'ALERT FEED'", 'ALERT FEED' in html, "(or ALERT)")
            test("Has 'FORECAST'", 'FORECAST' in html)
            test("Has 'BLOCK' button", 'BLOCK' in html)
        except Exception as e:
            test("Dashboard", False, str(e))
        
        # Dashboard API endpoints
        for endpoint in ['/api/stats', '/api/forecast']:
            try:
                r = requests.get(f"{DASHBOARD_URL}{endpoint}", timeout=5)
                test(f"Dashboard {endpoint}", r.status_code == 200)
            except:
                test(f"Dashboard {endpoint}", False)
    else:
        print(f"{YELLOW}⚠️  Dashboard not running - skipping dashboard tests{RESET}")
    
    # ========================================
    # 5. MODEL FILE TESTS
    # ========================================
    print(f"\n{BOLD}{BLUE}🤖 5. MODEL FILE TESTS{RESET}")
    print("-" * 50)
    
    model_dir = os.path.join(BASE_DIR, 'ml', 'models')
    models_to_check = [
        'xgb_model.pkl',
        'rf_model.pkl',
        'rf_model_noisy.pkl',
        'lstm_model.h5',
        'lstm_model.keras',
        'deep_learning_model.h5'
    ]
    
    for model_file in models_to_check:
        path = os.path.join(model_dir, model_file)
        exists = os.path.exists(path)
        size = os.path.getsize(path) if exists else 0
        test(f"Model: {model_file}", exists, f"({size//1024} KB)" if exists else "")
    
    # ========================================
    # 6. DATA PIPELINE TESTS
    # ========================================
    print(f"\n{BOLD}{BLUE}📡 6. DATA PIPELINE TESTS{RESET}")
    print("-" * 50)
    
    # Check Kafka topics
    if kafka_running:
        try:
            result = subprocess.run(
                ['docker', 'exec', '-i', 
                 subprocess.run(['docker', 'ps', '-q', '-f', 'name=kafka'], capture_output=True, text=True).stdout.strip(),
                 'kafka-topics', '--list', '--bootstrap-server', 'localhost:9092'],
                capture_output=True, text=True, timeout=10
            )
            topics = result.stdout.strip().split('\n')
            expected_topics = ['network-logs', 'user-activity', 'system-events', 'threat-alerts']
            
            for topic in expected_topics:
                test(f"Kafka topic: {topic}", topic in topics)
        except Exception as e:
            test("Kafka topics check", False, str(e))
    
    # Check dataset
    dataset_path = os.path.join(BASE_DIR, 'ml', 'training', 'security_dataset.csv')
    test("Dataset exists", os.path.exists(dataset_path), 
         f"({os.path.getsize(dataset_path)//1024} KB)" if os.path.exists(dataset_path) else "")
    
    # ========================================
    # 7. PERFORMANCE TESTS
    # ========================================
    print(f"\n{BOLD}{BLUE}⚡ 7. PERFORMANCE TESTS{RESET}")
    print("-" * 50)
    
    if api_running:
        # Response time test
        try:
            times = []
            for _ in range(5):
                start = time.time()
                r = requests.post(f"{API_URL}/predict", json={
                    'hour_of_day': 10, 'files_accessed': 30,
                    'login_attempts': 1, 'foreign_ip': 0,
                    'unknown_device': 0, 'data_uploaded_mb': 10
                }, timeout=5)
                times.append(time.time() - start)
            
            avg_time = sum(times) / len(times) * 1000
            max_time = max(times) * 1000
            
            test(f"Avg Response < 500ms", avg_time < 500, f"({avg_time:.0f}ms)")
            test(f"Max Response < 1000ms", max_time < 1000, f"({max_time:.0f}ms)")
        except Exception as e:
            test("Performance test", False, str(e))
    
    # ========================================
    # SUMMARY
    # ========================================
    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}📊 TEST SUMMARY{RESET}")
    print(f"{BOLD}{'='*70}{RESET}")
    
    score = (passed / total * 100) if total > 0 else 0
    
    print(f"\n   Total Tests:  {total}")
    print(f"   {GREEN}Passed:       {passed}{RESET}")
    print(f"   {RED}Failed:       {failed}{RESET}")
    print(f"   Score:        {score:.0f}%")
    
    if score == 100:
        grade = f"{GREEN}🏆 A+ PERFECT!{RESET}"
    elif score >= 90:
        grade = f"{GREEN}✅ A - Excellent{RESET}"
    elif score >= 75:
        grade = f"{YELLOW}⚠️  B - Good, some issues{RESET}"
    elif score >= 60:
        grade = f"{YELLOW}🟡 C - Needs improvement{RESET}"
    else:
        grade = f"{RED}❌ F - Critical failures{RESET}"
    
    print(f"   Grade:        {grade}")
    
    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"🕐 Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{BOLD}{'='*70}{RESET}")
    
    return score

# ============================================
# MAIN
# ============================================
if __name__ == "__main__":
    score = run_tests()
    sys.exit(0 if score >= 75 else 1)
