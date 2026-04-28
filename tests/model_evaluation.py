#!/usr/bin/env python3
"""
📊 Complete Model Evaluation Suite
Compare all models, generate performance reports
"""

import joblib
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_curve, auc, precision_recall_curve,
    accuracy_score, f1_score
)
import os
import warnings
from datetime import datetime
warnings.filterwarnings('ignore')

# ============================================
# CONFIG
# ============================================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, 'ml', 'models')
DATA_DIR = os.path.join(BASE_DIR, 'ml', 'training')
OUTPUT_DIR = os.path.join(BASE_DIR, 'tests', 'evaluation_results')
os.makedirs(OUTPUT_DIR, exist_ok=True)

FEATURES = ['hour_of_day', 'files_accessed', 'login_attempts',
            'foreign_ip', 'unknown_device', 'data_uploaded_mb']

sns.set_style('darkgrid')
plt.rcParams['figure.dpi'] = 120

# ============================================
# LOAD DATA
# ============================================
print("=" * 70)
print("📊 MODEL EVALUATION SUITE")
print("=" * 70)
print(f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# Load dataset
dataset_path = os.path.join(DATA_DIR, 'security_dataset.csv')
if not os.path.exists(dataset_path):
    dataset_path = os.path.join(DATA_DIR, 'security_dataset_noisy.csv')

print(f"\n📂 Loading: {os.path.basename(dataset_path)}")
df = pd.read_csv(dataset_path)
print(f"   Records: {len(df):,}")
print(f"   Threats: {df['is_threat'].sum()} ({100*df['is_threat'].sum()/len(df):.1f}%)")

X = df[FEATURES]
y = df['is_threat']

# ============================================
# LOAD MODELS
# ============================================
models = {}
model_files = {
    'XGBoost': 'xgb_model.pkl',
    'Random Forest': 'rf_model.pkl',
    'RF Noisy': 'rf_model_noisy.pkl',
}

print(f"\n🤖 Loading models...")
for name, filename in model_files.items():
    path = os.path.join(MODEL_DIR, filename)
    if os.path.exists(path):
        try:
            models[name] = joblib.load(path)
            size = os.path.getsize(path) // 1024
            print(f"   ✅ {name}: {filename} ({size} KB)")
        except Exception as e:
            print(f"   ❌ {name}: {e}")
    else:
        print(f"   ⚠️  {name}: not found")

if not models:
    print("\n❌ No models found!")
    exit(1)

# ============================================
# 1. CLASSIFICATION REPORTS
# ============================================
print(f"\n{'='*70}")
print("📋 1. CLASSIFICATION REPORTS")
print(f"{'='*70}")

results = {}

for name, model in models.items():
    y_pred = model.predict(X)
    accuracy = accuracy_score(y, y_pred)
    f1 = f1_score(y, y_pred)
    
    results[name] = {
        'accuracy': accuracy,
        'f1': f1,
        'y_pred': y_pred
    }
    
    print(f"\n{'─'*50}")
    print(f"🤖 {name}")
    print(f"{'─'*50}")
    print(classification_report(y, y_pred, target_names=['Normal', 'Threat'], digits=3))
    print(f"   Accuracy: {accuracy:.3f} | F1-Score: {f1:.3f}")

# ============================================
# 2. CONFUSION MATRICES
# ============================================
print(f"\n{'='*70}")
print("📊 2. CONFUSION MATRICES")
print(f"{'='*70}")

fig, axes = plt.subplots(1, len(models), figsize=(6*len(models), 5))
if len(models) == 1:
    axes = [axes]

for i, (name, model) in enumerate(models.items()):
    y_pred = results[name]['y_pred']
    cm = confusion_matrix(y, y_pred)
    
    sns.heatmap(cm, annot=True, fmt='d', cmap='YlOrRd',
                xticklabels=['Normal', 'Threat'],
                yticklabels=['Normal', 'Threat'],
                ax=axes[i], cbar=False)
    axes[i].set_title(f'{name}\nAccuracy: {results[name]["accuracy"]:.1%}', fontweight='bold')
    axes[i].set_xlabel('Predicted')
    axes[i].set_ylabel('Actual')
    
    # Add metrics text
    tn, fp, fn, tp = cm.ravel()
    axes[i].text(0.5, -0.15, 
                f'TPR: {tp/(tp+fn):.1%} | FPR: {fp/(fp+tn):.1%}',
                transform=axes[i].transAxes, ha='center', fontsize=9)

plt.suptitle('CONFUSION MATRICES COMPARISON', fontsize=14, fontweight='bold', y=1.02)
plt.tight_layout()
plt.savefig(f'{OUTPUT_DIR}/confusion_matrices.png', dpi=150, bbox_inches='tight')
plt.close()
print("   ✅ confusion_matrices.png")

# ============================================
# 3. ROC CURVES
# ============================================
print(f"\n{'='*70}")
print("📈 3. ROC CURVES")
print(f"{'='*70}")

plt.figure(figsize=(10, 8))
colors = ['#ff4444', '#58a6ff', '#00ff41', '#ffaa00']

for i, (name, model) in enumerate(models.items()):
    y_prob = model.predict_proba(X)[:, 1]
    fpr, tpr, _ = roc_curve(y, y_prob)
    roc_auc = auc(fpr, tpr)
    
    plt.plot(fpr, tpr, color=colors[i % len(colors)], linewidth=2,
             label=f'{name} (AUC = {roc_auc:.3f})')

# Diagonal line
plt.plot([0, 1], [0, 1], 'k--', alpha=0.3, label='Random (AUC = 0.500)')

plt.xlabel('False Positive Rate', fontsize=12)
plt.ylabel('True Positive Rate', fontsize=12)
plt.title('ROC CURVES - MODEL COMPARISON', fontsize=14, fontweight='bold')
plt.legend(loc='lower right', fontsize=10)
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(f'{OUTPUT_DIR}/roc_curves.png', dpi=150, bbox_inches='tight')
plt.close()

# Print AUC scores
for name, model in models.items():
    y_prob = model.predict_proba(X)[:, 1]
    roc_auc = auc(*roc_curve(y, y_prob)[:2])
    print(f"   {name:20s} AUC: {roc_auc:.4f}")

print("   ✅ roc_curves.png")

# ============================================
# 4. PRECISION-RECALL CURVES
# ============================================
print(f"\n{'='*70}")
print("📉 4. PRECISION-RECALL CURVES")
print(f"{'='*70}")

plt.figure(figsize=(10, 8))

for i, (name, model) in enumerate(models.items()):
    y_prob = model.predict_proba(X)[:, 1]
    precision, recall, _ = precision_recall_curve(y, y_prob)
    pr_auc = auc(recall, precision)
    
    plt.plot(recall, precision, color=colors[i % len(colors)], linewidth=2,
             label=f'{name} (PR-AUC = {pr_auc:.3f})')

# Baseline
baseline = y.sum() / len(y)
plt.axhline(y=baseline, color='gray', linestyle='--', alpha=0.5,
            label=f'Baseline ({baseline:.1%})')

plt.xlabel('Recall', fontsize=12)
plt.ylabel('Precision', fontsize=12)
plt.title('PRECISION-RECALL CURVES', fontsize=14, fontweight='bold')
plt.legend(loc='best', fontsize=10)
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(f'{OUTPUT_DIR}/precision_recall_curves.png', dpi=150, bbox_inches='tight')
plt.close()
print("   ✅ precision_recall_curves.png")

# ============================================
# 5. MODEL COMPARISON BAR CHART
# ============================================
print(f"\n{'='*70}")
print("📊 5. MODEL COMPARISON")
print(f"{'='*70}")

fig, axes = plt.subplots(1, 2, figsize=(14, 5))

names = list(results.keys())
accuracies = [results[n]['accuracy'] for n in names]
f1_scores = [results[n]['f1'] for n in names]

# Accuracy bars
bars1 = axes[0].bar(names, accuracies, color=['#ff4444', '#58a6ff', '#00ff41'][:len(names)])
axes[0].set_title('Accuracy Comparison', fontweight='bold')
axes[0].set_ylabel('Accuracy')
axes[0].set_ylim(0.8, 1.0)
for bar, acc in zip(bars1, accuracies):
    axes[0].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.005,
                f'{acc:.1%}', ha='center', fontweight='bold')

# F1 bars
bars2 = axes[1].bar(names, f1_scores, color=['#ff8800', '#58a6ff', '#00ff41'][:len(names)])
axes[1].set_title('F1-Score Comparison', fontweight='bold')
axes[1].set_ylabel('F1-Score')
axes[1].set_ylim(0.5, 1.0)
for bar, f1 in zip(bars2, f1_scores):
    axes[1].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.005,
                f'{f1:.1%}', ha='center', fontweight='bold')

plt.suptitle('MODEL PERFORMANCE COMPARISON', fontsize=14, fontweight='bold')
plt.tight_layout()
plt.savefig(f'{OUTPUT_DIR}/model_comparison.png', dpi=150, bbox_inches='tight')
plt.close()
print("   ✅ model_comparison.png")

# ============================================
# 6. FEATURE IMPORTANCE (for tree models)
# ============================================
print(f"\n{'='*70}")
print("🔍 6. FEATURE IMPORTANCE")
print(f"{'='*70}")

for name, model in models.items():
    if hasattr(model, 'feature_importances_'):
        importance = model.feature_importances_
        
        plt.figure(figsize=(10, 5))
        sorted_idx = np.argsort(importance)
        plt.barh(range(len(FEATURES)), importance[sorted_idx], color='steelblue')
        plt.yticks(range(len(FEATURES)), [FEATURES[i] for i in sorted_idx])
        plt.title(f'{name} - Feature Importance', fontweight='bold')
        plt.xlabel('Importance')
        
        for i, v in enumerate(importance[sorted_idx]):
            plt.text(v + 0.01, i, f'{v:.3f}', va='center')
        
        plt.tight_layout()
        plt.savefig(f'{OUTPUT_DIR}/feature_importance_{name.lower().replace(" ", "_")}.png', 
                   dpi=150, bbox_inches='tight')
        plt.close()
        
        print(f"\n   {name}:")
        for feat, imp in sorted(zip(FEATURES, importance), key=lambda x: x[1], reverse=True):
            bar = "█" * int(imp * 50)
            print(f"   {feat:20s} {bar} {imp:.3f}")

print(f"\n   ✅ feature_importance_*.png")

# ============================================
# 7. ERROR ANALYSIS
# ============================================
print(f"\n{'='*70}")
print("🔍 7. ERROR ANALYSIS")
print(f"{'='*70}")

for name, model in models.items():
    y_pred = results[name]['y_pred']
    
    # False Positives (Normal predicted as Threat)
    fp_mask = (y == 0) & (y_pred == 1)
    fp_count = fp_mask.sum()
    
    # False Negatives (Threat predicted as Normal)
    fn_mask = (y == 1) & (y_pred == 0)
    fn_count = fn_mask.sum()
    
    print(f"\n   {name}:")
    print(f"   ❌ False Positives: {fp_count} ({100*fp_count/len(y):.1f}%)")
    print(f"   ❌ False Negatives: {fn_count} ({100*fn_count/len(y):.1f}%)")
    
    # Analyze false negatives
    if fn_count > 0:
        fn_data = df[fn_mask][FEATURES]
        print(f"   📊 False Negative Profile (avg):")
        for feat in FEATURES:
            print(f"      {feat}: {fn_data[feat].mean():.1f}")

# ============================================
# 8. SUMMARY REPORT
# ============================================
print(f"\n{'='*70}")
print("📋 8. FINAL SUMMARY")
print(f"{'='*70}")

# Find best model
best_model = max(results.items(), key=lambda x: x[1]['f1'])
print(f"\n   🏆 BEST MODEL: {best_model[0]}")
print(f"      Accuracy: {best_model[1]['accuracy']:.1%}")
print(f"      F1-Score:  {best_model[1]['f1']:.1%}")

# Performance table
print(f"\n   {'Model':<20s} {'Accuracy':>10s} {'F1-Score':>10s} {'Status':>10s}")
print(f"   {'─'*50}")
for name, res in results.items():
    status = '🏆 BEST' if name == best_model[0] else '✅ Ready' if res['accuracy'] > 0.9 else '⚠️ Tune'
    print(f"   {name:<20s} {res['accuracy']:>9.1%} {res['f1']:>9.1%} {status:>10s}")

# Output files
print(f"\n📁 Output files:")
import glob
for f in sorted(glob.glob(f'{OUTPUT_DIR}/*.png')):
    size = os.path.getsize(f) // 1024
    print(f"   📊 {os.path.basename(f)} ({size} KB)")

print(f"\n{'='*70}")
print(f"✅ EVALUATION COMPLETE!")
print(f"{'='*70}")
print(f"📁 All results: {OUTPUT_DIR}/")
