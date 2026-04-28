import joblib, pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
import seaborn as sns
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')

# ========== CORRECT PATHS ==========
MODEL_PATH = '/home/wind/cybersec-platform/ml/models/rf_model_noisy.pkl'
DATASET_PATH = '/home/wind/cybersec-platform/ml/training/security_dataset_noisy.csv'

# Load model
print("📦 Loading model...")
model = joblib.load(MODEL_PATH)
print(f"✅ Model loaded: {type(model).__name__}")

# Load dataset
print("📊 Loading dataset...")
df = pd.read_csv(DATASET_PATH)
print(f"✅ Dataset: {df.shape[0]} rows, {df.shape[1]} columns")

# Features
features = ['hour_of_day', 'files_accessed', 'login_attempts',
            'foreign_ip', 'unknown_device', 'data_uploaded_mb']

X = df[features]
y = df['is_threat']

# Predictions
print("🔮 Making predictions...")
y_pred = model.predict(X)
y_prob = model.predict_proba(X)[:, 1]

# ========== RESULTS ==========
print("\n" + "="*60)
print("📊 MODEL PERFORMANCE REPORT")
print("="*60)

# 1. Classification Report
print("\n📋 Classification Report:")
print("-"*50)
print(classification_report(y, y_pred, target_names=['✅ Normal', '🚨 Threat']))

# 2. Confusion Matrix
cm = confusion_matrix(y, y_pred)
print("\n📐 Confusion Matrix:")
print("-"*50)
print(f"True Normal:  {cm[0][0]:5d} | False Threat: {cm[0][1]:5d}")
print(f"False Normal: {cm[1][0]:5d} | True Threat:  {cm[1][1]:5d}")

# 3. Key Metrics
tn, fp, fn, tp = cm.ravel()
accuracy = (tp + tn) / (tp + tn + fp + fn)
precision = tp / (tp + fp) if (tp + fp) > 0 else 0
recall = tp / (tp + fn) if (tp + fn) > 0 else 0
f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
auc = roc_auc_score(y, y_prob)

print(f"\n🎯 Key Metrics:")
print("-"*50)
print(f"Accuracy:  {accuracy:.3f} ({accuracy*100:.1f}%)")
print(f"Precision: {precision:.3f} ({precision*100:.1f}%)")
print(f"Recall:    {recall:.3f} ({recall*100:.1f}%)")
print(f"F1 Score:  {f1:.3f}")
print(f"AUC-ROC:   {auc:.3f}")

# 4. Feature Importance (Random Forest specific)
if hasattr(model, 'feature_importances_'):
    print(f"\n📈 Feature Importance:")
    print("-"*50)
    for feat, imp in sorted(zip(features, model.feature_importances_),
                            key=lambda x: x[1], reverse=True):
        bar = "█" * int(imp * 50)
        print(f"  {feat:20s}: {imp:.3f} {bar}")

# ========== PLOTS ==========
print("\n📊 Generating plots...")

fig, axes = plt.subplots(2, 2, figsize=(14, 12))
fig.suptitle('🛡️ Model Evaluation Dashboard', fontsize=16, fontweight='bold', color='#00ff00')
fig.patch.set_facecolor('#0a0a0f')

# Plot 1: Confusion Matrix
sns.heatmap(cm, annot=True, fmt='d', cmap='Reds',
            xticklabels=['Normal', 'Threat'],
            yticklabels=['Normal', 'Threat'],
            ax=axes[0, 0], cbar=False, annot_kws={'size': 20, 'fontweight': 'bold'})
axes[0, 0].set_title('Confusion Matrix', color='white', fontsize=12)
axes[0, 0].set_ylabel('Actual', color='white')
axes[0, 0].set_xlabel('Predicted', color='white')

# Plot 2: ROC Curve
fpr, tpr, _ = roc_curve(y, y_prob)
axes[0, 1].plot(fpr, tpr, 'c-', linewidth=2, label=f'AUC = {auc:.3f}')
axes[0, 1].plot([0, 1], [0, 1], 'r--', alpha=0.5, label='Random')
axes[0, 1].fill_between(fpr, tpr, alpha=0.3, color='cyan')
axes[0, 1].set_title('ROC Curve', color='white', fontsize=12)
axes[0, 1].set_xlabel('False Positive Rate', color='white')
axes[0, 1].set_ylabel('True Positive Rate', color='white')
axes[0, 1].legend(framealpha=0.3)
axes[0, 1].grid(True, alpha=0.3)

# Plot 3: Feature Importance
if hasattr(model, 'feature_importances_'):
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    colors = ['#ff0000' if imp > 0.2 else '#ff6600' if imp > 0.1 else '#00ff00'
             for imp in importances[indices]]
    axes[1, 0].barh(range(len(indices)), importances[indices], color=colors)
    axes[1, 0].set_yticks(range(len(indices)))
    axes[1, 0].set_yticklabels([features[i] for i in indices], color='white')
    axes[1, 0].set_title('Feature Importance', color='white', fontsize=12)
    axes[1, 0].set_xlabel('Importance Score', color='white')

# Plot 4: Score Distribution
axes[1, 1].hist(y_prob[y == 0], bins=30, alpha=0.7, color='green', label='Normal')
axes[1, 1].hist(y_prob[y == 1], bins=30, alpha=0.7, color='red', label='Threat')
axes[1, 1].axvline(x=0.7, color='yellow', linestyle='--', linewidth=2, label='Threshold (0.7)')
axes[1, 1].set_title('Prediction Score Distribution', color='white', fontsize=12)
axes[1, 1].set_xlabel('Threat Score', color='white')
axes[1, 1].set_ylabel('Count', color='white')
axes[1, 1].legend(framealpha=0.3)

# Style all subplots
for ax in axes.flat:
    ax.set_facecolor('#0a0a0f')
    ax.tick_params(colors='white')
    for spine in ax.spines.values():
        spine.set_color('#333')

plt.tight_layout()
plt.savefig('/home/wind/cybersec-platform/tests/model_evaluation_report.png',
            dpi=150, bbox_inches='tight', facecolor='#0a0a0f')
print("✅ Report saved: model_evaluation_report.png")

# Save report to file
report = f"""
MODEL EVALUATION REPORT
{'='*60}
Model: {type(model).__name__}
Dataset: {df.shape[0]} rows
Date: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}

PERFORMANCE METRICS:
  Accuracy:  {accuracy:.3f}
  Precision: {precision:.3f}
  Recall:    {recall:.3f}
  F1 Score:  {f1:.3f}
  AUC-ROC:   {auc:.3f}

CONFUSION MATRIX:
  True Normal:  {tn}
  False Threat: {fp}
  False Normal: {fn}
  True Threat:  {tp}
"""

with open('/home/wind/cybersec-platform/tests/evaluation_report.txt', 'w') as f:
    f.write(report)

print("📄 Report saved: evaluation_report.txt")
print("\n✅ Evaluation Complete!")
