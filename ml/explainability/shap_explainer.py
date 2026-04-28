import shap
import joblib
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os, warnings
warnings.filterwarnings('ignore')

print("=" * 60)
print("🔍 SHAP ANALYSIS - Random Forest Model")
print("=" * 60)

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
output_dir = os.path.join(BASE_DIR, 'explainability')
os.makedirs(output_dir, exist_ok=True)

# Load RF Model
model_path = os.path.join(BASE_DIR, 'models', 'rf_model_noisy.pkl')
print(f"\n📂 Loading: {model_path}")
model = joblib.load(model_path)
print(f"✅ Random Forest loaded successfully!")

# Load dataset
data_path = os.path.join(BASE_DIR, 'training', 'security_dataset_noisy.csv')
if not os.path.exists(data_path):
    data_path = os.path.join(BASE_DIR, 'training', 'security_dataset_noisy.csv')

print(f"📊 Dataset: {data_path}")
df = pd.read_csv(data_path)
print(f"✅ {len(df)} records")

features = ['hour_of_day', 'files_accessed', 'login_attempts',
            'foreign_ip', 'unknown_device', 'data_uploaded_mb']
X = df[features].head(300)
print(f"✅ Features: {len(features)} | Samples: {len(X)}")

# ============================================
# SHAP ANALYSIS
# ============================================
print(f"\n🧮 Calculating SHAP...")
explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(X)

# RF returns [class0, class1] for binary
if isinstance(shap_values, list):
    print(f"   SHAP for both classes: {len(shap_values)} arrays")
    shap_vals = shap_values[:,:,1] if len(shap_values.shape)==3 else shap_values[:,:,1] if len(shap_values.shape)==3 else shap_values[1]  # Threat class
else:
    shap_vals = shap_values[:,:,1] if len(shap_values.shape)==3 else shap_values

print(f"   Shape: {shap_vals.shape}")

# ============================================
# 1. FEATURE IMPORTANCE
# ============================================
print("\n" + "=" * 60)
print("📊 FEATURE IMPORTANCE (SHAP)")
print("=" * 60)

importance = np.abs(shap_vals).mean(axis=0)
total = importance.sum()

print(f"\n{'Feature':<22s} {'Importance':>10s} {'%':>8s} {'Bar'}")
print("-" * 60)
for feat, imp in sorted(zip(features, importance), key=lambda x: x[1], reverse=True):
    pct = 100 * imp / total
    bar = "█" * int(pct)
    print(f"{feat:<22s} {imp:10.4f} {pct:7.1f}% {bar}")

# Save
importance_df = pd.DataFrame({
    'Feature': features,
    'SHAP_Importance': importance,
    'Percentage': 100 * importance / total
}).sort_values('SHAP_Importance', ascending=False)
importance_df.to_csv(f'{output_dir}/feature_importance.csv', index=False)
print(f"\n💾 Saved: feature_importance.csv")

# ============================================
# 2. SUMMARY PLOT
# ============================================
print("\n📈 Summary plot...")
plt.figure(figsize=(10, 6))
shap.summary_plot(shap_vals, X, feature_names=features, show=False)
plt.tight_layout()
plt.savefig(f'{output_dir}/shap_summary.png', dpi=150, bbox_inches='tight')
plt.close()
print("✅ shap_summary.png")

# ============================================
# 3. BAR PLOT
# ============================================
print("\n📊 Bar plot...")
plt.figure(figsize=(10, 5))
shap.summary_plot(shap_vals, X, feature_names=features, plot_type="bar", show=False)
plt.tight_layout()
plt.savefig(f'{output_dir}/shap_bar.png', dpi=150, bbox_inches='tight')
plt.close()
print("✅ shap_bar.png")

# ============================================
# 4. SINGLE PREDICTIONS
# ============================================
print("\n" + "=" * 60)
print("🔍 PREDICTION EXPLANATIONS")
print("=" * 60)

def explain(title, data_dict):
    df_single = pd.DataFrame([data_dict])
    proba = model.predict_proba(df_single)[0]
    threat_prob = proba[1]

    sv = explainer.shap_values(df_single)
    if isinstance(sv, list):
        sv = sv[1]
    if len(sv.shape) == 3:
        sv = sv[:,:,1]
    sv = sv[0]  # Single prediction

    emoji = "🚨" if threat_prob > 0.7 else "⚠️" if threat_prob > 0.4 else "✅"

    print(f"\n{'='*50}")
    print(f"📋 {title}")
    print(f"{'='*50}")
    print(f"{emoji} Threat Score: {threat_prob:.1%}")
    print(f"\nWhy? Feature Contributions:")

    impacts = []
    for feat, val, sv_val in zip(features, df_single.values[0], sv):
        direction = "🔺 RISK" if sv_val > 0 else "🔻 SAFE"
        impacts.append((abs(sv_val), feat, val, sv_val, direction))

    impacts.sort(reverse=True)

    for _, feat, val, sv_val, direction in impacts:
        bar_len = min(int(abs(sv_val) * 50), 50)
        bar = "█" * bar_len
        print(f"  {direction} {feat:20s} = {val:8.1f} | {sv_val:+.3f} {bar}")

    # Waterfall
    try:
        plt.figure(figsize=(10, 4))
        exp_val = explainer.expected_value
        if isinstance(exp_val, list):
            exp_val = exp_val[1]
        if isinstance(exp_val, np.ndarray):
            exp_val = float(exp_val)

        shap.waterfall_plot(
            shap.Explanation(values=sv, base_values=exp_val,
                           data=df_single.values[0], feature_names=features),
            show=False
        )
        plt.tight_layout()
        name = title.lower().replace(' ', '_')[:30]
        plt.savefig(f'{output_dir}/waterfall_{name}.png', dpi=150, bbox_inches='tight')
        plt.close()
        print(f"\n  📊 waterfall_{name}.png")
    except Exception as e:
        print(f"\n  ⚠️ Waterfall error: {e}")

# Test cases
tests = [
    ('Obvious Threat (3AM, 8000 files)',
     {'hour_of_day':3,'files_accessed':8000,'login_attempts':10,'foreign_ip':1,'unknown_device':1,'data_uploaded_mb':2000}),
    ('Normal Worker (10AM, 30 files)',
     {'hour_of_day':10,'files_accessed':30,'login_attempts':1,'foreign_ip':0,'unknown_device':0,'data_uploaded_mb':10}),
    ('Late Night (11PM, 200 files)',
     {'hour_of_day':23,'files_accessed':200,'login_attempts':2,'foreign_ip':0,'unknown_device':0,'data_uploaded_mb':100}),
    ('Stealth Insider (9AM, 150 files)',
     {'hour_of_day':9,'files_accessed':150,'login_attempts':1,'foreign_ip':0,'unknown_device':0,'data_uploaded_mb':200})
]

for title, data in tests:
    explain(title, data)

# ============================================
# 5. FORCE PLOT HTML
# ============================================
print("\n" + "=" * 60)
print("🌐 Saving interactive HTML...")

try:
    exp_val = explainer.expected_value
    if isinstance(exp_val, list):
        exp_val = exp_val[1]
    if isinstance(exp_val, np.ndarray):
        exp_val = float(exp_val)

    shap.save_html(
        f'{output_dir}/shap_force_plot.html',
        shap.force_plot(exp_val, shap_vals[:30], X[:30], feature_names=features)
    )
    print("✅ shap_force_plot.html")
except Exception as e:
    print(f"⚠️ Skipped: {e}")

# ============================================
# FINAL
# ============================================
print("\n" + "=" * 60)
print("✅ SHAP ANALYSIS COMPLETE!")
print("=" * 60)
print(f"\n📁 Output: {output_dir}/")
import glob
for f in sorted(glob.glob(f'{output_dir}/*')):
    size = os.path.getsize(f) / 1024
    print(f"   📄 {os.path.basename(f)} ({size:.0f} KB)")
print(f"\n💡 Browser open karo: {output_dir}/shap_force_plot.html")
