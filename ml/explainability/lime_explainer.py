import lime
import lime.lime_tabular
import joblib
import pandas as pd
import numpy as np
import warnings
warnings.filterwarnings('ignore')

print("=" * 60)
print("🔍 LIME EXPLAINABILITY - Random Forest Model")
print("=" * 60)

# Load RF model (XGBoost has issues with LIME)
try:
    model = joblib.load('../models/xgb_model_noisy.pkl')
    model_name = "XGBoost"
    print(f"\n✅ {model_name} loaded")
except:
    model = joblib.load('../models/rf_model_noisy.pkl')
    model_name = "Random Forest"
    print(f"\n✅ {model_name} loaded (fallback)")

# Load data
df = pd.read_csv('../training/security_dataset.csv')
features = ['hour_of_day', 'files_accessed', 'login_attempts',
            'foreign_ip', 'unknown_device', 'data_uploaded_mb']
X = df[features].values

print(f"📊 Data: {X.shape[0]} samples, {X.shape[1]} features")
print(f"🎯 Model: {model_name}")

# Create LIME explainer
print("\n🧮 Creating LIME explainer...")
explainer = lime.lime_tabular.LimeTabularExplainer(
    training_data=X,
    feature_names=features,
    class_names=['✅ Normal', '🚨 Threat'],
    mode='classification',
    discretize_continuous=True
)
print("✅ Explainer ready!")

# ============================================
# Test Cases
# ============================================
test_cases = [
    {
        'title': 'Obvious Threat (3AM, 8000 files, Foreign)',
        'data': np.array([3, 8000, 10, 1, 1, 2000]),
        'expected': '🚨 THREAT'
    },
    {
        'title': 'Normal Worker (10AM, 30 files, Local)',
        'data': np.array([10, 30, 1, 0, 0, 10]),
        'expected': '✅ NORMAL'
    },
    {
        'title': 'Late Night Worker (11PM, 200 files)',
        'data': np.array([23, 200, 2, 0, 0, 100]),
        'expected': '⚠️ BORDERLINE'
    },
    {
        'title': 'Stealth Insider (9AM, 150 files, Local)',
        'data': np.array([9, 150, 1, 0, 0, 200]),
        'expected': '✅ NORMAL?'
    }
]

print("\n" + "=" * 60)
print("🔍 ANALYZING TEST CASES")
print("=" * 60)

for test in test_cases:
    print(f"\n{'='*50}")
    print(f"📋 {test['title']}")
    print(f"{'='*50}")

    # Model prediction
    proba = model.predict_proba(test['data'].reshape(1, -1))[0]
    threat_score = proba[1] if len(proba) > 1 else proba[0]

    emoji = "🚨" if threat_score > 0.7 else "⚠️" if threat_score > 0.4 else "✅"
    print(f"{emoji} Model Prediction: {threat_score:.1%} threat")
    print(f"   Expected: {test['expected']}")

    # LIME explanation
    print(f"\n📊 LIME Feature Contributions:")
    print("-" * 40)

    exp = explainer.explain_instance(
        test['data'],
        model.predict_proba,
        num_features=6,
        num_samples=5000
    )

    # Show feature contributions
    lime_list = exp.as_list()
    for feat, weight in lime_list:
        direction = "🔺 Increases threat" if weight > 0 else "🔻 Decreases threat"
        bar_len = min(int(abs(weight) * 100), 40)
        bar = "█" * bar_len
        print(f"  {direction} {feat:25s} {bar} ({weight:+.3f})")

    # Show prediction probabilities
    print(f"\n  Final prediction: {exp.predict_proba}")

    # Save HTML
    filename = f"lime_{test['title'].lower().replace(' ', '_').replace('(', '').replace(')', '').replace(',', '')[:40]}.html"
    exp.save_to_file(filename)
    print(f"  📄 Saved: {filename}")

# ============================================
# Special: Explain why normal user flagged
# ============================================
print("\n" + "=" * 60)
print("🔍 BORDERLINE CASE ANALYSIS")
print("=" * 60)

print("\n📋 Why might a normal-looking user be flagged?")
borderline = np.array([10, 100, 3, 1, 0, 50])

proba = model.predict_proba(borderline.reshape(1, -1))[0]
threat_score = proba[1] if len(proba) > 1 else proba[0]
print(f"   Threat Score: {threat_score:.1%}")

exp = explainer.explain_instance(
    borderline,
    model.predict_proba,
    num_features=6,
    num_samples=5000
)

print(f"\n   Key factors:")
for feat, weight in exp.as_list()[:3]:
    direction = "⚠️ Risk" if weight > 0 else "✅ Safe"
    print(f"     {direction}: {feat} ({weight:+.3f})")

# Save
exp.save_to_file('lime_borderline_case.html')

# ============================================
# Feature Importance Summary
# ============================================
print("\n" + "=" * 60)
print("📊 AGGREGATE ANALYSIS")
print("=" * 60)

print("\nTesting multiple samples to find common patterns...")
feature_impacts = {feat: [] for feat in features}

for _ in range(20):
    random_sample = X[np.random.randint(0, len(X))]
    exp = explainer.explain_instance(
        random_sample,
        model.predict_proba,
        num_features=6,
        num_samples=2000
    )
    for feat, weight in exp.as_list():
        # Match to base feature names
        for base_feat in features:
            if base_feat in feat:
                feature_impacts[base_feat].append(weight)
                break

print("\n📈 Average Feature Impact (across 20 samples):")
print("-" * 50)
for feat in features:
    if feature_impacts[feat]:
        avg = np.mean(np.abs(feature_impacts[feat]))
        bar = "█" * int(avg * 200)
        print(f"  {feat:20s} {bar} ({avg:.3f})")

print("\n" + "=" * 60)
print("✅ LIME ANALYSIS COMPLETE!")
print("=" * 60)
print(f"\n📁 Output files:")
import glob
for f in sorted(glob.glob('lime_*.html')):
    size = __import__('os').path.getsize(f) / 1024
    print(f"   📄 {f} ({size:.0f} KB)")
print(f"\n💡 Open in browser: firefox lime_obvious_threat*.html")
