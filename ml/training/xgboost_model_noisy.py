import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import joblib

df = pd.read_csv('security_dataset_noisy.csv')
features = ['hour_of_day','files_accessed','login_attempts',
            'foreign_ip','unknown_device','data_uploaded_mb']

X = df[features]
y = df['is_threat']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

model = xgb.XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    scale_pos_weight=5,  # imbalanced data handle karo
    random_state=42
)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("=== XGBoost Results ===")
print(classification_report(y_test, y_pred))
print(f"AUC Score: {roc_auc_score(y_test, y_pred):.3f}")

joblib.dump(model, '../models/xgb_model_noisy.pkl')
print("XGBoost model saved!")
