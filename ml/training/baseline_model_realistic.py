import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

df = pd.read_csv('security_dataset_noisy.csv')

features = ['hour_of_day','files_accessed','login_attempts',
            'foreign_ip','unknown_device','data_uploaded_mb']

X = df[features]
y = df['is_threat']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Model save karo
joblib.dump(model, '../models/rf_model_realistic.pkl')
print("Model saved!")
