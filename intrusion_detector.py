# intrusion_detector.py
# AI-Based Intrusion Detection System (Starter Version)
# Author: Chukwuma Paul

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# ---- Step 1: Create a small synthetic dataset ----
data = {
    "duration": [10, 0, 5, 2, 8, 20],
    "protocol": ["tcp", "udp", "tcp", "icmp", "tcp", "udp"],
    "src_bytes": [100, 2000, 300, 50, 1200, 400],
    "dst_bytes": [500, 0, 100, 2000, 100, 20],
    "flag": ["SF", "REJ", "SF", "SF", "S0", "REJ"],
    "intrusion": [0, 1, 0, 0, 1, 1]  # 1 = attack, 0 = normal
}

df = pd.DataFrame(data)

# ---- Step 2: Preprocess data ----
encoder = LabelEncoder()
df["protocol"] = encoder.fit_transform(df["protocol"])
df["flag"] = encoder.fit_transform(df["flag"])

X = df.drop("intrusion", axis=1)
y = df["intrusion"]

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ---- Step 3: Train/Test split ----
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.3, random_state=42)

# ---- Step 4: Train model ----
model = RandomForestClassifier(random_state=42)
model.fit(X_train, y_train)

# ---- Step 5: Evaluate model ----
y_pred = model.predict(X_test)
print("Model Accuracy:", round(accuracy_score(y_test, y_pred)*100, 2), "%")
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# ---- Step 6: Test on custom connection ----
custom_input = pd.DataFrame({
    "duration": [6],
    "protocol": [encoder.transform(["tcp"])[0]],
    "src_bytes": [800],
    "dst_bytes": [100],
    "flag": [encoder.transform(["SF"])[0]]
})

custom_scaled = scaler.transform(custom_input)
prediction = model.predict(custom_scaled)[0]

if prediction == 1:
    print("\n⚠️ Suspicious connection detected: Possible intrusion!")
else:
    print("\n✅ Connection appears normal.")
