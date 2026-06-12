import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

print("Loading network telemetry logs...")

df = pd.read_csv("network_traffic_logs.csv") #  Load the data generated in Phase 1


features = ['Packet_Count', 'Byte_Volume_KB', 'Failed_Logins'] #  Select Features for the AI
# The AI only looks at numerical behaviors, not IP strings or timestamps
X = df[features]

print(f"Training Unsupervised Isolation Forest model on features: {features}...")

model = IsolationForest(contamination=0.01, random_state=42) # Initialize the Machine Learning Model
# We set contamination=0.01 (1%) because we assume anomalies are rare in enterprise traffic

df['AI_Raw_Prediction'] = model.fit_predict(X) 
# 4. Fit the model and predict anomalies
# Isolation Forest outputs: 1 for normal data, -1 for an anomaly/outlier

# 5. Convert AI predictions to match our validation label format
# Convert 1 (normal) -> 0, and convert -1 (anomaly) -> 1
df['AI_Is_Anomaly'] = df['AI_Raw_Prediction'].apply(lambda x: 1 if x == -1 else 0)

print("\n--- Model Evaluation vs Hidden Truth ---")
# 6. Calculate Confusion Matrix metrics
# True Negative (TN), False Positive (FP), False Negative (FN), True Positive (TP)
tn, fp, fn, tp = confusion_matrix(df['Is_Anomaly'], df['AI_Is_Anomaly']).ravel()

print(f"Successfully caught Threats (True Positives): {tp} / 50")
print(f"False Alarms Generated (False Positives): {fp}")
print(f"Missed Threats (False Negatives): {fn}")

print("\n--- Detailed Security Performance Report ---")
print(classification_report(df['Is_Anomaly'], df['AI_Is_Anomaly'], target_names=['Normal Traffic', 'Malicious Attack']))

# 7. Save a quick triage list of flagged alerts for SOC review
flagged_alerts = df[df['AI_Is_Anomaly'] == 1][['Timestamp', 'Source_IP', 'Packet_Count', 'Byte_Volume_KB', 'Failed_Logins']]
flagged_alerts.to_csv("soc_alerts_triage.csv", index=False)
print("\nSuccess! Generated 'soc_alerts_triage.csv' containing malicious endpoints for analyst review.")