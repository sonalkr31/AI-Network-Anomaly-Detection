import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

# Load dataset
df = pd.read_csv("network_traffic_logs.csv")

# Isolate numerical features for behavioral analysis (dropping metadata like IP/Timestamp)
features = ['Packet_Count', 'Byte_Volume_KB', 'Failed_Logins']
X = df[features]

# Init Isolation Forest
# Contamination fixed at 0.01 based on assumed 1% anomaly rate in baseline telemetry
model = IsolationForest(contamination=0.01, random_state=42)

# Fit model and map output (-1 = anomaly, 1 = normal) to standard binary labels (1 = anomaly, 0 = normal)
df['AI_Raw'] = model.fit_predict(X)
df['AI_Is_Anomaly'] = df['AI_Raw'].map({-1: 1, 1: 0})

# Calculate evaluation metrics vs hidden validation column
tn, fp, fn, tp = confusion_matrix(df['Is_Anomaly'], df['AI_Is_Anomaly']).ravel()

print(f"TP: {tp} | FP: {fp} | FN: {fn}\n")
print(classification_report(df['Is_Anomaly'], df['AI_Is_Anomaly']))

# Extract flagged alerts and export for analyst triage
alerts = df[df['AI_Is_Anomaly'] == 1][['Timestamp', 'Source_IP', 'Packet_Count', 'Byte_Volume_KB', 'Failed_Logins']]
alerts.to_csv("soc_alerts_triage.csv", index=False)