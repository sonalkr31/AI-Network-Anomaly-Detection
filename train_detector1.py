from pyexpat import model

import pandas as pd # type: ignore
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report,confusion_matrix

print ("Loading network telemetry logs..")
df = pd.read_csv("network_traffic_log.csv") #loding the generated data

feature = ['Packet_count','Byte_volume_KB',"Failed_logins"] # for Ai to see num var behaviours , not ip strings or timestamps
print(f"Training Unsupervised isolation for Forest model on features: {feature}......") 

model = IsolationForest(contamination=0.01,random_state=42) # ML works here (learnig model) we set conatmination 0.1%, assuming  anomalies are rare in entprise traffeic as usual
df['AI_Is_Anomaly'] = df['AI_Raw_Prediction'].apply(lambda x: 1 if x == -1 else 0)
# Convert AI predictions to match our validation label format
# Convert 1 (normal) -> 0, and convert -1 (anomaly) -> 1

print("\n-- Model Evaluation vs Hidden Truth --") # 
tn, fp, fn, tp = confusion_matrix(df['Is_Anomaly'], df['AI_Is_Anomaly']).ravel()
#  Calculate Confusion Matrix metrics
# True Negative (TN), False Positive (FP), False Negative (FN), True Positive (TP)

print(f"Successfully caught Threats (True Positives): {tp} / 50")
print(f"False Alarms Generated (False Positives): {fp}")
print(f"Missed Threats (False Negatives): {fn}")

print("\n--- Detailed Security Performance Report ---")
print(classification_report(df['Is_Anomaly'], df['AI_Is_Anomaly'], target_names=['Normal Traffic', 'Malicious Attack']))

# Save a quick triage list of flagged alerts for SOC review
flagged_alerts = df[df['AI_Is_Anomaly'] == 1][['Timestamp', 'Source_IP', 'Packet_Count', 'Byte_Volume_KB', 'Failed_Logins']]
flagged_alerts.to_csv("soc_alerts_triage.csv", index=False)
print("\nSuccess! Generated 'soc_alerts_triage.csv' containing malicious endpoints for analyst review.")