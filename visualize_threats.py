import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest

df = pd.read_csv("network_traffic_logs.csv")
features = ['Packet_Count', 'Byte_Volume_KB', 'Failed_Logins']

# Re-run ML model to generate labels for the scatter plot
model = IsolationForest(contamination=0.01, random_state=42)
df['AI_Prediction'] = model.fit_predict(df[features])

# Map numerical predictions to readable strings for the graph legend
df['Traffic_Type'] = df['AI_Prediction'].map({-1: 'Malicious Anomaly', 1: 'Normal Baseline'})

plt.figure(figsize=(12, 7))
sns.set_theme(style="darkgrid")

sns.scatterplot(
    data=df,
    x='Packet_Count',
    y='Byte_Volume_KB',
    hue='Traffic_Type',
    palette={'Normal Baseline': '#2ecc71', 'Malicious Anomaly': '#e74c3c'},
    alpha=0.75,
    edgecolor=None
)

plt.title('Unsupervised Network Anomaly Detection', fontsize=14, fontweight='bold')
plt.xlabel('Packet Count (Per Minute)')
plt.ylabel('Data Volume Transferred (KB)')
plt.legend(loc='upper right')

plt.savefig("soc_threat_dashboard.png", dpi=300, bbox_inches='tight')