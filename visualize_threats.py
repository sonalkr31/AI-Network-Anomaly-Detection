import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest

print("Loading data for SOC Dashboard Visualization...")
# 1. Load the original dataset
df = pd.read_csv("network_traffic_logs.csv")
features = ['Packet_Count', 'Byte_Volume_KB', 'Failed_Logins']

# 2. Run the Isolation Forest AI again to get the labels for the graph
model = IsolationForest(contamination=0.01, random_state=42)
df['AI_Prediction'] = model.fit_predict(df[features])

# Convert predictions to readable labels for the graph legend
df['Traffic_Type'] = df['AI_Prediction'].apply(lambda x: 'Malicious Anomaly' if x == -1 else 'Normal Baseline')

print("Generating Threat Hunting Scatter Plot...")
# 3. Configure the aesthetic style of the graph
plt.figure(figsize=(12, 7))
sns.set_theme(style="darkgrid")

# 4. Create the scatter plot
# We plot Packet Count vs Data Volume to visually separate the attacks
sns.scatterplot(
    data=df,
    x='Packet_Count',
    y='Byte_Volume_KB',
    hue='Traffic_Type',
    palette={'Normal Baseline': '#2ecc71', 'Malicious Anomaly': '#e74c3c'}, # Green for normal, Red for attacks
    alpha=0.7,
    edgecolor=None
)

# 5. Add professional titles and labels
plt.title('SOC AI: Unsupervised Network Anomaly Detection', fontsize=16, fontweight='bold', pad=15)
plt.xlabel('Packet Count (Per Minute)', fontsize=12, fontweight='bold')
plt.ylabel('Data Volume Transferred (KB)', fontsize=12, fontweight='bold')
plt.legend(title='AI Classification', loc='upper right')

# 6. Save the graph as an image file
filename = "soc_threat_dashboard.png"
plt.savefig(filename, dpi=300, bbox_inches='tight')
print(f"Success! Visualization saved locally as '{filename}'.")