import pandas as pd
import numpy as np
from datetime import datetime, timedelta

print("Starting data generation engine...")

# Set random seed for reproducibility
np.random.seed(42)

num_normal = 10000
num_anomalies = 50
total_records = num_normal + num_anomalies

# 1. Generate Timestamps over a 24-hour window
start_time = datetime(2026, 6, 10, 0, 0, 0)
timestamps = [start_time + timedelta(seconds=int(np.random.randint(0, 86400))) for _ in range(total_records)]

# 2. Generate Base normal traffic profiles
# Features: [Packet_Count, Byte_Volume_KB, Failed_Logins]
# Normal users send low-to-moderate packets, small byte sizes, and rarely fail logins
normal_packets = np.random.poisson(lam=15, size=num_normal)
normal_bytes = np.random.normal(loc=150, scale=30, size=num_normal)
normal_logins = np.random.choice([0, 1], p=[0.98, 0.02], size=num_normal) # 98% have 0 failed logins

# 3. Generate Malicious traffic profiles (The Anomalies)
# Scenario A: Brute force attack (High failed logins, low traffic volume)
anomaly_logins_bf = np.random.randint(15, 45, size=25)
anomaly_packets_bf = np.random.poisson(lam=5, size=25)
anomaly_bytes_bf = np.random.normal(loc=20, scale=5, size=25)

# Scenario B: Data Exfiltration / DDoS (Massive packet count and byte volume)
anomaly_logins_ex = np.zeros(25)
anomaly_packets_ex = np.random.randint(500, 1500, size=25)
anomaly_bytes_ex = np.random.normal(loc=8000, scale=1000, size=25)

# Combine anomaly scenarios
anomaly_packets = np.concatenate([anomaly_packets_bf, anomaly_packets_ex])
anomaly_bytes = np.concatenate([anomaly_bytes_bf, anomaly_bytes_ex])
anomaly_logins = np.concatenate([anomaly_logins_bf, anomaly_logins_ex])

# 4. Merge Normal and Anomalous Data
all_packets = np.concatenate([normal_packets, anomaly_packets])
all_bytes = np.clip(np.concatenate([normal_bytes, anomaly_bytes]), 1, None) # No negative bytes
all_logins = np.concatenate([normal_logins, anomaly_logins])

# 5. Create IP addresses
source_ips = [f"192.168.1.{np.random.randint(2, 254)}" for _ in range(num_normal)]
# Give the anomalies specific suspicious external/internal IPs
suspicious_ips = [f"10.0.5.{np.random.randint(2, 50)}" for _ in range(num_anomalies)]
all_ips = source_ips + suspicious_ips

# 6. Construct DataFrame and Label (Label is ONLY for checking our work later, not for training the AI!)
df = pd.DataFrame({
    'Timestamp': timestamps,
    'Source_IP': all_ips,
    'Packet_Count': all_packets,
    'Byte_Volume_KB': all_bytes,
    'Failed_Logins': all_logins,
    'Is_Anomaly': [0] * num_normal + [1] * num_anomalies # 0 = normal, 1 = attack
})

# Shuffle the dataset so the anomalies are hidden randomly throughout the day
df = df.sample(frac=1).reset_index(drop=True)

# Save to CSV
output_file = "network_traffic_logs.csv"
df.to_csv(output_file, index=False)

print(f"Success! Generated {total_records} logs and saved to '{output_file}'.")
print(f"Baseline contains {num_normal} normal logs and {num_anomalies} hidden threats.")