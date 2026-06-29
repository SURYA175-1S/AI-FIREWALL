import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from joblib import dump, load
import pyshark
import warnings, contextlib, random, os
try:
    import llama  
except ImportError:
    pass 
warnings.filterwarnings("ignore")

# === Load dataset and train ===
data = pd.read_csv('dataset_demo.csv')  # <-- Dataset loaded here
data.columns = data.columns.str.strip()

categorical_cols = data.select_dtypes(include='object').columns.tolist()
encoders = {}
for col in categorical_cols:
    le = LabelEncoder()
    data[col] = le.fit_transform(data[col])
    encoders[col] = le

X = data.drop('label', axis=1)
y = data['label']

from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)  # <-- Model is trained here

dump(model, 'firewall_model.joblib')  # <-- Trained model saved
dump(encoders, 'encoders.joblib')     # <-- Encoders saved

# === Load trained model for live use ===
clf = load('firewall_model.joblib')   # <-- Trained model loaded here
encoders = load('encoders.joblib')    # <-- Encoders loaded here

# === Reason tags for malicious packets ===
malicious_reasons = [
    "Port Scan", "Flood Attack", "Spoof Attempt", 
    "Abnormal Size", "Flag Misuse", "Rapid Requests"
]

def process_packet(pkt):
    try:
        src_ip = pkt.ip.src if hasattr(pkt.ip, 'src') else '0.0.0.0'
        dst_ip = pkt.ip.dst if hasattr(pkt.ip, 'dst') else '0.0.0.0'

        if hasattr(pkt, pkt.transport_layer.lower()):
            src_port = int(pkt[pkt.transport_layer].srcport)
            dst_port = int(pkt[pkt.transport_layer].dstport)
        else:
            src_port = dst_port = 0

        protocol = 1 if pkt.transport_layer == 'TCP' else 2
        packet_size = int(pkt.length)
        flags = pkt.tcp.flags if pkt.transport_layer == 'TCP' else 'None'

        df = pd.DataFrame([{
            'src_ip': src_ip,'dst_ip': dst_ip,'src_port': src_port,
            'dst_port': dst_port,'protocol': protocol,'packet_size': packet_size,'flags': flags
        }])
        for col in categorical_cols:
            if col in df.columns:
                df[col] = encoders[col].fit_transform(df[col])

        pred = clf.predict(df)[0]  # <-- Prediction using trained model
        if pred == 1:
            
            reason = random.choice(malicious_reasons)
            print(f"\n🚨 Blocked | Suspicious traffic detected!\n"
                  f"↳ From: {src_ip}  →  {dst_ip}\n"
                  f"↳ Port: {dst_port}  |  Size: {packet_size}\n"
                  f"↳ Reason: {reason}\n")
        else:
            print(f"\n✅ Allowed | Normal communication\n"
                  f"↳ Between: {src_ip}  ↔  {dst_ip}\n"
                  f"↳ Port: {dst_port}  |  Size: {packet_size}\n")

    except Exception:
        pass

# === Start capture ===
print("🛡️ AI Firewall Live Monitoring Started...\nPress Ctrl+C to stop.\n")
capture = pyshark.LiveCapture(interface='Wi-Fi')  # Change interface if needed

try:
    with contextlib.suppress(EOFError):
        for packet in capture.sniff_continuously():
            process_packet(packet)
except KeyboardInterrupt:
    print("\n🛑 Monitoring stopped by user.\n")
    os._exit(0)
