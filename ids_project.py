import time
import pandas as pd
import subprocess
from scapy.all import sniff
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from joblib import dump, load
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from sklearn.preprocessing import LabelEncoder
import numpy as np

# Global DataFrame to store traffic data
traffic_data = pd.DataFrame(columns=['timestamp', 'src_ip', 'dst_ip', 'protocol', 'packet_size', 'packet_rate', 'byte_rate'])

# Initialize LabelEncoder for IPs
le_ip = LabelEncoder()

# Function to fit the LabelEncoder to both source and destination IPs
def fit_ip_encoder(data):
    combined_ips = pd.concat([data['src_ip'], data['dst_ip']]).unique()
    le_ip.fit(combined_ips)

# Function to process packets in real-time
def process_packet(packet):
    global traffic_data

    if packet.haslayer('IP'):
        features = extract_features(packet)

        # Handle unseen IP addresses by encoding them dynamically
        src_ip_encoded = encode_ip(features[0])
        dst_ip_encoded = encode_ip(features[1])

        # Create a DataFrame for prediction with proper column names
        feature_names = ['src_ip', 'dst_ip', 'protocol', 'packet_size']
        encoded_features = pd.DataFrame([[src_ip_encoded, dst_ip_encoded, features[2], features[3]]], columns=feature_names)

        # Make predictions
        prediction = ml_model.predict(encoded_features)

        # Log the detection
        log_detection(features, prediction)

        # Update traffic data for visualization
        update_traffic_data(features)

# Dynamic encoding of unseen IPs
def encode_ip(ip):
    if not hasattr(le_ip, 'classes_'):
        le_ip.classes_ = np.array([])  # Initialize classes_ as an empty array

    if ip not in le_ip.classes_:
        le_ip.classes_ = np.append(le_ip.classes_, ip)
        le_ip.fit(le_ip.classes_)
    return le_ip.transform([ip])[0]

# Function to extract features from the packet
def extract_features(packet):
    src_ip = packet['IP'].src
    dst_ip = packet['IP'].dst
    protocol = packet['IP'].proto
    packet_size = len(packet)  # Use 'packet_size' consistently
    return [src_ip, dst_ip, protocol, packet_size]

# Function to log detected anomalies
def log_detection(features, prediction):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    status = 'Suspicious' if prediction[0] == 1 else 'Normal'
    print(f"{timestamp} - Detection: {status} - Features: {features}")

# Function to update the traffic data DataFrame
def update_traffic_data(features):
    global traffic_data

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    new_data = pd.DataFrame([{
        'timestamp': timestamp,
        'src_ip': features[0],
        'dst_ip': features[1],
        'protocol': features[2],
        'packet_size': features[3]
    }])

    traffic_data = pd.concat([traffic_data, new_data], ignore_index=True)

    # Update additional features using 'min' instead of 'T'
    traffic_data['timestamp'] = pd.to_datetime(traffic_data['timestamp'])
    traffic_data['packet_rate'] = traffic_data.groupby(traffic_data['timestamp'].dt.floor('min'))['timestamp'].transform('count')
    traffic_data['byte_rate'] = traffic_data.groupby(traffic_data['timestamp'].dt.floor('min'))['packet_size'].transform('sum')

# Function to load or train the machine learning model
def load_or_train_model():
    try:
        model = load('rf_model.joblib')
        print("Model loaded successfully.")
    except FileNotFoundError:
        print("Model not found. Training a new model...")
        data = pd.read_csv('data.csv')
        fit_ip_encoder(data)
        data['src_ip'] = le_ip.transform(data['src_ip'])
        data['dst_ip'] = le_ip.transform(data['dst_ip'])

        # Use 'packet_size' consistently
        data = data.rename(columns={'size': 'packet_size'})  # Rename 'size' to 'packet_size'

        X = data.drop('label', axis=1)
        y = data['label']
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

        model = RandomForestClassifier()
        model.fit(X_train, y_train)
        dump(model, 'rf_model.joblib')
        y_pred = model.predict(X_test)
        print(classification_report(y_test, y_pred))
    return model

# Function to capture network traffic using tshark
def capture_with_tshark(interface, duration, output_file):
    command = [
        "tshark",
        "-i", interface,
        "-a", f"duration:{duration}",
        "-w", output_file
    ]
    try:
        subprocess.run(command, check=True)
    except Exception as e:
        print(f"Error capturing packets with tshark: {e}")

# Function to process captured packets
def process_pcap_file(pcap_file):
    packets = sniff(offline=pcap_file)
    for packet in packets:
        process_packet(packet)

# Function to visualize traffic patterns periodically
def visualize_traffic():
    global traffic_data
    while True:
        time.sleep(60)
        plt.figure(figsize=(12, 6))
        sns.lineplot(data=traffic_data, x='timestamp', y='packet_rate', label='Packet Rate')
        sns.lineplot(data=traffic_data, x='timestamp', y='byte_rate', label='Byte Rate')
        plt.xlabel('Time')
        plt.ylabel('Rate')
        plt.title('Network Traffic Over Time')
        plt.legend()
        plt.show()

# Main function to run the IDS
if __name__ == "__main__":
    print("Starting Intrusion Detection System...")

    # Load or train the ML model
    ml_model = load_or_train_model()

    # Capture packets using tshark
    interface = "Wi-Fi"  # Use the Wi-Fi interface as per your ipconfig details
    capture_duration = 60  # Capture duration in seconds
    pcap_file = "capture_output.pcap"

    capture_with_tshark(interface, capture_duration, pcap_file)

    # Process the captured packets
    process_pcap_file(pcap_file)

    # Visualize traffic patterns
    visualize_traffic()
