# Nids
# Intrusion Detection System (IDS)

## Overview
This project implements an **Intrusion Detection System (IDS)** for real-time **Network Traffic Analysis** and **Intrusion Detection** using **Machine Learning**. The system monitors network traffic, extracts key features, and classifies packets as either normal or suspicious, providing a robust tool for securing networks.

## Features
- Real-time packet capture using **Wireshark**.
- Feature extraction from captured packets with **Scapy**.
- Machine learning-based intrusion detection using **Random Forest Classifier**.
- Visualization of network traffic patterns using **Matplotlib** and **Seaborn**.
- Modular design for traffic capture, analysis, and visualization.

## Technologies Used
- **Programming Language**: Python
- **Network Traffic Capture Tool**: Wireshark
- **Machine Learning Libraries**: Scikit-learn, TensorFlow
- **Visualization Libraries**: Matplotlib, Seaborn
- **Packet Analysis Tool**: Scapy

## System Architecture
The project is divided into the following components:
1. **Traffic Capture**: Captures network traffic using Wireshark and saves it in `.pcap` format.
2. **Feature Extraction**: Extracts relevant features such as IP addresses, protocol types, and packet sizes.
3. **Model Training**: Trains a Random Forest classifier to detect suspicious traffic.
4. **Real-time Detection**: Monitors live network traffic and classifies packets in real-time.
5. **Visualization**: Analyzes and visualizes network traffic trends to identify anomalies.
