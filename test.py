from collections import defaultdict
import pyshark
from datetime import datetime
import joblib
import os
import pandas as pd
from joblib import load
import numpy as np


model = load('random_forest_model.joblib')
scaler = load('scaler.joblib')


flows = defaultdict(lambda: {
    'Flow Duration': 0,
    'Total Fwd Packets': 0,
    'Total Backward Packets': 0,
    'Total Length of Fwd Packets': 0,
    'Total Length of Bwd Packets': 0,
    'Fwd Packet Length Max': 0,
    'Fwd Packet Length Min': float('inf'),
    'Fwd Packet Length Mean': 0,
    'Fwd Packet Length Std': 0,
    'Bwd Packet Length Max': 0,
    'Bwd Packet Length Min': float('inf'),
    'Bwd Packet Length Mean': 0,
    'Bwd Packet Length Std': 0,
    'Flow Bytes/s': 0,
    'Flow Packets/s': 0,
    'Flow IAT Mean': 0,
    'Flow IAT Std': 0,
    'Flow IAT Max': 0,
    'Flow IAT Min': float('inf'),
    'Fwd IAT Total': 0,
    'Fwd IAT Mean': 0,
    'Fwd IAT Std': 0,
    'Fwd IAT Max': 0,
    'Fwd IAT Min': float('inf'),
    'Bwd IAT Total': 0,
    'Bwd IAT Mean': 0,
    'Bwd IAT Std': 0,
    'Bwd IAT Max': 0,
    'Bwd IAT Min': float('inf'),
    'Fwd PSH Flags': 0,
    'Bwd PSH Flags': 0,
    'Fwd URG Flags': 0,
    'Bwd URG Flags': 0,
    'Fwd Header Length': 0,
    'Bwd Header Length': 0,
    'Fwd Packets/s': 0,
    'Bwd Packets/s': 0,
    'Min Packet Length': float('inf'),
    'Max Packet Length': 0,
    'Packet Length Mean': 0,
    'Packet Length Std': 0,
    'Packet Length Variance': 0,
    'FIN Flag Count': 0,
    'SYN Flag Count': 0,
    'RST Flag Count': 0,
    'PSH Flag Count': 0,
    'ACK Flag Count': 0,
    'URG Flag Count': 0,
    'CWE Flag Count': 0,
    'ECE Flag Count': 0,
    'Down/Up Ratio': 0,
    'Average Packet Size': 0,
    'Avg Fwd Segment Size': 0,
    'Avg Bwd Segment Size': 0,
    'Fwd Header Length.1': 0,
    'Fwd Avg Bytes/Bulk': 0,
    'Fwd Avg Packets/Bulk': 0,
    'Fwd Avg Bulk Rate': 0,
    'Bwd Avg Bytes/Bulk': 0,
    'Bwd Avg Packets/Bulk': 0,
    'Bwd Avg Bulk Rate': 0,
    'Subflow Fwd Packets': 0,
    'Subflow Fwd Bytes': 0,
    'Subflow Bwd Packets': 0,
    'Subflow Bwd Bytes': 0,
    'Init_Win_bytes_forward': 0,
    'Init_Win_bytes_backward': 0,
    'act_data_pkt_fwd': 0,
    'min_seg_size_forward': 0,
    'Active Mean': 0,
    'Active Std': 0,
    'Active Max': 0,
    'Active Min': float('inf'),
    'Idle Times':[],
    'Idle Mean': 0,
    'Idle Std': 0,
    'Idle Max': 0,
    'Idle Min': float('inf'),
    'first_timestamp': None,
    'last_timestamp': None,
    'src_ip': None,
    'dst_ip': None
})

# Function to extract additional packet features for all 78 features
def extract_features_from_packet(packet):
    features = {}

    try:
        features['src_ip'] = packet.ip.src
        features['dst_ip'] = packet.ip.dst
        features['src_port'] = int(packet[packet.transport_layer].srcport)
        features['dst_port'] = int(packet[packet.transport_layer].dstport)
        features['protocol'] = packet.transport_layer
    except AttributeError:
        return None  # Skip if essential attributes are missing
    
    features['timestamp'] = packet.sniff_time.timestamp()
    
    # Extract packet length
    try:
        features['packet_length'] = int(packet.length)
    except AttributeError:
        features['packet_length'] = 0

    # Extract flags for TCP packets
    if packet.transport_layer == 'TCP':
        features['tcp_flags'] = packet.tcp.flags
        features['tcp_syn'] = 1 if packet.tcp.flags_syn == '1' else 0
        features['tcp_ack'] = 1 if packet.tcp.flags_ack == '1' else 0
        features['tcp_fin'] = 1 if packet.tcp.flags_fin == '1' else 0
        features['tcp_psh'] = 1 if packet.tcp.flags_push == '1' else 0
        features['tcp_urg'] = 1 if packet.tcp.flags_urg == '1' else 0
        features['tcp_rst'] = 1 if packet.tcp.flags_reset == '1' else 0
    else:
        features['tcp_flags'] = 0
        features['tcp_syn'] = 0
        features['tcp_ack'] = 0
        features['tcp_fin'] = 0
        features['tcp_psh'] = 0
        features['tcp_urg'] = 0
        features['tcp_rst'] = 0

    return features

# Update process_packet to calculate new features
def process_packet(packet):
    features = extract_features_from_packet(packet)
    if features is None:
        return
    
    flow_key = (features['src_ip'], features['src_port'], features['dst_ip'], features['dst_port'])

    # Check if this is a new flow
    if flow_key not in flows:
        flows[flow_key]['first_timestamp'] = features['timestamp']
        flows[flow_key]['last_timestamp'] = features['timestamp']
        flows[flow_key]['src_ip'] = features['src_ip']
        flows[flow_key]['dst_ip'] = features['dst_ip']
    
    # Update flow duration and packet counts
    flows[flow_key]['Flow Duration'] = features['timestamp'] - flows[flow_key]['first_timestamp']
    
    if features['src_ip'] == flow_key[0]:  # Forward direction
        flows[flow_key]['Total Fwd Packets'] += 1
        flows[flow_key]['Total Length of Fwd Packets'] += features['packet_length']
    else:  # Backward direction
        flows[flow_key]['Total Backward Packets'] += 1
        flows[flow_key]['Total Length of Bwd Packets'] += features['packet_length']
    
    # Increment TCP flags
    flows[flow_key]['FIN Flag Count'] += features['tcp_fin']
    flows[flow_key]['SYN Flag Count'] += features['tcp_syn']
    flows[flow_key]['PSH Flag Count'] += features['tcp_psh']
    flows[flow_key]['ACK Flag Count'] += features['tcp_ack']
    flows[flow_key]['URG Flag Count'] += features['tcp_urg']
    flows[flow_key]['RST Flag Count'] += features['tcp_rst']
    # Update packet length stats for forward direction
    if features['src_ip'] == flow_key[0]:  
        flows[flow_key]['Fwd Packet Length Max'] = max(flows[flow_key]['Fwd Packet Length Max'], features['packet_length'])
        flows[flow_key]['Fwd Packet Length Min'] = min(flows[flow_key]['Fwd Packet Length Min'], features['packet_length'])
        flows[flow_key]['Avg Fwd Segment Size'] = flows[flow_key]['Total Length of Fwd Packets'] / flows[flow_key]['Total Fwd Packets']
        
        # Update Fwd IAT calculations here (e.g., mean, max, min)
    else:  # Backward direction
        flows[flow_key]['Bwd Packet Length Max'] = max(flows[flow_key]['Bwd Packet Length Max'], features['packet_length'])
        flows[flow_key]['Bwd Packet Length Min'] = min(flows[flow_key]['Bwd Packet Length Min'], features['packet_length'])
        flows[flow_key]['Avg Bwd Segment Size'] = flows[flow_key]['Total Length of Bwd Packets'] / flows[flow_key]['Total Backward Packets']
    active_duration = features['timestamp'] - flows[flow_key]['last_timestamp']
    if active_duration > 0:
        flows[flow_key]['Active Mean'] = (flows[flow_key].get('Active Mean', 0) + active_duration) / 2
        flows[flow_key]['Active Max'] = max(flows[flow_key].get('Active Max', 0), active_duration)
        flows[flow_key]['Active Min'] = min(flows[flow_key].get('Active Min', float('inf')), active_duration)
    # Update Bwd IAT calculations here (e.g., mean, max, min)
    bulk_threshold = 1000
    if flows[flow_key]['Total Length of Fwd Packets'] > bulk_threshold:
        flows[flow_key]['Fwd Avg Bytes/Bulk'] = flows[flow_key]['Total Length of Fwd Packets'] / flows[flow_key]['Total Fwd Packets']
        flows[flow_key]['Fwd Avg Packets/Bulk'] = flows[flow_key]['Total Fwd Packets']
        flows[flow_key]['Fwd Avg Bulk Rate'] = flows[flow_key]['Fwd Packets/s']

    if flows[flow_key]['Total Length of Bwd Packets'] > bulk_threshold:
        flows[flow_key]['Bwd Avg Bytes/Bulk'] = flows[flow_key]['Total Length of Bwd Packets'] / flows[flow_key]['Total Backward Packets']
        flows[flow_key]['Bwd Avg Packets/Bulk'] = flows[flow_key]['Total Backward Packets']
        flows[flow_key]['Bwd Avg Bulk Rate'] = flows[flow_key]['Bwd Packets/s']
    idle_duration = features['timestamp'] - flows[flow_key]['last_timestamp']
    if idle_duration > 0:
        flows[flow_key]['Idle Times'].append(idle_duration)
        
        # Update Idle Mean, Idle Std, Idle Max, and Idle Min
        flows[flow_key]['Idle Mean'] = np.mean(flows[flow_key]['Idle Times'])
        flows[flow_key]['Idle Std'] = np.std(flows[flow_key]['Idle Times'])
        flows[flow_key]['Idle Max'] = max(flows[flow_key]['Idle Times'])
        flows[flow_key]['Idle Min'] = min(flows[flow_key]['Idle Times'])

def preprocess_new_data(file_path):
    data = pd.read_csv(file_path)

    data['Destination Port'] = data['flow_key'].apply(lambda x: x.split(',')[3] if isinstance(x, str) and len(x.split(',')) > 3 else None)
    data = data.drop(columns=['flow_key'], errors='ignore')

    # Drop unnecessary columns 
    columns_to_drop = [
        'first_timestamp', 'last_timestamp',
        'src_ip', 'dst_ip', 'Idle Times'
    ]
    
    data = data.drop(columns=columns_to_drop, errors='ignore')

    data = data.replace([np.inf, -np.inf], np.nan)
    data = data.fillna(0)

    data['Destination Port'] = data['Destination Port'].str.replace(')', '', regex=False).astype(int)
    cols = ['Destination Port'] + [col for col in data.columns if col != 'Destination Port']
    data = data[cols]
    return data


def create_csv(path):
    capture = pyshark.FileCapture(path)
    for packet in capture:
        process_packet(packet)

    flow_data = [{**{'flow_key': key}, **value} for key, value in flows.items()]
    df = pd.DataFrame(flow_data)

    df.to_csv('user_data.csv', index=False)
    print("user_data.csv has been created.")
    new_data_path = "user_data.csv"

    orignal_df=pd.read_csv(new_data_path)
    new_data = preprocess_new_data(new_data_path)

    X_new = new_data

    # Scale the features using the previously fitted scaler
    X_new_scaled = scaler.transform(X_new)

    # Perform predictions using the trained model
    predictions = model.predict(X_new_scaled)

    # Add predictions to the new data DataFrame
    new_data['Predictions'] = predictions
    new_data['flow_key'] = orignal_df['flow_key']
    new_data.to_csv('final_result_user.csv')
    print("final_result_data.csv has been created.")
    return 'final_result_user.csv'