from flask import Flask, request, jsonify, render_template, redirect, url_for
import numpy as np
import pandas as pd
import pyshark
import asyncio
import seaborn as sns
import matplotlib.pyplot as plt
from threading import Thread
from functools import wraps
import os
# User - defined modules for feature engineering
import test
# import visual

app = Flask(__name__)
UPLOAD_FOLDER = './user_files'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def async_action(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(f(*args, **kwargs))
        finally:
            loop.close()
    return wrapped

def run_async(async_func, *args):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result = loop.run_until_complete(async_func(*args))
    finally:
        loop.close()
    return result

def create_visualizations(data_path):
    # Read the CSV file if a path is provided
    if isinstance(data_path, str):
        data = pd.read_csv(data_path)
    else:
        data = data_path  # If DataFrame is passed directly

    # Clear any existing plots
    plt.close('all')

    ############# PIE CHART ##########################
    plt.figure(figsize=(10, 8))
    class_distribution = data['Predictions'].value_counts()
    plt.pie(class_distribution, labels=["Benign","Attack"], 
            autopct='%1.1f%%', startangle=140, 
            colors=['lightcoral', 'turquoise'])
    plt.title('Distribution of Predictions (Attack vs. Normal Traffic)')
    plt.axis('equal')
    plt.savefig(os.path.join('static', 'visualization1.png'))
    plt.close()

    ############# UNSTACKED BAR CHART ##########################
    plt.figure(figsize=(10, 6))
    attack_traffic = data[data['Predictions'] == 1]
    benign_traffic = data[data['Predictions'] == 0]
    
    # Handle case where there might be no attack or benign traffic
    attack_ports = attack_traffic['Destination Port'].value_counts().head(10)
    benign_ports = benign_traffic['Destination Port'].value_counts().head(10)
    
    # Create DataFrame for plotting
    port_counts = pd.DataFrame({
        'Attack': attack_ports,
        'Benign': benign_ports
    }).fillna(0)

    # Plot unstacked bar chart
    ax = port_counts.plot(kind='bar', stacked=False, 
                         color=['#FF6347', '#4CAF50'], 
                         figsize=(10, 8))
    plt.title('Top 10 Destination Ports for Attack and Benign Traffic')
    plt.xlabel('Destination Port')
    plt.ylabel('Frequency')
    plt.xticks(rotation=45)
    plt.tight_layout()  # Prevent label cutoff
    plt.savefig(os.path.join('static', 'visualization2.png'))
    plt.close()

    ############# HISTOGRAM ##########################
    plt.figure(figsize=(10, 8))
    plt.hist(data['Flow Duration'], bins=30, 
             color='skyblue', edgecolor='black')
    plt.title("Distribution of Flow Duration")
    plt.xlabel("Flow Duration (milliseconds)")
    plt.ylabel("Frequency")
    plt.tight_layout()
    plt.savefig(os.path.join('static', 'visualization3.png'))
    plt.close()

    traffic_packets = data.groupby('Predictions')[['Total Fwd Packets', 'Total Backward Packets']].sum()
    traffic_packets.index = ['Benign', 'Attack']

    # Plot stacked bar chart
    traffic_packets.plot(kind='bar', stacked=True, color=['#4CAF50', '#FF6347'], figsize=(8, 6))
    plt.title('Total Packets (Forward and Backward) by Traffic Type')
    plt.xlabel('Traffic Type')
    plt.ylabel('Total Packets')
    plt.legend(['Total Fwd Packets', 'Total Backward Packets'])
    plt.savefig(os.path.join('static','visualization4.png'))
    plt.close()


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part", 400
        
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
        
    try:
        # Save the uploaded file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        
        # Create a new thread for async operations
        def process_async():
            return run_async(test.create_csv, file_path)
            
        thread = Thread(target=process_async)
        thread.start()
        thread.join()  # Wait for the thread to complete
        
        return redirect(url_for('result'))
        
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return f"Error processing file: {str(e)}", 500

@app.route('/result')
def result():
    try:
        result_path = 'final_result_user.csv'
        if not os.path.exists(result_path):
            return "Results file not found", 404
        
        results_df = pd.read_csv(result_path)
        results = results_df.to_dict(orient='records')
        create_visualizations(result_path)
        return render_template('result.html', predictions=results)
    
    except Exception as e:
        print(f"Error loading results: {e}")
        return "Internal Server Error", 500

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
    