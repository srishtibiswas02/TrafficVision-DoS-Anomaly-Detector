# test_pred.py
# Import necessary libraries
import os
import pandas as pd
from joblib import load
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
# Load the trained model and scaler
model = load('random_forest_model.joblib')
scaler = load('scaler.joblib')

# Function to load and preprocess the new dataset
def preprocess_new_data(file_path):
    # Load the dataset
    data = pd.read_csv(file_path)

    # Extract the third index value from 'flow_key' and create a new column 'Destination Port'
    data['Destination Port'] = data['flow_key'].apply(lambda x: x.split(',')[3] if isinstance(x, str) and len(x.split(',')) > 3 else None)
    # data['Destination Port'] = data.apply(lambda x: x.flow_key[3], axis=1)
    
    # Drop the original 'flow_key' column
    data = data.drop(columns=['flow_key'], errors='ignore')

    # Drop unnecessary columns (customize based on your dataset)
    columns_to_drop = [
        'first_timestamp', 'last_timestamp',
        'src_ip', 'dst_ip'
    ]
    
    # Drop the specified columns
    data = data.drop(columns=columns_to_drop, errors='ignore')

    # Replace infinite values and fill NaN values
    data = data.replace([np.inf, -np.inf], np.nan)
    data = data.fillna(0)

    # Move 'Destination Port' to the first column
    # Create a new DataFrame with 'Destination Port' as the first column
    data['Destination Port'] = data['Destination Port'].str.replace(')', '', regex=False).astype(int)
    cols = ['Destination Port'] + [col for col in data.columns if col != 'Destination Port']
    data = data[cols]

    return data

def make_pred(new_data_path):
    # Specify the path to your new dataset
    orignal_df=pd.read_csv(new_data_path)
    new_data = preprocess_new_data(new_data_path)

    # Separate features from the new data (assuming 'Label' column is absent)
    X_new = new_data
    # print(X_new.head())
    # Scale the features using the previously fitted scaler
    X_new_scaled = scaler.transform(X_new)

    # Perform predictions using the trained model
    predictions = model.predict(X_new_scaled)

    # Add predictions to the new data DataFrame
    new_data['Predictions'] = predictions

    # Output the DataFrame with predictions
    # print(new_data)
    # print(new_data["Predictions"].count)
    # print(new_data)
    new_data['flow_key'] = orignal_df['flow_key']
    new_data.to_csv('final_result_user.csv')
    print("final_result_data.csv has been created.")
    return 'final_result_user.csv'

# def create_visualization():
# # Load your CSV file
#     data = pd.read_csv('final_result_user.csv')

#     # Count the distribution of classes in the Predictions column
#     class_distribution = data['Predictions'].value_counts()

#     # Create a pie chart for the distribution of classes
#     plt.figure(figsize=(8, 8))
#     plt.pie(class_distribution, labels=["Attack","Benign"], autopct='%1.12f%%', startangle=140, colors=['lightcoral', 'turquoise'])
#     plt.title('Distribution of Predictions (Attack vs. Normal Traffic)')
#     plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
#     plt.show()
#       # Save the plot
    visualization_path1 = 'static/visualizations/prediction_distribution1.png'
    # plt.savefig(visualization_path1)
    # visualization_path2 = 'static/visualizations/prediction_distribution2.png'
    # plt.savefig(visualization_path2)
    # visualization_path3 = 'static/visualizations/prediction_distribution3.png'
    # plt.savefig(visualization_path3)
    # visualization_path4 = 'static/visualizations/prediction_distribution4.png'
    # plt.savefig(visualization_path4)
    # visualization_path5 = 'static/visualizations/prediction_distribution5.png'
    # plt.savefig(visualization_path5)
    # plt.close()

# make_pred("user_data.csv")
# create_visualization()