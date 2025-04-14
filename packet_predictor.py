# predict_packets.py

import pandas as pd
import pickle
import ipaddress

def clean_data(data):
    '''
    Clean the data by converting IP addresses to integers.
    '''
    def ip_to_int(ip_address):
        try:
            return int(ipaddress.ip_address(ip_address))
        except ValueError:
            return None  # Handle invalid IPs as needed

    data['src_ip'] = data['src_ip'].apply(ip_to_int)
    data['dst_ip'] = data['dst_ip'].apply(ip_to_int)
    return data

def load_model(model_path):
    '''
    Load the saved model from a file.
    '''
    with open(model_path, 'rb') as file:
        model = pickle.load(file)
    return model

def predict_data(model, data):
    '''
    Use the loaded model to predict anomalies and scores for the new data.
    '''
    features = data[['src_ip', 'dst_ip', 'protocol', 'length']]
    predictions = model.predict(features)
    scores = model.decision_function(features)
    data['anomaly'] = predictions
    data['anomaly_score'] = scores
    return data

def generate_report(predicted_data, report_filename='anomaly_detection_report.csv'):
    '''
    Generate a report with anomaly labels and scores.
    '''
    # Map -1 and 1 to human-readable labels
    predicted_data['anomaly_label'] = predicted_data['anomaly'].map({1: 'Normal', -1: 'Anomaly'})

    # Select key fields
    report = predicted_data[['timestamp', 'src_ip', 'dst_ip', 'protocol', 'length', 'anomaly_label', 'anomaly_score']]

    # Save the report
    report.to_csv(report_filename, index=False)
    print(f"✅ Detailed anomaly report saved to '{report_filename}'")

    # Print a summary
    print("\n📊 Anomaly Summary:")
    print(predicted_data['anomaly'].value_counts().rename(index={1: 'Normal', -1: 'Anomaly'}))

# --- MAIN EXECUTION ---

# Paths
new_data_path = 'network_data_20min_anomalous_ping_flood.csv'
model_path = 'ids_isolation_forest.pkl'

# Load and clean new data
new_data = pd.read_csv(new_data_path)
new_data = clean_data(new_data)

# Load trained model
trained_model = load_model(model_path)

# Predict anomalies
predicted_data = predict_data(trained_model, new_data)

# Save raw predictions
predicted_data.to_csv('network_data_20min_anomalous_ping_flood_with_predictions.csv', index=False)
print("Predictions saved to 'network_data_20min_anomalous_ping_flood_with_predictions.csv'")

# Generate detailed report
generate_report(predicted_data)
