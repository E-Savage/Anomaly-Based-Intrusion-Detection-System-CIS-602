# train_model.py

from sklearn.ensemble import IsolationForest
import pandas as pd
import pickle
import ipaddress

def clean_data(data):
    '''
    Clean the data so that src_ip and dst_ip are formatted into integers.
    '''
    def ip_to_int(ip_address):
        try:
            return int(ipaddress.ip_address(ip_address))
        except ValueError:
            return None  # Or handle invalid IPs as needed

    data['src_ip'] = data['src_ip'].apply(ip_to_int)
    data['dst_ip'] = data['dst_ip'].apply(ip_to_int)
    return data

def train_model(data):
    '''
    Create and fit the IsolationForest model.
    '''
    model = IsolationForest()
    model.fit(data[['src_ip', 'dst_ip', 'protocol', 'length']])
    return model

def save_model(model, filename='ids_isolation_forest.pkl'):
    '''
    Save the trained IsolationForest model.
    '''
    with open(filename, 'wb') as file:
        pickle.dump(model, file)
    print(f"Trained model is now saved as {filename}")

def save_training_data(data, filename='training_data_with_anomaly_scores.csv'):
    '''
    (Optional) Save the training data with anomaly labels and scores for reference.
    '''
    data.to_csv(filename, index=False)
    print(f"Training data with predictions saved as {filename}")

# --- MAIN EXECUTION ---

# 1. Read the input CSV
data = pd.read_csv('network_data_2days.csv')

# 2. Clean the data
cleaned_data = clean_data(data)

# 3. Train the Isolation Forest model
model = train_model(cleaned_data)

# 4. (Optional) Predict on training data to inspect performance
predictions = model.predict(cleaned_data[['src_ip', 'dst_ip', 'protocol', 'length']])
scores = model.decision_function(cleaned_data[['src_ip', 'dst_ip', 'protocol', 'length']])

# Add prediction results into the cleaned data
cleaned_data['anomaly'] = predictions
cleaned_data['anomaly_score'] = scores

# 5. Save the trained model
save_model(model)

# 6. (Optional) Save the training data with scores
save_training_data(cleaned_data)
