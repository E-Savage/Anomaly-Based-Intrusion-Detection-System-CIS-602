from sklearn.ensemble import IsolationForest
import pandas as pd
import pickle
import csv
from scapy.all import sniff
from datetime import datetime

def train_data():
    # read in the data
    training_data = pd.read_csv('network_data_2days.csv')
    # the model
    model = IsolationForest()
    model.fit(training_data[['protocol', 'length']])
    # the predictions
    predictions = model.predict(training_data[['protocol', 'length']])
    # the scores
    scores = model.decision_function(training_data[['protocol', 'length']])
    # add new columns to dataset
    training_data['anomaly'] = predictions
    training_data['anomaly_score'] = scores
    print(training_data)
    return training_data

def save_model(trained_data):
    filename = 'network_anomoly_model_mb_es.pkl'
    pickle.dump(trained_data, open(filename, 'wb'))
    print(f"Trained model is now saved as {filename}")
    return filename

def capture_live(trained_model):
    interface = "wlan0"
    fields = ["timestamp", "src_ip", "dst_ip", "protocol", "length"]
    last_network_activity = None
    anomolies = []
    with open('live_network_data.csv', mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        def detect_anomoly(live_network_activity, model, anomolies):
            if live_network_activity is None:
                return anomolies
            # loads in the live data
            live_data = pd.DataFrame([live_network_activity])
            # predicts for the live data point based on the model
            prediction = model.predict(live_data[['protocol', 'length']])[0]
            # scores the live data point based on the model
            score = model.decision_function(live_data[['protocol', 'length']])[0]
            if prediction == -1:
                print("~~~ANOMOLY DETECTED~~~")
                anomolies.append(live_network_activity)
            return anomolies
        
        def process_network_packet(pkt):
            if pkt.haslayer("IP"):
                row = {
                    "timestamp": datetime.now().isoformat(),
                    "src_ip": pkt["IP"].src,
                    "dst_ip": pkt["IP"].dst,
                    "protocol": pkt["IP"].proto,
                    "length": len(pkt)
                }
                writer.writerow(row)
                file.flush()
                last_network_activity = row
            anomolies = detect_anomoly(last_network_activity, trained_model, anomolies)
        sniff(iface=interface, prn=process_network_packet, store=False)
        return anomolies

data = train_data()
file = save_model(data)
trained_model = pickle.load(open(file, 'rb'))
capture_live(trained_model)