from sklearn.ensemble import IsolationForest
import pandas as pd
import pickle
import csv
from scapy.all import sniff
from datetime import datetime
import ipaddress

def clean_data(data):
    '''
    In this section we clean the data so that src_ip and dst_ip are formatted into integers to be used in the IsolationForest model
    '''
    def ip_to_int(ip_address):
        try:
            return int(ipaddress.ip_address(ip_address))
        except ValueError:
            return None  # Or handle invalid IPs as needed

    data['src_ip'] = data['src_ip'].apply(ip_to_int)
    data['dst_ip'] = data['dst_ip'].apply(ip_to_int)
    return data

def train_data(data):
    '''
    The model is created and fitted using IsolationForest, we then add new columns to the dataset for their predictions and scores
    '''
    model = IsolationForest()
    model.fit(data[['src_ip', 'dst_ip', 'protocol', 'length']])
    predictions = model.predict(data[['src_ip', 'dst_ip', 'protocol', 'length']])
    scores = model.decision_function(data[['src_ip', 'dst_ip', 'protocol', 'length']])
    data['anomaly'] = predictions
    data['anomaly_score'] = scores
    print(data)
    return data

def save_model(trained_data):
    '''
    Using pickle we save the AI model as a file which is returned
    '''
    filename = 'network_anomoly_model_mb_es.pkl'
    pickle.dump(trained_data, open(filename, 'wb'))
    print(f"Trained model is now saved as {filename}")
    return filename

# def capture_live(trained_model):
#     interface = "wlan0"
#     fields = ["timestamp", "src_ip", "dst_ip", "protocol", "length"]
#     last_network_activity = None
#     anomolies = []
#     with open('live_network_data.csv', mode='w', newline='') as file:
#         writer = csv.DictWriter(file, fieldnames=fields)
#         writer.writeheader()

#         def detect_anomoly(live_network_activity, model, anomolies):
#             if live_network_activity is None:
#                 return anomolies
#             # loads in the live data
#             live_data = pd.DataFrame([live_network_activity])
#             # predicts for the live data point based on the model
#             prediction = model.predict(live_data[['protocol', 'length']])[0]
#             # scores the live data point based on the model
#             score = model.decision_function(live_data[['protocol', 'length']])[0]
#             if prediction == -1:
#                 print("~~~ANOMOLY DETECTED~~~")
#                 anomolies.append(live_network_activity)
#             return anomolies
        
#         def process_network_packet(pkt):
#             if pkt.haslayer("IP"):
#                 row = {
#                     "timestamp": datetime.now().isoformat(),
#                     "src_ip": pkt["IP"].src,
#                     "dst_ip": pkt["IP"].dst,
#                     "protocol": pkt["IP"].proto,
#                     "length": len(pkt)
#                 }
#                 writer.writerow(row)
#                 file.flush()
#                 last_network_activity = row
#             anomolies = detect_anomoly(last_network_activity, trained_model, anomolies)
#         sniff(iface=interface, prn=process_network_packet, store=False)
#         return anomolies

# read in the data
data = pd.read_csv('network_data_2days.csv')
# clean the data
cleaned_data = clean_data(data)
# train the data
trained_data = train_data(cleaned_data)
# save the trained data
file = save_model(trained_data)
# open the model of the trained data
trained_model = pickle.load(open(file, 'rb'))
# capture_live(trained_model)