from sklearn.ensemble import IsolationForest
import numpy as np
import pandas as pd
import matplotlib as plt

# read in the data
data = pd.read_csv('network_data_2days.csv')

# the model
model = IsolationForest()
model.fit(data['timestamp', 'src_ip', 'dst_ip', 'protocol', 'length'])

# the predictions
predictions = model.predict(data['timestamp', 'src_ip', 'dst_ip', 'protocol', 'length'])

# the scores
scores = model.decision_function(data['timestamp', 'src_ip', 'dst_ip', 'protocol', 'length'])

# wrap it up
data['anomaly'] = predictions
data['anomaly_score'] = scores

print(data)
