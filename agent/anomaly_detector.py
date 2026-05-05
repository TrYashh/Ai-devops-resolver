from sklearn.ensemble import IsolationForest
import numpy as np


class AnomalyDetector:

    def __init__(self):

        self.model = IsolationForest(contamination=0.05)

        # baseline normal metrics
        training_data = np.array([
            [30, 40, 10, 5, 0.01, 100],
            [32, 42, 12, 6, 0.02, 110],
            [29, 38, 9, 4, 0.01, 95],
            [31, 41, 11, 5, 0.02, 105]
        ])

        self.model.fit(training_data)

    def is_anomaly(self, cpu, memory, disk, network, error_rate, latency):

        features = np.array([[cpu, memory, disk, network, error_rate, latency]])

        prediction = self.model.predict(features)

        return prediction[0] == -1