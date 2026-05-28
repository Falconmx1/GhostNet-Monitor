import json
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime
import random

print("[GhostNet] Iniciando detección de anomalías...")

# Simular tráfico normal (entrenamiento)
normal_traffic = np.random.rand(200, 4)  # 4 features: packets/sec, bytes/sec, unique_ports, avg_ttl
model = IsolationForest(contamination=0.1, random_state=42)
model.fit(normal_traffic)

# Simular tráfico actual (mezcla normal + anomalías)
current_traffic = []
for i in range(50):
    if i < 40:  # Normal
        current_traffic.append(np.random.rand(4))
    else:  # Anomalías
        anomaly = np.random.rand(4) * [5, 10, 3, 0.5]  # Valores extremos
        current_traffic.append(anomaly)

# Detectar anomalías
predictions = model.predict(current_traffic)
anomaly_scores = model.score_samples(current_traffic)

alerts = []
for i, (pred, score) in enumerate(zip(predictions, anomaly_scores)):
    if pred == -1:  # Anomalía detectada
        alerts.append({
            "timestamp": datetime.utcnow().isoformat(),
            "event_id": i,
            "anomaly_score": float(score),
            "severity": "high" if score < -0.3 else "medium",
            "features": [float(x) for x in current_traffic[i]]
        })

# Guardar resultados
result = {
    "scan_time": datetime.utcnow().isoformat(),
    "total_events": len(current_traffic),
    "anomalies_found": len(alerts),
    "alerts": alerts
}

with open("output/anomalies.json", "w") as f:
    json.dump(result, f, indent=2)

print(f"[GhostNet] ✅ Anomalías detectadas: {len(alerts)}/{len(current_traffic)}")
