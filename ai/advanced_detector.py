import json
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

print("[GhostNet-Pro] Iniciando análisis avanzado...")

# Cargar datos de ejemplo
try:
    df = pd.read_csv('data/sample_data.csv')
    print(f"[GhostNet-Pro] ✅ Cargados {len(df)} eventos")
except:
    print("[GhostNet-Pro] ⚠️ Usando datos sintéticos")
    # Datos sintéticos si no existe el archivo
    df = pd.DataFrame({
        'packet_size': np.random.normal(500, 200, 1000),
        'ttl': np.random.choice([64, 128, 255], 1000),
        'protocol': np.random.choice(['TCP', 'UDP', 'ICMP'], 1000)
    })

# Feature engineering
features = []
for idx, row in df.iterrows():
    feature_vec = []
    
    # Tamaño de paquete
    feature_vec.append(min(row.get('packet_size', 500) / 1500, 1.0))
    
    # TTL (normalizado)
    ttl = row.get('ttl', 64)
    feature_vec.append(ttl / 255)
    
    # Protocolo one-hot
    protocol = row.get('protocol', 'TCP')
    feature_vec.extend([1 if protocol == 'TCP' else 0,
                        1 if protocol == 'UDP' else 0,
                        1 if protocol == 'ICMP' else 0])
    
    # Flags (si existe)
    flags = row.get('flags', 0)
    feature_vec.append(min(flags / 10, 1.0))
    
    features.append(feature_vec)

X = np.array(features)

# Detección de anomalías con Isolation Forest
iso_forest = IsolationForest(contamination=0.15, random_state=42)
anomalies = iso_forest.fit_predict(X)
anomaly_scores = iso_forest.score_samples(X)

# Clasificación de ataques (simulado con reglas)
attack_classifier = {
    'DDoS': lambda x: x[0] > 0.8 and x[2] == 1,  # Paquetes grandes + ICMP
    'PortScan': lambda x: x[0] < 0.1 and x[3] == 1,  # Paquetes pequeños + TCP
    'BruteForce': lambda x: 0.3 < x[0] < 0.5 and x[4] == 0,  # Tamaño medio + UDP
    'Malware': lambda x: x[1] < 0.2 and x[0] > 0.6  # TTL bajo + paquete grande
}

detections = []
for i, features_vec in enumerate(features):
    if anomalies[i] == -1:  # Anomalía detectada
        attack_type = "Unknown"
        confidence = float(anomaly_scores[i])
        
        for atype, condition in attack_classifier.items():
            if condition(features_vec):
                attack_type = atype
                confidence = abs(confidence)
                break
        
        detections.append({
            "event_id": i,
            "attack_type": attack_type,
            "confidence": round(min(abs(confidence), 1.0), 3),
            "anomaly_score": float(anomaly_scores[i]),
            "features": [round(x, 3) for x in features_vec],
            "timestamp": row.get('timestamp', datetime.utcnow().isoformat())
        })

# Generar reporte final
report = {
    "scan_id": datetime.utcnow().strftime("%Y%m%d-%H%M%S"),
    "timestamp": datetime.utcnow().isoformat(),
    "total_events": len(X),
    "anomalies_detected": len(detections),
    "anomaly_rate": f"{(len(detections)/len(X))*100:.2f}%",
    "attack_breakdown": {
        "DDoS": sum(1 for d in detections if d["attack_type"] == "DDoS"),
        "PortScan": sum(1 for d in detections if d["attack_type"] == "PortScan"),
        "BruteForce": sum(1 for d in detections if d["attack_type"] == "BruteForce"),
        "Malware": sum(1 for d in detections if d["attack_type"] == "Malware"),
        "Unknown": sum(1 for d in detections if d["attack_type"] == "Unknown")
    },
    "critical_alerts": [d for d in detections if d["confidence"] > 0.8][:10],  # Top 10 críticos
    "recommendations": []
}

# Generar recomendaciones automáticas
if report["attack_breakdown"]["DDoS"] > 5:
    report["recommendations"].append("🚨 Implementar rate limiting y captcha")
if report["attack_breakdown"]["PortScan"] > 10:
    report["recommendations"].append("🔒 Configurar firewall para bloquear escaneos")
if report["attack_breakdown"]["BruteForce"] > 3:
    report["recommendations"].append("🔐 Habilitar 2FA y limitar intentos de login")
if report["attack_breakdown"]["Malware"] > 1:
    report["recommendations"].append("🦠 Aislar equipos infectados y actualizar antivirus")

# Guardar resultado
with open("output/advanced_report.json", "w") as f:
    json.dump(report, f, indent=2)

print(f"[GhostNet-Pro] ✅ Análisis completado")
print(f"[GhostNet-Pro] 📊 Anomalías: {report['anomalies_detected']}/{report['total_events']}")
print(f"[GhostNet-Pro] 🎯 Ataques: {sum(report['attack_breakdown'].values()) - report['attack_breakdown']['Unknown']}")
for rec in report["recommendations"]:
    print(f"[GhostNet-Pro] 💡 {rec}")
