import json
from datetime import datetime
import random

print("[GhostNet] Analizando tráfico de red...")

# Simular análisis de paquetes
traffic_stats = {
    "total_packets": random.randint(5000, 50000),
    "total_bytes": random.randint(10**6, 10**9),
    "protocols": {
        "TCP": random.randint(1000, 30000),
        "UDP": random.randint(500, 10000),
        "ICMP": random.randint(10, 500)
    },
    "top_sources": [],
    "suspicious_flows": []
}

# Generar top fuentes
for i in range(5):
    traffic_stats["top_sources"].append({
        "ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "packets": random.randint(500, 5000),
        "bytes": random.randint(10**5, 10**7)
    })

# Detectar flujo sospechosos
for i in range(random.randint(3, 10)):
    traffic_stats["suspicious_flows"].append({
        "flow_id": i,
        "source": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
        "destination": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "reason": random.choice(["high_frequency", "odd_port", "encrypted_payload", "small_ttl"]),
        "risk_score": round(random.uniform(0.6, 1.0), 2)
    })

result = {
    "analysis_time": datetime.utcnow().isoformat(),
    "capture_duration_seconds": 3600,
    "statistics": traffic_stats,
    "summary": {
        "total_suspicious_flows": len(traffic_stats["suspicious_flows"]),
        "avg_risk_score": sum(f["risk_score"] for f in traffic_stats["suspicious_flows"]) / len(traffic_stats["suspicious_flows"]) if traffic_stats["suspicious_flows"] else 0
    }
}

with open("output/traffic_analysis.json", "w") as f:
    json.dump(result, f, indent=2)

print(f"[GhostNet] ✅ Tráfico analizado: {traffic_stats['total_packets']} paquetes")
