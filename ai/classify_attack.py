import json
import random
from datetime import datetime

print("[GhostNet] Clasificando tipos de ataque...")

# Simular detección de ataques basada en patrones
attack_patterns = {
    "DDoS": ["high_packet_rate", "multiple_sources", "same_port"],
    "Brute Force": ["failed_logins", "same_source", "different_users"],
    "Port Scan": ["sequential_ports", "short_intervals", "no_payload"],
    "Malware C2": ["odd_hours", "small_packets", "encrypted_traffic"],
    "Normal": []
}

# Simular eventos detectados
detected_events = []
attack_types = ["DDoS", "Brute Force", "Port Scan", "Malware C2", "Normal"]
weights = [0.15, 0.25, 0.30, 0.10, 0.20]  # 80% ataques, 20% normal

for i in range(20):
    attack = random.choices(attack_types, weights=weights)[0]
    if attack != "Normal":
        detected_events.append({
            "event_id": i,
            "attack_type": attack,
            "confidence": round(random.uniform(0.75, 0.99), 3),
            "source_ip": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            "target_port": random.choice([22, 80, 443, 3389, 8080]),
            "patterns_matched": attack_patterns[attack]
        })

# Clasificar gravedad
for event in detected_events:
    if event["attack_type"] == "DDoS":
        event["severity"] = "critical"
    elif event["attack_type"] in ["Malware C2", "Port Scan"]:
        event["severity"] = "high"
    else:
        event["severity"] = "medium"

result = {
    "scan_time": datetime.utcnow().isoformat(),
    "total_events": 20,
    "attacks_detected": len(detected_events),
    "attack_breakdown": {
        "DDoS": sum(1 for e in detected_events if e["attack_type"] == "DDoS"),
        "Brute Force": sum(1 for e in detected_events if e["attack_type"] == "Brute Force"),
        "Port Scan": sum(1 for e in detected_events if e["attack_type"] == "Port Scan"),
        "Malware C2": sum(1 for e in detected_events if e["attack_type"] == "Malware C2")
    },
    "events": detected_events
}

with open("output/attacks.json", "w") as f:
    json.dump(result, f, indent=2)

print(f"[GhostNet] ✅ Ataques clasificados: {len(detected_events)} encontrados")
