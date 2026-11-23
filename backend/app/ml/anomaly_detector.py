from typing import Dict, Any, Tuple


class AnomalyDetector:
    """
    Deterministic anomaly detector and feature classifier for network flow telemetry.
    Computes explainable anomaly scores based on port sensitivity, packet volume,
    and protocol characteristics to mitigate false-positive and false-negative risks.
    """
    def __init__(self):
        self.sensitive_auth_ports = {22, 3389, 445, 21, 23}
        self.c2_ports = {4444, 1337, 31337, 6667, 9001}

    def score_flow(self, source_ip: str, destination_ip: str, flow_data: Dict[str, Any]) -> Tuple[float, str, str]:
        """
        Calculates deterministic anomaly score (0.0 to 1.0), severity, and attack type.
        Eliminates non-deterministic jitter to ensure reliable SOC detection baselines.
        """
        dst_port = int(flow_data.get("destination_port") or 80)
        packet_count = int(flow_data.get("packet_count") or 100)
        byte_count = int(flow_data.get("byte_count") or 50000)

        # Baseline risk
        base_score = 0.50

        # Feature 1: Administrative / Auth port targeting
        if dst_port in self.sensitive_auth_ports:
            base_score += 0.32
            attack_type = "Brute Force"
        elif dst_port in self.c2_ports:
            base_score += 0.38
            attack_type = "Malware Communication"
        elif packet_count >= 1000:
            base_score += 0.40
            attack_type = "DDoS"
        elif packet_count >= 300:
            base_score += 0.28
            attack_type = "Port Scanning"
        else:
            base_score += 0.15
            attack_type = "Suspicious Traffic"

        # Feature 2: High byte-per-packet or volumetric inflation
        if byte_count > 500000:
            base_score += 0.08

        # Bound score between 0.50 and 0.99
        final_score = round(max(0.50, min(0.98, base_score)), 3)

        if final_score >= 0.88:
            severity = "Critical"
        elif final_score >= 0.75:
            severity = "High"
        elif final_score >= 0.60:
            severity = "Medium"
        else:
            severity = "Low"

        return final_score, severity, attack_type


anomaly_detector = AnomalyDetector()
