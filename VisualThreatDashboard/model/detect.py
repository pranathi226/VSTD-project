"""
Threat detection model
"""
import random
from datetime import datetime
import numpy as np

class ThreatDetector:
    def __init__(self):
        self.threat_patterns = {
            "DDoS_Attack": {
                "features": ["high_packet_rate", "multiple_sources", "syn_flood"],
                "threshold": 0.8
            },
            "Brute_Force": {
                "features": ["failed_logins", "rapid_attempts", "privileged_accounts"],
                "threshold": 0.75
            },
            "Port_Scan": {
                "features": ["sequential_ports", "rapid_connections", "multiple_targets"],
                "threshold": 0.7
            },
            "Malware": {
                "features": ["suspicious_domains", "executable_downloads", "unusual_ports"],
                "threshold": 0.85
            },
            "SQL_Injection": {
                "features": ["sql_keywords", "long_parameters", "malformed_queries"],
                "threshold": 0.9
            }
        }
    
    def detect(self):
        """Detect threats in network traffic"""
        # Simulate feature extraction from network data
        features = self._extract_features()
        
        # Analyze features for threats
        threats = self._analyze_features(features)
        
        if threats:
            # Get the highest confidence threat
            primary_threat = max(threats, key=lambda x: x["confidence"])
            return primary_threat
        else:
            # Return normal traffic with low confidence threat
            return {
                "threat_type": "Normal_Traffic",
                "severity": "low",
                "confidence": 0.2,
                "description": "No significant threats detected",
                "source_ip": f"192.168.1.{random.randint(1, 255)}"
            }
    
    def _extract_features(self):
        """Extract features from simulated network data"""
        return {
            "packet_rate": random.randint(100, 10000),
            "failed_logins": random.randint(0, 15),
            "unique_ports": random.randint(1, 100),
            "suspicious_domains": random.randint(0, 5),
            "sql_patterns": random.randint(0, 10),
            "source_count": random.randint(1, 50),
            "connection_rate": random.randint(10, 1000)
        }
    
    def _analyze_features(self, features):
        """Analyze features to detect threats"""
        threats = []
        
        # Check for DDoS patterns
        if features["packet_rate"] > 5000 and features["source_count"] > 10:
            confidence = min(0.95, features["packet_rate"] / 10000)
            threats.append({
                "threat_type": "DDoS_Attack",
                "severity": "high",
                "confidence": confidence,
                "description": f"High traffic volume ({features['packet_rate']} packets/sec) from {features['source_count']} sources",
                "source_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.1.{random.randint(1,255)}"
            })
        
        # Check for Brute Force patterns
        if features["failed_logins"] > 5:
            confidence = min(0.9, features["failed_logins"] / 15)
            threats.append({
                "threat_type": "Brute_Force",
                "severity": "medium" if features["failed_logins"] < 10 else "high",
                "confidence": confidence,
                "description": f"{features['failed_logins']} failed login attempts detected",
                "source_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.2.{random.randint(1,255)}"
            })
        
        # Check for Port Scanning
        if features["unique_ports"] > 20:
            confidence = min(0.85, features["unique_ports"] / 100)
            threats.append({
                "threat_type": "Port_Scan",
                "severity": "medium",
                "confidence": confidence,
                "description": f"Scanning detected across {features['unique_ports']} ports",
                "source_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.3.{random.randint(1,255)}"
            })
        
        # Check for SQL Injection
        if features["sql_patterns"] > 3:
            confidence = min(0.95, features["sql_patterns"] / 10)
            threats.append({
                "threat_type": "SQL_Injection",
                "severity": "high",
                "confidence": confidence,
                "description": f"SQL injection patterns detected ({features['sql_patterns']} attempts)",
                "source_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.4.{random.randint(1,255)}"
            })
        
        return threats
    
    def batch_detect(self, n_samples=10):
        """Detect threats in batch"""
        results = []
        for _ in range(n_samples):
            results.append(self.detect())
        return results

if __name__ == "__main__":
    # Test the detector
    detector = ThreatDetector()
    result = detector.detect()
    
    print("Threat Detection Test:")
    print(f"Threat Type: {result['threat_type']}")
    print(f"Severity: {result['severity']}")
    print(f"Confidence: {result['confidence']:.2%}")
    print(f"Description: {result['description']}")