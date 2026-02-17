"""
Train a simple threat detection model
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

def train_simple_model():
    """Train a simple threat detection model"""
    print("🔄 Training Threat Detection Model...")
    
    # Create synthetic training data
    np.random.seed(42)
    n_samples = 1000
    
    # Features: [packet_rate, failed_logins, unique_ports, sql_patterns]
    X = []
    y = []
    
    # Normal traffic (70%)
    for _ in range(int(n_samples * 0.7)):
        X.append([
            np.random.normal(1000, 200),    # packet_rate
            np.random.randint(0, 3),        # failed_logins
            np.random.randint(1, 10),       # unique_ports
            np.random.randint(0, 2)         # sql_patterns
        ])
        y.append(0)  # Normal
    
    # DDoS attacks (10%)
    for _ in range(int(n_samples * 0.1)):
        X.append([
            np.random.normal(8000, 1000),   # High packet_rate
            np.random.randint(0, 2),
            np.random.randint(1, 5),
            0
        ])
        y.append(1)  # DDoS
    
    # Brute Force attacks (10%)
    for _ in range(int(n_samples * 0.1)):
        X.append([
            np.random.normal(100, 30),
            np.random.randint(5, 15),       # Many failed_logins
            np.random.randint(1, 3),
            0
        ])
        y.append(2)  # BruteForce
    
    # Port Scanning (10%)
    for _ in range(int(n_samples * 0.1)):
        X.append([
            np.random.normal(500, 100),
            np.random.randint(0, 2),
            np.random.randint(20, 50),      # Many unique_ports
            0
        ])
        y.append(3)  # PortScan
    
    X = np.array(X)
    y = np.array(y)
    
    print(f"Training data shape: {X.shape}")
    print(f"Class distribution: Normal: {sum(y==0)}, DDoS: {sum(y==1)}, BruteForce: {sum(y==2)}, PortScan: {sum(y==3)}")
    
    # Train model
    model = RandomForestClassifier(
        n_estimators=50,
        max_depth=10,
        random_state=42
    )
    
    model.fit(X, y)
    
    # Evaluate
    train_score = model.score(X, y)
    print(f"✅ Training accuracy: {train_score:.2%}")
    
    # Save model
    os.makedirs('model/saved', exist_ok=True)
    joblib.dump(model, 'model/saved/threat_model.pkl')
    
    print("✅ Model saved to 'model/saved/threat_model.pkl'")
    
    # Test predictions
    print("\n📊 Sample Predictions:")
    test_samples = [
        [8000, 1, 3, 0],    # Should predict DDoS
        [150, 10, 2, 0],    # Should predict BruteForce
        [600, 1, 30, 0],    # Should predict PortScan
        [1200, 2, 8, 1]     # Should predict Normal
    ]
    
    for i, sample in enumerate(test_samples):
        pred = model.predict([sample])[0]
        threat_types = ['Normal', 'DDoS', 'BruteForce', 'PortScan']
        print(f"  Sample {i+1}: Predicted = {threat_types[pred]}")
    
    return model

if __name__ == "__main__":
    train_simple_model()