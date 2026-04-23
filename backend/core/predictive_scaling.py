import random
import numpy as np
from sklearn.linear_model import LinearRegression

def predict_cpu_load():
    """
    Simulates recent CloudWatch CPU Utilization percent data across time.
    Uses scikit-learn Linear Regression to predict if the load will exceed 80% 
    in the upcoming window.
    """
    # Simulate past 10 minutes of CPU load data (x: minutes ago, y: CPU %)
    # Let's create an aggressively scaling trend
    past_minutes = np.array([[-10], [-9], [-8], [-7], [-6], [-5], [-4], [-3], [-2], [-1], [0]])
    base_load = [35.2, 40.1, 44.5, 48.0, 50.2, 55.4, 58.9, 62.1, 65.0, 70.3, 74.8]
    
    # Introduce slight randomness
    actual_load = np.array([val + random.uniform(-2, 2) for val in base_load])
    
    # Train model
    model = LinearRegression()
    model.fit(past_minutes, actual_load)
    
    # Predict next 5 minutes
    future_minutes = np.array([[1], [2], [3], [4], [5]])
    predicted_load = model.predict(future_minutes)
    
    # Check if any prediction exceeds 80%
    exceeds_threshold = any(load >= 80.0 for load in predicted_load)
    
    return {
        "historical": list(actual_load),
        "predicted": list(predicted_load),
        "exceeds_threshold": exceeds_threshold,
        "recommendation": "Provision extra instances immediately." if exceeds_threshold else "Capacity adequate."
    }
