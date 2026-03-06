#!/usr/bin/env python3
"""
Quick launcher for the Network Intrusion Detection Dashboard.

This script checks if a trained model exists, trains one if needed,
and launches the web dashboard.
"""

import os
import sys

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def check_model_exists():
    """Check if a trained model exists."""
    return os.path.exists("data/intrusion_detector.joblib")


def train_model():
    """Train a new model."""
    print("\n" + "="*60)
    print("No trained model found. Training a new model...")
    print("="*60 + "\n")
    print("This will download the NSL-KDD dataset and train a model.")
    print("This may take a few minutes...\n")
    
    try:
        from core.intrusion_detector import NetworkIntrusionDetector
        
        # Create and train detector
        detector = NetworkIntrusionDetector(binary=False, n_estimators=100)
        train_df, test_df = detector.load_data()
        detector.fit(train_df)
        detector.evaluate(test_df)
        
        # Ensure data directory exists
        os.makedirs("data", exist_ok=True)
        detector.save("data/intrusion_detector.joblib")
        
        print("\n✅ Model training complete!")
        return True
    except Exception as e:
        print(f"\n❌ Error training model: {e}")
        return False


def launch_dashboard():
    """Launch the dashboard."""
    print("\n" + "="*60)
    print("Launching Network Intrusion Detection Dashboard...")
    print("="*60 + "\n")
    
    try:
        from web.dashboard import main
        main()
    except KeyboardInterrupt:
        print("\n\nDashboard stopped by user.")
    except Exception as e:
        print(f"\n❌ Error launching dashboard: {e}")
        sys.exit(1)


def main():
    """Main launcher function."""
    print("\n🛡️  Network Intrusion Detection System")
    print("="*60)
    
    # Check if model exists
    if not check_model_exists():
        response = input("\nNo trained model found. Train one now? (y/n): ").strip().lower()
        if response == 'y':
            if not train_model():
                print("\nFailed to train model. Exiting.")
                sys.exit(1)
        else:
            print("\nCannot start dashboard without a trained model.")
            print("Please run: python train.py")
            sys.exit(1)
    else:
        print("\n✅ Found trained model: data/intrusion_detector.joblib")
    launch_dashboard()


if __name__ == "__main__":
    main()
