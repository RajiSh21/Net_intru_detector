"""
Example script demonstrating real-time intrusion detection usage.

This script shows how to:
1. Load a trained model
2. Set up real-time monitoring with callbacks
3. Use simulation mode for testing
4. Access detection statistics
"""

import time
import os
import sys

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.intrusion_detector import NetworkIntrusionDetector
from core.realtime_detector import simulate_network_traffic


def main():
    print("="*60)
    print("Network Intrusion Detection - Example Usage")
    print("="*60)
    
    # Step 1: Load trained model
    print("\n[1] Loading trained model...")
    try:
        model_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'intrusion_detector.joblib')
        detector = NetworkIntrusionDetector.load(model_path)
        print("✅ Model loaded successfully")
    except FileNotFoundError:
        print("❌ No trained model found. Please run: python train.py")
        return
    
    # Step 2: Define a callback function for detections
    print("\n[2] Setting up detection callback...")
    
    detection_count = {"normal": 0, "attack": 0}
    
    def on_detection(features, prediction, probabilities, timestamp, src_ip, dst_ip, location):
        """Called for each packet detection."""
        is_attack = prediction != "normal" and prediction != 0
        
        location_str = f"{location.get('city', 'Unknown')}, {location.get('country', 'Unknown')}"
        
        if is_attack:
            detection_count["attack"] += 1
            print(f"🚨 [{timestamp.strftime('%H:%M:%S')}] ATTACK from {src_ip} ({location_str})")
            print(f"   Type: {prediction} | Confidence: {max(probabilities):.1%}")
        else:
            detection_count["normal"] += 1
            # Only print every 10th normal packet to reduce output
            if detection_count["normal"] % 10 == 0:
                print(f"✅ [{timestamp.strftime('%H:%M:%S')}] Normal traffic from {src_ip}")
                print(f"   Total normal: {detection_count['normal']}")
    
    # Step 3: Start monitoring in simulation mode
    print("\n[3] Starting network monitoring (simulation mode)...")
    print("    Duration: 30 seconds")
    print("    Note: This generates realistic network traffic patterns\n")
    
    monitor = simulate_network_traffic(detector, duration=30)
    monitor.callback = on_detection
    
    # Step 4: Wait for simulation to complete
    print("Monitoring in progress...\n")
    time.sleep(31)  # Wait for simulation to complete
    
    # Step 5: Display final statistics
    print("\n" + "="*60)
    print("Detection Summary")
    print("="*60)
    
    stats = monitor.get_statistics()
    total_attacks = sum(stats["attacks"].values())
    
    print(f"\n📊 Total Packets Analyzed: {stats['total_packets']}")
    print(f"✅ Normal Traffic: {stats['normal']} ({stats['normal']/stats['total_packets']*100:.1f}%)")
    print(f"🚨 Total Attacks: {total_attacks} ({total_attacks/stats['total_packets']*100:.1f}%)")
    
    if stats["attacks"]:
        print(f"\n🎯 Attack Breakdown:")
        for attack_type, count in sorted(stats["attacks"].items(), key=lambda x: x[1], reverse=True):
            print(f"   • {attack_type}: {count}")
    
    # Step 6: Show recent detections
    print(f"\n📋 Last 5 Detections:")
    recent = monitor.get_recent_detections(n=5)
    for i, det in enumerate(recent, 1):
        pred = det["prediction"]
        conf = det["confidence"] * 100
        ts = det["timestamp"].strftime("%H:%M:%S")
        src_ip = det.get("src_ip", "N/A")
        location = det.get("location_summary", "Unknown")
        print(f"   {i}. [{ts}] {pred} ({conf:.1f}% confidence)")
        print(f"      From: {src_ip} ({location})")
    
    print("\n" + "="*60)
    print("Example complete!")
    print("\n💡 Tip: Run 'python run_dashboard.py' for a web-based dashboard")
    print("="*60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nExample stopped by user.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
