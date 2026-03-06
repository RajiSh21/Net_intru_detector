"""
Demo script showcasing Application and Geolocation Tracking features.

This demonstrates:
1. Which applications/services are being targeted
2. Where attacks are coming from geographically
3. Detailed port and protocol information
"""

import time
import os
import sys

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.intrusion_detector import NetworkIntrusionDetector
from core.realtime_detector import simulate_network_traffic


def print_section(title):
    """Print a formatted section header."""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")


def main():
    print("\n" + "🎯"*35)
    print("   APPLICATION & GEOLOCATION TRACKING DEMO")
    print("🎯"*35)
    
    # Load trained model
    print_section("📚 Loading Model")
    try:
        model_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'intrusion_detector.joblib')
        detector = NetworkIntrusionDetector.load(model_path)
        print("✅ Model loaded successfully!")
    except FileNotFoundError:
        print("❌ No trained model found. Please run: python train.py")
        return
    
    # Start monitoring with enhanced tracking
    print_section("🚀 Starting Enhanced Monitoring")
    print("⏱️  Running simulation for 20 seconds...")
    print("📡 Tracking applications and geolocation...")
    
    monitor = simulate_network_traffic(detector, duration=20)
    time.sleep(21)  # Wait for simulation to complete
    
    # Get application statistics
    print_section("🎯 Targeted Applications")
    top_targets = monitor.get_top_targets(10)
    
    if top_targets:
        print("Applications under attack:")
        for i, (app_name, count) in enumerate(top_targets, 1):
            bar = "█" * min(count, 50)
            print(f"  {i:2d}. {app_name:25s} {bar} {count} attacks")
    else:
        print("  No attacks detected yet")
    
    # Get geographic sources
    print_section("🌍 Attack Source Locations")
    top_countries = monitor.get_top_source_countries(10)
    
    if top_countries:
        print("Countries with most attack sources:")
        for i, (country, count) in enumerate(top_countries, 1):
            bar = "█" * min(count, 50)
            print(f"  {i:2d}. {country:25s} {bar} {count} attacks")
    else:
        print("  No attacks detected yet")
    
    # Show recent detections with full details
    print_section("📋 Recent Attack Details")
    recent_detections = monitor.get_recent_detections(5)
    
    for i, detection in enumerate(recent_detections, 1):
        prediction = detection["prediction"]
        
        # Only show attacks
        if prediction == "normal"  or prediction == 0:
            continue
            
        app_info = detection.get("application", {})
        loc_info = detection.get("source_location", {})
        
        print(f"\n🚨 Attack #{i}")
        print(f"  ├─ Type: {prediction}")
        print(f"  ├─ Confidence: {detection['confidence']*100:.1f}%")
        print(f"  ├─ Time: {detection['timestamp'].strftime('%H:%M:%S')}")
        print(f"  ├─ Source: {detection['src_ip']}")
        print(f"  │   └─ Location: {loc_info.get('city', 'Unknown')}, {loc_info.get('country', 'Unknown')}")
        print(f"  │   └─ ISP: {loc_info.get('isp', 'Unknown')}")
        print(f"  └─ Target Application:")
        print(f"      ├─ {app_info.get('icon', '🔧')} {app_info.get('application', 'Unknown')}")
        print(f"      ├─ Category: {app_info.get('category', 'Unknown')}")
        print(f"      ├─ Port: {detection.get('dst_port', 0)}/{detection.get('protocol', 'unknown')}")
        print(f"      └─ {app_info.get('description', 'No description')}")
    
    # Protocol distribution
    print_section("📊 Protocol Distribution")
    app_stats = monitor.get_application_statistics()
    protocols = app_stats.get("protocol_distribution", {})
    
    if protocols:
        total = sum(protocols.values())
        for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            bar = "█" * int(percentage / 2)
            print(f"  {proto.upper():10s} {bar:50s} {count:4d} ({percentage:5.1f}%)")
    
    # Overall summary
    print_section("📈 Summary Statistics")
    stats = monitor.get_statistics()
    total_packets = stats["total_packets"]
    total_attacks = sum(stats["attacks"].values())
    
    print(f"  Total Packets Analyzed:     {total_packets:,}")
    print(f"  Normal Traffic:             {stats['normal']:,} ({stats['normal']/total_packets*100:.1f}%)")
    print(f"  Total Attacks Detected:     {total_attacks:,} ({total_attacks/total_packets*100:.1f}%)")
    print(f"  Unique Applications Targeted: {len(top_targets)}")
    print(f"  Attack Source Countries:    {len(top_countries)}")
    
    # Attack breakdown
    print(f"\n  Attack Types Detected:")
    for attack_type, count in sorted(stats["attacks"].items(), key=lambda x: x[1], reverse=True):
        print(f"    • {attack_type:15s} {count:4d} attacks")
    
    print("\n" + "="*70)
    print("💡 Key Features Demonstrated:")
    print("="*70)
    print("  ✅ Application identification (web, database, email, etc.)")
    print("  ✅ Geographic source tracking (country, city, ISP)")
    print("  ✅ Port and protocol analysis")
    print("  ✅ Service categorization")
    print("  ✅ Real-time attack attribution")
    print("="*70)
    
    print("\n🎉 Demo Complete!")
    print("\n💻 To see this in action on the dashboard:")
    print("   1. Run: python run_dashboard.py")
    print("   2. Open: http://localhost:5000")
    print("   3. View real-time application and location tracking!\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDemo stopped by user.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
