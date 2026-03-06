# Net_intru_detector

A machine-learning–based **Network Intrusion Detection System (NIDS)** trained on the [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html) benchmark dataset.

## Features

- **Multi-class detection** – classifies traffic as *normal*, *DoS*, *Probe*, *R2L*, or *U2R*
- **Binary mode** – predict simply *normal* vs *attack*
- **Real-time monitoring** – capture and analyze live network traffic
- **Interactive dashboard** – web-based visualization of real-time attacks
- **IP Geolocation tracking** – identify geographic source of attacks (country, city, coordinates)
- **Attack source visualization** – see where attacks are coming from with country flags
- Random Forest classifier with standard scaling and label encoding
- Save/load trained models with `joblib`
- Handles unseen categorical values gracefully

## Project Structure

```
Net_intru_detector/
├── src/                      # Source code
│   ├── core/                 # Core detection modules
│   │   ├── intrusion_detector.py    # Main ML detector class
│   │   ├── realtime_detector.py     # Real-time monitoring
│   │   ├── ip_geolocation.py        # Geolocation & app tracking
│   │   └── train.py                 # Training script
│   ├── web/                  # Web dashboard
│   │   ├── dashboard.py             # Flask server & API
│   │   ├── visualize_dashboard.py   # Visualization tools
│   │   └── templates/               # HTML templates
│   └── utils/                # Utility functions
├── data/                     # Data and models
│   └── intrusion_detector.joblib    # Trained model
├── examples/                 # Example scripts
│   ├── demo_app_tracking.py         # Feature demo
│   └── example_realtime.py          # Real-time usage
├── tests/                    # Unit tests
├── docs/                     # Documentation
│   ├── QUICKSTART.md
│   ├── IMPLEMENTATION.md
│   └── PROJECT_SUMMARY.md
├── run_dashboard.py          # Main launcher script
├── requirements.txt          # Dependencies
└── README.md                 # This file
```

## Requirements

- Python 3.9+

Install dependencies:

```bash
pip install -r requirements.txt
```

## Quick Start

### 🚀 Launch the Real-Time Dashboard (Recommended)

The easiest way to get started is with the interactive dashboard:

```bash
# Install dependencies
pip install -r requirements.txt

# Launch the dashboard (will train a model if needed)
python run_dashboard.py
```

Then open your browser to **http://localhost:5000** to see:
- Real-time attack detection and classification
- Live statistics (total packets, normal traffic, attacks detected)
- Attack breakdown by type (DoS, Probe, R2L, U2R)
- Interactive charts and graphs
- Recent detection history table

**Note:** The dashboard runs in simulation mode by default (generates realistic traffic patterns). For real packet capture, see the [Advanced Usage](#advanced-usage) section below.

### Train and evaluate

```bash
# Multi-class (default) – downloads NSL-KDD automatically
python train.py

# Binary mode (normal vs attack)
python train.py --binary

# Use local dataset files
python train.py --train path/to/KDDTrain+.txt --test path/to/KDDTest+.txt

# Save the model to a custom path
python train.py --output my_model.joblib
```

### Use the detector in Python

```python
from intrusion_detector import NetworkIntrusionDetector

# Load a trained model
detector = NetworkIntrusionDetector.load("intrusion_detector.joblib")

# Predict a single network record (dict of NSL-KDD feature values)
sample = {
    "duration": 0,
    "protocol_type": "tcp",
    "service": "http",
    "flag": "SF",
    "src_bytes": 215,
    "dst_bytes": 45076,
    # … all 41 NSL-KDD features …
}
label = detector.predict(sample)   # e.g. ['normal'] or ['DoS']
proba = detector.predict_proba(sample)

# Train from scratch
detector = NetworkIntrusionDetector(binary=False, n_estimators=100)
train_df, test_df = detector.load_data()
detector.fit(train_df)
detector.evaluate(test_df)
detector.save("intrusion_detector.joblib")
```

## Real-Time Monitoring

### Dashboard Features

The web dashboard provides comprehensive real-time monitoring:

1. **Live Statistics Cards**
   - Total packets processed
   - Normal traffic count
   - Attacks detected
   - Detection rate percentage

2. **Attack Breakdown**
   - Real-time list of attack types and counts
   - Sortable by frequency

3. **Attack Source Locations**
   - Geographic tracking of intrusion sources
   - Top 10 attack origin countries/cities
   - Visual progress bars showing attack distribution
   - Country flags for easy identification

4. **Interactive Visualizations**
   - Pie chart: Normal vs Attack traffic distribution
   - Timeline chart: Attack pattern over last 50 packets

5. **Recent Detections Table**
   - Timestamp, prediction, confidence level
   - Source IP address and geographic location
   - Protocol and service information
   - Country flags for attack sources
   - Color-coded badges for attack types
   - Scrollable history

6. **Control Panel**
   - Start/Stop monitoring
   - Clear history
   - Real-time connection status

### Programmatic Usage

Use the real-time monitor in your Python code:

```python
from intrusion_detector import NetworkIntrusionDetector
from realtime_detector import RealtimeNetworkMonitor, simulate_network_traffic

# Load trained model
detector = NetworkIntrusionDetector.load("intrusion_detector.joblib")

# Create monitor with callback
def on_detection(features, prediction, probabilities, timestamp):
    print(f"[{timestamp}] Detected: {prediction} (confidence: {max(probabilities):.2%})")

monitor = RealtimeNetworkMonitor(detector, callback=on_detection)

# Start capturing (requires root privileges for real capture)
monitor.start(interface=None)  # None = all interfaces

# Or use simulation mode for testing
monitor = simulate_network_traffic(detector, duration=60)

# Get statistics
stats = monitor.get_statistics()
print(f"Total packets: {stats['total_packets']}")
print(f"Attacks detected: {sum(stats['attacks'].values())}")

# Get recent detections
recent = monitor.get_recent_detections(n=10)
for detection in recent:
    print(detection['prediction'], detection['confidence'])

# Stop monitoring
monitor.stop()
```

## Advanced Usage

### Real Packet Capture (Requires Root)

For capturing actual network packets (not simulation):

```bash
# Run with sudo for packet capture privileges
sudo python dashboard.py
```

Or programmatically:

```python
from intrusion_detector import NetworkIntrusionDetector
from realtime_detector import RealtimeNetworkMonitor

detector = NetworkIntrusionDetector.load("intrusion_detector.joblib")
monitor = RealtimeNetworkMonitor(detector)

# Capture on specific interface
monitor.start(interface="eth0")  # or "wlan0", etc.

# Capture on all interfaces
monitor.start(interface=None)
```

**Note:** Real packet capture requires:
- Root/sudo privileges
- Scapy library (`pip install scapy`)
- Appropriate network interface permissions

### Customizing the Dashboard

The dashboard can be customized by modifying [dashboard.py](dashboard.py):

- Change port: `socketio.run(app, port=8080)`
- Adjust history size: `RealtimeNetworkMonitor(detector, max_history=5000)`
- Modify update frequency: Change the polling interval in the JavaScript code
- Custom styling: Edit the CSS in `templates/dashboard.html`

## Dataset

The NSL-KDD dataset is automatically downloaded from GitHub when you run `train.py`.  
You can also supply local CSV files via `--train` / `--test`.

| Split       | Samples |
|-------------|---------|
| KDDTrain+   | 125,973 |
| KDDTest+    |  22,544 |

Attack families covered:

| Family | Description                       | Example attacks               |
|--------|-----------------------------------|-------------------------------|
| DoS    | Denial of Service                 | neptune, smurf, teardrop      |
| Probe  | Network scanning / probing        | ipsweep, nmap, portsweep      |
| R2L    | Remote-to-Local unauthorised access | ftp_write, guess_passwd     |
| U2R    | User-to-Root privilege escalation | buffer_overflow, rootkit      |

## Project Structure

```
Net_intru_detector/
├── intrusion_detector.py     # Core ML model (Random Forest classifier)
├── train.py                   # Training script for the model
├── realtime_detector.py       # Real-time packet capture and analysis
├── dashboard.py               # Web dashboard with Flask and Socket.IO
├── run_dashboard.py           # Quick launcher for the dashboard
├── requirements.txt           # Python dependencies
├── README.md                  # This file
└── tests/                     # Unit tests
    ├── __init__.py
    └── test_intrusion_detector.py
```

## Tests

```bash
python -m pytest tests/ -v
```
