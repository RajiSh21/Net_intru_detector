# Quick Start Guide - Network Intrusion Detection System

## 🚀 Get Started in 3 Steps

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `scikit-learn` - Machine learning framework
- `pandas` & `numpy` - Data processing
- `flask` & `flask-socketio` - Web dashboard
- `scapy` - Network packet capture (optional for real-time capture)

### Step 2: Launch the Dashboard

```bash
python run_dashboard.py
```

This will:
1. Check if a trained model exists
2. If not, automatically download NSL-KDD dataset and train a model (~2-3 minutes)
3. Start the web dashboard on http://localhost:5000

### Step 3: View Real-Time Detections

Open your browser to:
```
http://localhost:5000
```

You'll see:
- 📊 Live statistics (packets, normal traffic, attacks)
- 📈 Interactive charts showing traffic patterns
- 🚨 Real-time attack detection table
- 🎯 Attack breakdown by type

---

## 🎯 What You'll See

### Dashboard Features

1. **Status Bar** (top)
   - Connection status indicator
   - Control buttons: Start, Stop, Clear History

2. **Statistics Cards** (4 cards)
   - Total packets processed
   - Normal traffic count
   - Attacks detected
   - Detection rate percentage

3. **Attack Breakdown**
   - Lists attack types: DoS, Probe, R2L, U2R
   - Shows count for each type

4. **Charts** (2 interactive charts)
   - Pie chart: Normal vs Attack distribution
   - Timeline: Attack pattern over last 50 packets

5. **Recent Detections Table**
   - Timestamp, prediction, confidence
   - Protocol, service, byte statistics
   - Color-coded by attack type

---

## 🔧 Alternative Usage

### Command Line Training

Train a model manually:

```bash
# Multi-class detection (DoS, Probe, R2L, U2R)
python train.py

# Binary detection (normal vs attack)
python train.py --binary

# Custom settings
python train.py --n-estimators 200 --output my_model.joblib
```

### Run Example Script

See real-time detection in action:

```bash
python example_realtime.py
```

### Use in Python Code

```python
from intrusion_detector import NetworkIntrusionDetector
from realtime_detector import simulate_network_traffic

# Load model
detector = NetworkIntrusionDetector.load("intrusion_detector.joblib")

# Start monitoring (simulation mode)
monitor = simulate_network_traffic(detector, duration=60)

# Get statistics
stats = monitor.get_statistics()
print(f"Attacks detected: {sum(stats['attacks'].values())}")
```

---

## 📝 Notes

### Simulation Mode vs Real Capture

**Simulation Mode (Default)**
- ✅ No special permissions required
- ✅ Works on any system
- ✅ Generates realistic traffic patterns
- ✅ Perfect for testing and demonstration

**Real Packet Capture**
- ⚠️ Requires root/sudo privileges
- ⚠️ Needs network interface access
- ✅ Captures actual network traffic
- ✅ Real-world intrusion detection

To use real packet capture:
```bash
sudo python dashboard.py
```

### System Requirements

- Python 3.9+
- 4GB RAM (for model training)
- Modern web browser (Chrome, Firefox, Safari, Edge)

---

## 🆘 Troubleshooting

### "No trained model found"
**Solution:** Run `python train.py` first, or use `python run_dashboard.py` which trains automatically.

### "Cannot connect to dashboard"
**Solution:** Check if port 5000 is available. Change port in `dashboard.py` if needed.

### "Scapy not installed"
**Solution:** Install with `pip install scapy`. Not needed for simulation mode.

### Dashboard shows no data
**Solution:** Wait a few seconds for simulation to start generating traffic.

---

## 📚 Next Steps

1. **Customize the model:**
   - Adjust `n_estimators` in training
   - Try binary vs multi-class mode
   - Use your own training data

2. **Extend the dashboard:**
   - Modify `templates/dashboard.html` for custom styling
   - Add new charts or statistics
   - Integrate with alerting systems

3. **Deploy in production:**
   - Use real packet capture mode
   - Set up logging and monitoring
   - Implement automated responses to threats

---

## 📖 Full Documentation

See [README.md](README.md) for complete documentation.

---

**Need help?** Check the example files:
- `example_realtime.py` - Basic usage example
- `train.py` - Model training
- `dashboard.py` - Web dashboard implementation
