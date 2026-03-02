# Net_intru_detector

A machine-learning–based **Network Intrusion Detection System (NIDS)** trained on the [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html) benchmark dataset.

## Features

- **Multi-class detection** – classifies traffic as *normal*, *DoS*, *Probe*, *R2L*, or *U2R*
- **Binary mode** – predict simply *normal* vs *attack*
- Random Forest classifier with standard scaling and label encoding
- Save/load trained models with `joblib`
- Handles unseen categorical values gracefully

## Requirements

- Python 3.9+

Install dependencies:

```bash
pip install -r requirements.txt
```

## Quick Start

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

## Tests

```bash
python -m pytest tests/ -v
```
