"""
Real-time Network Intrusion Detection System.

Captures live network packets and processes them for intrusion detection.
Works with the trained NetworkIntrusionDetector model.
"""

import time
from collections import deque
from datetime import datetime
from threading import Lock, Thread
from typing import Callable, Optional

import pandas as pd

try:
    from scapy.all import IP, TCP, UDP, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not installed. Install with: pip install scapy")

from .intrusion_detector import NetworkIntrusionDetector, COLUMN_NAMES
from .ip_geolocation import IPGeocoder, ApplicationTracker


class RealtimeNetworkMonitor:
    """Real-time network traffic monitor and intrusion detector.
    
    Captures live network packets, extracts features, and classifies
    them using a trained NetworkIntrusionDetector model.
    
    Parameters
    ----------
    detector : NetworkIntrusionDetector
        Pre-trained intrusion detector model.
    max_history : int
        Maximum number of recent detections to store.
    callback : Optional[Callable]
        Function called for each detection with signature:
        callback(packet_features, prediction, probabilities, timestamp)
    """
    
    def __init__(
        self,
        detector: NetworkIntrusionDetector,
        max_history: int = 1000,
        callback: Optional[Callable] = None,
    ):
        if not SCAPY_AVAILABLE:
            raise ImportError(
                "scapy is required for real-time monitoring. "
                "Install with: pip install scapy"
            )
        
        self.detector = detector
        self.max_history = max_history
        self.callback = callback
        
        # Thread-safe storage for detections
        self._detections = deque(maxlen=max_history)
        self._lock = Lock()
        self._running = False
        self._thread = None
        
        # Initialize geolocation and application tracking
        self._geocoder = IPGeocoder()
        self._app_tracker = ApplicationTracker()
        
        # Statistics
        self._stats = {
            "total_packets": 0,
            "normal": 0,
            "attacks": {},
        }
        self._stats_lock = Lock()
        
        # Flow tracking for feature extraction
        self._flows = {}
        self._flow_window = 100  # Packets to consider for flow features
    
    def _extract_features(self, packet) -> Optional[tuple]:
        """Extract NSL-KDD-like features from a scapy packet.
        
        Returns
        -------
        tuple or None
            (features_dict, source_ip, dest_ip, dest_port, protocol) or None if packet invalid
        """
        try:
            if not packet.haslayer(IP):
                return None
            
            # Initialize features with default values
            features = {col: 0 for col in COLUMN_NAMES[:-2]}  # Exclude attack_type, difficulty
            
            # Basic packet info
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            features["src_bytes"] = len(packet)
            features["dst_bytes"] = 0  # Will be updated with flow tracking
            
            # Protocol detection and port extraction
            dst_port = 0
            protocol = "other"
            
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                dst_port = tcp_layer.dport
                protocol = "tcp"
                features["protocol_type"] = "tcp"
                features["service"] = self._guess_service(dst_port)
                
                # TCP flags
                flags = tcp_layer.flags
                if flags:
                    features["flag"] = self._parse_tcp_flags(flags)
                else:
                    features["flag"] = "SF"  # Default
                    
                features["urgent"] = tcp_layer.urgptr
                
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                dst_port = udp_layer.dport
                protocol = "udp"
                features["protocol_type"] = "udp"
                features["service"] = self._guess_service(dst_port)
                features["flag"] = "SF"
            else:
                protocol = "icmp"
                features["protocol_type"] = "icmp"
                features["service"] = "ecr_i"
                features["flag"] = "SF"
            
            # Flow-based features (simplified)
            flow_key = (
                ip_layer.src,
                ip_layer.dst,
                getattr(packet[TCP] if packet.haslayer(TCP) else packet[UDP] if packet.haslayer(UDP) else None, 'sport', 0),
                getattr(packet[TCP] if packet.haslayer(TCP) else packet[UDP] if packet.haslayer(UDP) else None, 'dport', 0),
            )
            
            self._update_flow(flow_key, features)
            
            # Additional features (set reasonable defaults)
            features["logged_in"] = 0
            features["duration"] = 0
            features["count"] = features.get("count", 1)
            features["srv_count"] = features.get("srv_count", 1)
            
            # Rate features (normalized)
            features["same_srv_rate"] = 1.0
            features["diff_srv_rate"] = 0.0
            features["serror_rate"] = 0.0
            features["srv_serror_rate"] = 0.0
            features["rerror_rate"] = 0.0
            features["srv_rerror_rate"] = 0.0
            
            # Host-based features
            features["dst_host_count"] = 255
            features["dst_host_srv_count"] = 255
            features["dst_host_same_srv_rate"] = 1.0
            features["dst_host_diff_srv_rate"] = 0.0
            features["dst_host_same_src_port_rate"] = 1.0
            features["dst_host_srv_diff_host_rate"] = 0.0
            features["dst_host_serror_rate"] = 0.0
            features["dst_host_srv_serror_rate"] = 0.0
            features["dst_host_rerror_rate"] = 0.0
            features["dst_host_srv_rerror_rate"] = 0.0
            
            return (features, src_ip, dst_ip, dst_port, protocol)
            
        except Exception as e:
            print(f"Error extracting features: {e}")
            return None
    
    def _guess_service(self, port: int) -> str:
        """Map port number to service name."""
        service_map = {
            20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet",
            25: "smtp", 53: "domain_u", 80: "http", 110: "pop_3",
            143: "imap4", 443: "https", 3306: "mysql", 5432: "postgresql",
            6379: "redis", 8080: "http", 8443: "https",
        }
        return service_map.get(port, "other")
    
    def _parse_tcp_flags(self, flags) -> str:
        """Parse TCP flags to NSL-KDD flag format."""
        # Simplified flag mapping
        flag_map = {
            "S": "S0",    # SYN
            "SA": "SF",   # SYN-ACK
            "F": "SF",    # FIN
            "R": "REJ",   # RST
            "PA": "SF",   # PSH-ACK
            "FA": "SF",   # FIN-ACK
        }
        flag_str = str(flags)
        return flag_map.get(flag_str, "SF")
    
    def _update_flow(self, flow_key: tuple, features: dict):
        """Update flow-based features."""
        if flow_key not in self._flows:
            self._flows[flow_key] = {
                "count": 0,
                "packets": deque(maxlen=self._flow_window),
                "srv_count": 0,
            }
        
        flow = self._flows[flow_key]
        flow["count"] += 1
        flow["srv_count"] += 1
        flow["packets"].append(features)
        
        features["count"] = min(flow["count"], 511)
        features["srv_count"] = min(flow["srv_count"], 511)
        
        # Clean old flows (keep last 1000)
        if len(self._flows) > 1000:
            oldest_key = next(iter(self._flows))
            del self._flows[oldest_key]
    
    def _process_packet(self, packet):
        """Process a captured packet."""
        try:
            result = self._extract_features(packet)
            if result is None:
                return
            
            features, src_ip, dst_ip, dst_port, protocol = result
            
            # Make prediction
            prediction = self.detector.predict(features)[0]
            probabilities = self.detector.predict_proba(features)[0]
            timestamp = datetime.now()
            
            # Determine if this is an attack
            is_attack = prediction != "normal" and prediction != 0
            attack_type = str(prediction) if is_attack else None
            
            # Track application and geolocation
            app_tracking = self._app_tracker.track_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                is_attack=is_attack,
                attack_type=attack_type,
                geocoder=self._geocoder,
                use_simulation=True  # Use simulation for consistent results
            )
            
            # Store detection with enhanced information
            detection = {
                "timestamp": timestamp,
                "features": features,
                "prediction": prediction,
                "probabilities": probabilities.tolist() if hasattr(probabilities, 'tolist') else probabilities,
                "confidence": float(max(probabilities)),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "application": app_tracking["application"],
                "source_location": app_tracking["source_location"],
                "location_summary": f"{app_tracking['source_location']['city']}, {app_tracking['source_location']['country']}",
            }
            
            with self._lock:
                self._detections.append(detection)
            
            # Update statistics
            with self._stats_lock:
                self._stats["total_packets"] += 1
                if is_attack:
                    self._stats["attacks"][attack_type] = \
                        self._stats["attacks"].get(attack_type, 0) + 1
                else:
                    self._stats["normal"] += 1
            
            # Call callback if provided
            if self.callback:
                self.callback(features, prediction, probabilities, timestamp, src_ip, dst_ip, app_tracking)
                
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def start(self, interface: Optional[str] = None, packet_count: int = 0):
        """Start capturing packets in a background thread.
        
        Parameters
        ----------
        interface : Optional[str]
            Network interface to capture on (None = all interfaces).
        packet_count : int
            Number of packets to capture (0 = infinite).
        """
        if self._running:
            print("Monitor already running")
            return
        
        self._running = True
        
        def capture():
            print(f"Starting packet capture on interface: {interface or 'all'}")
            print("Press Ctrl+C to stop...")
            try:
                sniff(
                    iface=interface,
                    prn=self._process_packet,
                    count=packet_count,
                    store=False,
                    stop_filter=lambda _: not self._running,
                )
            except Exception as e:
                print(f"Capture error: {e}")
            finally:
                self._running = False
        
        self._thread = Thread(target=capture, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Stop packet capture."""
        if self._running:
            print("Stopping packet capture...")
            self._running = False
            if self._thread:
                self._thread.join(timeout=5)
    
    def get_recent_detections(self, n: int = 100) -> list:
        """Get the n most recent detections."""
        with self._lock:
            return list(self._detections)[-n:]
    
    def get_statistics(self) -> dict:
        """Get current detection statistics including application tracking."""
        with self._stats_lock:
            base_stats = self._stats.copy()
        
        # Add application tracking statistics
        app_stats = self._app_tracker.get_statistics_summary()
        base_stats.update({
            "top_targeted_apps": app_stats.get("top_targets", [])[:5],
            "top_source_countries": app_stats.get("top_sources", [])[:5],
            "top_attacked_ports": app_stats.get("top_ports", [])[:5],
            "protocol_distribution": app_stats.get("protocol_distribution", {}),
        })
        
        return base_stats
    
    def get_application_statistics(self) -> dict:
        """Get detailed application tracking statistics."""
        return self._app_tracker.get_statistics_summary()
    
    def get_top_targets(self, n: int = 10) -> list:
        """Get most targeted applications."""
        return self._app_tracker.get_top_targets(n)
    
    def get_top_source_countries(self, n: int = 10) -> list:
        """Get top attack source countries."""
        return self._app_tracker.get_top_source_countries(n)
    
    def clear_history(self):
        """Clear detection history and statistics."""
        with self._lock:
            self._detections.clear()
        with self._stats_lock:
            self._stats = {
                "total_packets": 0,
                "normal": 0,
                "attacks": {},
            }
        self._app_tracker.clear_statistics()
    
    @property
    def is_running(self) -> bool:
        """Check if monitor is currently running."""
        return self._running


def simulate_network_traffic(detector: NetworkIntrusionDetector, duration: int = 60) -> RealtimeNetworkMonitor:
    """Simulate network traffic for testing without packet capture.
    
    Parameters
    ----------
    detector : NetworkIntrusionDetector
        Pre-trained intrusion detector model.
    duration : int
        Simulation duration in seconds.
    
    Returns
    -------
    RealtimeNetworkMonitor
        Monitor with simulated detections.
    """
    import random
    
    monitor = RealtimeNetworkMonitor(detector)
    
    def generate_sample():
        """Generate a random network sample with port and protocol."""
        sample = {}
        
        # Generate realistic port and protocol
        common_ports = [80, 443, 22, 25, 3306, 8080, 3389, 1433, 5432, 21, 23]
        dst_port = random.choice(common_ports + [random.randint(1024, 65535)])
        protocol = random.choice(["tcp", "tcp", "tcp", "udp"])  # More TCP traffic
        
        # Numeric features with realistic ranges
        sample["duration"] = random.randint(0, 10000)
        sample["src_bytes"] = random.randint(0, 50000)
        sample["dst_bytes"] = random.randint(0, 50000)
        sample["land"] = random.choice([0, 0, 0, 1])
        sample["wrong_fragment"] = random.choice([0, 0, 0, 1])
        sample["urgent"] = 0
        sample["hot"] = random.randint(0, 5)
        sample["num_failed_logins"] = random.choice([0, 0, 0, 1, 2])
        sample["logged_in"] = random.choice([0, 1])
        sample["num_compromised"] = random.choice([0, 0, 0, 1])
        sample["root_shell"] = 0
        sample["su_attempted"] = 0
        sample["num_root"] = random.randint(0, 2)
        sample["num_file_creations"] = random.randint(0, 5)
        sample["num_shells"] = 0
        sample["num_access_files"] = random.randint(0, 3)
        sample["num_outbound_cmds"] = 0
        sample["is_host_login"] = 0
        sample["is_guest_login"] = random.choice([0, 0, 1])
        sample["count"] = random.randint(1, 511)
        sample["srv_count"] = random.randint(1, 511)
        
        # Categorical features
        sample["protocol_type"] = random.choice(["tcp", "udp", "icmp"])
        sample["service"] = random.choice(["http", "ftp", "smtp", "ssh", "other"])
        sample["flag"] = random.choice(["SF", "S0", "REJ", "RSTR", "S1"])
        
        # Rate features
        for key in ["serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
                    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate"]:
            sample[key] = random.random()
        
        # Host-based features
        sample["dst_host_count"] = random.randint(1, 255)
        sample["dst_host_srv_count"] = random.randint(1, 255)
        
        for key in ["dst_host_same_srv_rate", "dst_host_diff_srv_rate",
                    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
                    "dst_host_serror_rate", "dst_host_srv_serror_rate",
                    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"]:
            sample[key] = random.random()
        
        return sample, dst_port, protocol
    
    def simulate():
        """Simulate traffic for specified duration."""
        start_time = time.time()
        packet_num = 0
        
        while time.time() - start_time < duration:
            sample, dst_port, protocol = generate_sample()
            prediction = detector.predict(sample)[0]
            probabilities = detector.predict_proba(sample)[0]
            timestamp = datetime.now()
            
            # Generate random source IP
            src_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            dst_ip = "192.168.1.100"  # Simulated local server
            
            # Determine if attack
            is_attack = prediction != "normal" and prediction != 0
            attack_type = str(prediction) if is_attack else None
            
            # Track application
            app_tracking = monitor._app_tracker.track_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                is_attack=is_attack,
                attack_type=attack_type,
                geocoder=monitor._geocoder,
                use_simulation=True
            )
            
            detection = {
                "timestamp": timestamp,
                "features": sample,
                "prediction": prediction,
                "probabilities": probabilities.tolist(),
                "confidence": float(max(probabilities)),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "application": app_tracking["application"],
                "source_location": app_tracking["source_location"],
                "location_summary": f"{app_tracking['source_location']['city']}, {app_tracking['source_location']['country']}",
            }
            
            with monitor._lock:
                monitor._detections.append(detection)
            
            with monitor._stats_lock:
                monitor._stats["total_packets"] += 1
                if is_attack:
                    monitor._stats["attacks"][attack_type] = \
                        monitor._stats["attacks"].get(attack_type, 0) + 1
                else:
                    monitor._stats["normal"] += 1
            
            if monitor.callback:
                monitor.callback(sample, prediction, probabilities, timestamp, src_ip, dst_ip, app_tracking)
            
            packet_num += 1
            time.sleep(random.uniform(0.01, 0.5))  # Random delay between packets
        
        print(f"Simulation complete: {packet_num} packets generated")
    
    monitor._running = True
    thread = Thread(target=simulate, daemon=True)
    thread.start()
    monitor._thread = thread
    
    return monitor


if __name__ == "__main__":
    import sys
    
    # Load trained model
    try:
        detector = NetworkIntrusionDetector.load("intrusion_detector.joblib")
    except FileNotFoundError:
        print("Error: No trained model found. Train a model first with: python train.py")
        sys.exit(1)
    
    # Create monitor with callback
    def print_detection(features, prediction, probabilities, timestamp, src_ip, dst_ip, location):
        location_str = location.get('location_summary', f"{location.get('city', 'Unknown')}, {location.get('country', 'Unknown')}")
        print(f"[{timestamp.strftime('%H:%M:%S')}] "
              f"Prediction: {prediction} (confidence: {max(probabilities):.2%}) "
              f"from {src_ip} ({location_str})")
    
    monitor = RealtimeNetworkMonitor(detector, callback=print_detection)
    
    # Use simulation mode for testing (requires root for real capture)
    print("Starting simulation mode (use dashboard.py for real-time monitoring)")
    monitor = simulate_network_traffic(detector, duration=30)
    
    try:
        time.sleep(31)
    except KeyboardInterrupt:
        print("\nStopping...")
    
    stats = monitor.get_statistics()
    print(f"\nStatistics:")
    print(f"  Total packets: {stats['total_packets']}")
    print(f"  Normal traffic: {stats['normal']}")
    print(f"  Attacks: {sum(stats['attacks'].values())}")
    for attack_type, count in stats['attacks'].items():
        print(f"    {attack_type}: {count}")
