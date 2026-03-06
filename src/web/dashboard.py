"""
Real-time Network Intrusion Detection Dashboard.

Web-based dashboard for visualizing live network intrusion detection.
Uses Flask and Socket.IO for real-time updates.
"""

import json
import os
import sys
from datetime import datetime
from typing import Optional

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.intrusion_detector import NetworkIntrusionDetector
from core.realtime_detector import RealtimeNetworkMonitor, simulate_network_traffic

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'network-intrusion-detector-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global monitor instance
monitor: Optional[RealtimeNetworkMonitor] = None
detector: Optional[NetworkIntrusionDetector] = None


def emit_detection(features, prediction, probabilities, timestamp, src_ip, dst_ip, app_tracking):
    """Callback to emit detections to connected clients."""
    try:
        location = app_tracking.get('source_location', {})
        application = app_tracking.get('application', {})
        
        # Prepare detection data
        detection_data = {
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "prediction": str(prediction),
            "confidence": float(max(probabilities)) * 100,  # Convert to percentage
            "protocol": features.get("protocol_type", "unknown"),
            "service": features.get("service", "unknown"),
            "src_bytes": int(features.get("src_bytes", 0)),
            "dst_bytes": int(features.get("dst_bytes", 0)),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": app_tracking.get("destination_port", 0),
            "application": application.get("application", "Unknown"),
            "app_category": application.get("category", "Unknown"),
            "app_icon": application.get("icon", "🔧"),
            "location": location.get('city', 'Unknown') + ", " + location.get('country', 'Unknown'),
            "country": location.get('country', 'Unknown'),
            "country_code": location.get('country_code', 'XX'),
            "latitude": location.get('latitude', 0.0),
            "longitude": location.get('longitude', 0.0),
        }
        
        # Emit to all connected clients
        socketio.emit('new_detection', detection_data, namespace='/')
    except Exception as e:
        print(f"Error emitting detection: {e}")


@app.route('/')
def index():
    """Serve the main dashboard page."""
    return render_template('dashboard.html')


@app.route('/api/status')
def get_status():
    """Get current monitoring status."""
    if monitor is None:
        return jsonify({"running": False, "error": "Monitor not initialized"})
    
    return jsonify({
        "running": monitor.is_running,
        "statistics": monitor.get_statistics(),
    })


@app.route('/api/statistics')
def get_statistics():
    """Get detection statistics."""
    if monitor is None:
        return jsonify({"error": "Monitor not initialized"}), 400
    
    stats = monitor.get_statistics()
    return jsonify(stats)


@app.route('/api/applications', methods=['GET'])
def get_applications():
    """Get application tracking statistics."""
    if monitor is None:
        return jsonify({"error": "Monitor not initialized"}), 400
    
    app_stats = monitor.get_application_statistics()
    
    # Format for frontend
    return jsonify({
        "total_attacks": app_stats.get("total_attacks", 0),
        "unique_targets": app_stats.get("unique_targets", 0),
        "unique_sources": app_stats.get("unique_sources", 0),
        "top_targets": [{"name": name, "count": count} for name, count in app_stats.get("top_targets", [])],
        "top_sources": [{"country": country, "count": count} for country, count in app_stats.get("top_sources", [])],
        "top_ports": [{"port": port, "count": count} for port, count in app_stats.get("top_ports", [])],
        "protocol_distribution": app_stats.get("protocol_distribution", {}),
    })


@app.route('/api/recent', methods=['GET'])
def get_recent():
    """Get recent detections."""
    if monitor is None:
        return jsonify({"error": "Monitor not initialized"}), 400
    
    n = request.args.get('n', default=100, type=int)
    detections = monitor.get_recent_detections(n)
    
    # Format detections for JSON response
    formatted = []
    for det in detections:
        app_info = det.get("application", {})
        loc_info = det.get("source_location", {})
        
        formatted.append({
            "timestamp": det["timestamp"].strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "prediction": str(det["prediction"]),
            "confidence": det["confidence"] * 100,
            "protocol": det.get("protocol", det["features"].get("protocol_type", "unknown")),
            "service": det["features"].get("service", "unknown"),
            "src_bytes": int(det["features"].get("src_bytes", 0)),
            "dst_bytes": int(det["features"].get("dst_bytes", 0)),
            "src_ip": det.get("src_ip", "N/A"),
            "dst_ip": det.get("dst_ip", "N/A"),
            "dst_port": det.get("dst_port", 0),
            "application": app_info.get("application", "Unknown"),
            "app_category": app_info.get("category", "Unknown"),
            "app_icon": app_info.get("icon", "🔧"),
            "app_description": app_info.get("description", ""),
            "location": det.get("location_summary", loc_info.get("city", "Unknown")),
            "country": loc_info.get("country", "Unknown"),
            "country_code": loc_info.get("country_code", "XX"),
            "city": loc_info.get("city", "Unknown"),
            "latitude": loc_info.get("latitude", 0.0),
            "longitude": loc_info.get("longitude", 0.0),
            "isp": loc_info.get("isp", "Unknown"),
        })
    
    return jsonify(formatted)


@app.route('/api/start', methods=['POST'])
def start_monitoring():
    """Start the network monitor."""
    global monitor
    
    if monitor is None:
        return jsonify({"error": "Monitor not initialized"}), 400
    
    if monitor.is_running:
        return jsonify({"message": "Monitor already running"})
    
    data = request.get_json() or {}
    interface = data.get('interface', None)
    
    try:
        monitor.start(interface=interface)
        return jsonify({"message": "Monitoring started", "interface": interface or "all"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/stop', methods=['POST'])
def stop_monitoring():
    """Stop the network monitor."""
    if monitor is None:
        return jsonify({"error": "Monitor not initialized"}), 400
    
    monitor.stop()
    return jsonify({"message": "Monitoring stopped"})


@app.route('/api/clear', methods=['POST'])
def clear_history():
    """Clear detection history."""
    if monitor is None:
        return jsonify({"error": "Monitor not initialized"}), 400
    
    monitor.clear_history()
    return jsonify({"message": "History cleared"})


@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    print(f"Client connected: {request.sid}")
    emit('connection_response', {"status": "connected"})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    print(f"Client disconnected: {request.sid}")


@socketio.on('request_update')
def handle_request_update():
    """Handle client request for current statistics."""
    if monitor:
        stats = monitor.get_statistics()
        emit('statistics_update', stats)


def create_templates_directory():
    """Create templates directory and HTML file for the dashboard."""
    templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
    os.makedirs(templates_dir, exist_ok=True)
    
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Intrusion Detection Dashboard</title>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        header {
            background: white;
            padding: 20px 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        
        h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .status-bar {
            display: flex;
            align-items: center;
            gap: 20px;
            flex-wrap: wrap;
        }
        
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 16px;
            background: #f0f0f0;
            border-radius: 20px;
            font-size: 14px;
        }
        
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #dc3545;
            animation: pulse 2s infinite;
        }
        
        .status-dot.active {
            background: #28a745;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .controls {
            display: flex;
            gap: 10px;
        }
        
        button {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .btn-start {
            background: #28a745;
            color: white;
        }
        
        .btn-start:hover {
            background: #218838;
        }
        
        .btn-stop {
            background: #dc3545;
            color: white;
        }
        
        .btn-stop:hover {
            background: #c82333;
        }
        
        .btn-clear {
            background: #6c757d;
            color: white;
        }
        
        .btn-clear:hover {
            background: #5a6268;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .stat-title {
            font-size: 14px;
            color: #666;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .stat-value {
            font-size: 36px;
            font-weight: bold;
            color: #333;
        }
        
        .stat-value.normal {
            color: #28a745;
        }
        
        .stat-value.attack {
            color: #dc3545;
        }
        
        .chart-container {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        
        .chart-title {
            font-size: 18px;
            font-weight: 600;
            color: #333;
            margin-bottom: 20px;
        }
        
        .detections-table {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #333;
            border-bottom: 2px solid #dee2e6;
        }
        
        td {
            padding: 12px;
            border-bottom: 1px solid #dee2e6;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .badge-normal {
            background: #d4edda;
            color: #155724;
        }
        
        .badge-attack {
            background: #f8d7da;
            color: #721c24;
        }
        
        .badge-dos {
            background: #f8d7da;
            color: #721c24;
        }
        
        .badge-probe {
            background: #fff3cd;
            color: #856404;
        }
        
        .badge-r2l {
            background: #d1ecf1;
            color: #0c5460;
        }
        
        .badge-u2r {
            background: #e2d8f9;
            color: #4a148c;
        }
        
        .confidence {
            font-weight: 600;
        }
        
        .confidence.high {
            color: #28a745;
        }
        
        .confidence.medium {
            color: #ffc107;
        }
        
        .confidence.low {
            color: #dc3545;
        }
        
        .no-data {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        
        .table-scroll {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .attack-breakdown {
            margin-top: 15px;
        }
        
        .attack-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }
        
        .attack-item:last-child {
            border-bottom: none;
        }
        
        .attack-name {
            font-weight: 600;
            color: #666;
        }
        
        .attack-count {
            font-weight: 600;
            color: #dc3545;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Network Intrusion Detection System</h1>
            <div class="status-bar">
                <div class="status-indicator">
                    <div class="status-dot" id="statusDot"></div>
                    <span id="statusText">Disconnected</span>
                </div>
                <div class="controls">
                    <button class="btn-start" onclick="startMonitoring()">▶ Start Monitoring</button>
                    <button class="btn-stop" onclick="stopMonitoring()">⏹ Stop</button>
                    <button class="btn-clear" onclick="clearHistory()">🗑️ Clear History</button>
                </div>
            </div>
        </header>
        
        <div class="dashboard-grid">
            <div class="stat-card">
                <div class="stat-title">Total Packets</div>
                <div class="stat-value" id="totalPackets">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Normal Traffic</div>
                <div class="stat-value normal" id="normalTraffic">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Attacks Detected</div>
                <div class="stat-value attack" id="attacksDetected">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Detection Rate</div>
                <div class="stat-value" id="detectionRate">0%</div>
            </div>
        </div>
        
        <div class="stat-card">
            <div class="stat-title">Attack Breakdown</div>
            <div class="attack-breakdown" id="attackBreakdown">
                <div class="no-data">No attacks detected yet</div>
            </div>
        </div>
        
        <div class="chart-container" style="margin-top: 20px;">
            <div class="chart-title">🌍 Attack Source Locations (Top 10)</div>
            <div id="locationsList" style="max-height: 300px; overflow-y: auto;">
                <div class="no-data">No attacks detected yet</div>
            </div>
        </div>
        
        <div style="margin-top: 20px; display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div class="chart-container">
                <div class="chart-title">Traffic Classification</div>
                <canvas id="pieChart"></canvas>
            </div>
            <div class="chart-container">
                <div class="chart-title">Detection Timeline (Last 50 packets)</div>
                <canvas id="timelineChart"></canvas>
            </div>
        </div>
        
        <div class="detections-table">
            <div class="chart-title">Recent Detections</div>
            <div class="table-scroll">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Prediction</th>
                            <th>Confidence</th>
                            <th>Source IP</th>
                            <th>Location</th>
                            <th>Protocol</th>
                            <th>Service</th>
                        </tr>
                    </thead>
                    <tbody id="detectionsTableBody">
                        <tr>
                            <td colspan="7" class="no-data">No detections yet. Start monitoring to see live data.</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <script>
        // Initialize Socket.IO connection
        const socket = io();
        
        // Chart instances
        let pieChart;
        let timelineChart;
        
        // Data storage
        let detectionHistory = [];
        const maxHistoryDisplay = 50;
        
        // Socket.IO event handlers
        socket.on('connect', function() {
            console.log('Connected to server');
            updateStatusIndicator(true);
            requestUpdate();
        });
        
        socket.on('disconnect', function() {
            console.log('Disconnected from server');
            updateStatusIndicator(false);
        });
        
        socket.on('new_detection', function(data) {
            addDetection(data);
            updateCharts();
        });
        
        socket.on('statistics_update', function(stats) {
            updateStatistics(stats);
        });
        
        // Initialize charts
        function initCharts() {
            // Pie chart
            const pieCtx = document.getElementById('pieChart').getContext('2d');
            pieChart = new Chart(pieCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Normal', 'Attacks'],
                    datasets: [{
                        data: [0, 0],
                        backgroundColor: ['#28a745', '#dc3545'],
                        borderWidth: 2,
                        borderColor: '#fff'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
            
            // Timeline chart
            const timelineCtx = document.getElementById('timelineChart').getContext('2d');
            timelineChart = new Chart(timelineCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Attacks',
                        data: [],
                        borderColor: '#dc3545',
                        backgroundColor: 'rgba(220, 53, 69, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                stepSize: 1
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });
        }
        
        function updateStatusIndicator(connected) {
            const dot = document.getElementById('statusDot');
            const text = document.getElementById('statusText');
            if (connected) {
                dot.classList.add('active');
                text.textContent = 'Connected - Monitoring Active';
            } else {
                dot.classList.remove('active');
                text.textContent = 'Disconnected';
            }
        }
        
        function addDetection(detection) {
            detectionHistory.unshift(detection);
            if (detectionHistory.length > maxHistoryDisplay) {
                detectionHistory.pop();
            }
            updateDetectionsTable();
            updateLocationsList();
            fetchStatistics();
        }
        
        function updateLocationsList() {
            const locationsList = document.getElementById('locationsList');
            
            // Count attacks by location
            const locationCounts = {};
            detectionHistory.forEach(det => {
                const isAttack = det.prediction !== 'normal' && det.prediction !== '0';
                if (isAttack && det.location) {
                    const loc = det.location;
                    locationCounts[loc] = (locationCounts[loc] || 0) + 1;
                }
            });
            
            // Sort by count
            const sortedLocations = Object.entries(locationCounts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10);  // Top 10
            
            if (sortedLocations.length === 0) {
                locationsList.innerHTML = '<div class="no-data">No attacks detected yet</div>';
                return;
            }
            
            // Get country codes for flags
            const locationFlags = {};
            detectionHistory.forEach(det => {
                if (det.location && det.country_code) {
                    locationFlags[det.location] = det.country_code;
                }
            });
            
            locationsList.innerHTML = sortedLocations.map(([location, count]) => {
                const countryCode = locationFlags[location] || 'XX';
                const flag = countryCode !== 'XX' ? 
                    `<img src="https://flagcdn.com/16x12/${countryCode.toLowerCase()}.png" alt="${countryCode}" style="margin-right: 8px;">` : '';
                
                const percentage = (count / sortedLocations.reduce((sum, [,c]) => sum + c, 0) * 100).toFixed(1);
                const barWidth = (count / sortedLocations[0][1] * 100);
                
                return `
                    <div class="attack-item">
                        <div style="display: flex; align-items: center; flex: 1;">
                            ${flag}
                            <span class="attack-name">${location}</span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 10px; min-width: 150px;">
                            <div style="flex: 1; background: #f0f0f0; height: 20px; border-radius: 10px; overflow: hidden;">
                                <div style="width: ${barWidth}%; height: 100%; background: linear-gradient(90deg, #dc3545, #ff6b7a);"></div>
                            </div>
                            <span class="attack-count">${count}</span>
                        </div>
                    </div>
                `;
            }).join('');
        }
        
        function updateDetectionsTable() {
            const tbody = document.getElementById('detectionsTableBody');
            
            if (detectionHistory.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="no-data">No detections yet</td></tr>';
                return;
            }
            
            tbody.innerHTML = detectionHistory.map(det => {
                const isNormal = det.prediction === 'normal' || det.prediction === '0';
                const badgeClass = isNormal ? 'badge-normal' : getBadgeClass(det.prediction);
                const confidenceClass = getConfidenceClass(det.confidence);
                const location = det.location || 'Unknown';
                const srcIp = det.src_ip || 'N/A';
                const flag = det.country_code ? `<img src="https://flagcdn.com/16x12/${det.country_code.toLowerCase()}.png" alt="${det.country_code}" style="margin-right: 4px;">` : '';
                
                return `
                    <tr>
                        <td>${det.timestamp}</td>
                        <td><span class="badge ${badgeClass}">${det.prediction}</span></td>
                        <td><span class="confidence ${confidenceClass}">${det.confidence.toFixed(1)}%</span></td>
                        <td style="font-family: monospace;">${srcIp}</td>
                        <td>${flag}${location}</td>
                        <td>${det.protocol}</td>
                        <td>${det.service}</td>
                    </tr>
                `;
            }).join('');
        }
        
        function getBadgeClass(prediction) {
            const pred = prediction.toLowerCase();
            if (pred.includes('dos')) return 'badge-dos';
            if (pred.includes('probe')) return 'badge-probe';
            if (pred.includes('r2l')) return 'badge-r2l';
            if (pred.includes('u2r')) return 'badge-u2r';
            return 'badge-attack';
        }
        
        function getConfidenceClass(confidence) {
            if (confidence >= 80) return 'high';
            if (confidence >= 60) return 'medium';
            return 'low';
        }
        
        function updateStatistics(stats) {
            document.getElementById('totalPackets').textContent = stats.total_packets.toLocaleString();
            document.getElementById('normalTraffic').textContent = stats.normal.toLocaleString();
            
            const totalAttacks = Object.values(stats.attacks).reduce((a, b) => a + b, 0);
            document.getElementById('attacksDetected').textContent = totalAttacks.toLocaleString();
            
            const rate = stats.total_packets > 0 
                ? ((totalAttacks / stats.total_packets) * 100).toFixed(1)
                : '0.0';
            document.getElementById('detectionRate').textContent = rate + '%';
            
            // Update attack breakdown
            const breakdown = document.getElementById('attackBreakdown');
            if (Object.keys(stats.attacks).length === 0) {
                breakdown.innerHTML = '<div class="no-data">No attacks detected yet</div>';
            } else {
                breakdown.innerHTML = Object.entries(stats.attacks)
                    .sort((a, b) => b[1] - a[1])
                    .map(([type, count]) => `
                        <div class="attack-item">
                            <span class="attack-name">${type}</span>
                            <span class="attack-count">${count.toLocaleString()}</span>
                        </div>
                    `).join('');
            }
            
            // Update pie chart
            pieChart.data.datasets[0].data = [stats.normal, totalAttacks];
            pieChart.update();
        }
        
        function updateCharts() {
            // Update timeline with recent attack pattern
            const recentData = detectionHistory.slice(0, 50).reverse();
            timelineChart.data.labels = recentData.map((_, i) => i + 1);
            timelineChart.data.datasets[0].data = recentData.map(det => {
                return (det.prediction !== 'normal' && det.prediction !== '0') ? 1 : 0;
            });
            timelineChart.update();
        }
        
        function requestUpdate() {
            socket.emit('request_update');
        }
        
        async function fetchStatistics() {
            try {
                const response = await fetch('/api/statistics');
                const stats = await response.json();
                updateStatistics(stats);
            } catch (error) {
                console.error('Error fetching statistics:', error);
            }
        }
        
        async function startMonitoring() {
            try {
                const response = await fetch('/api/start', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'}
                });
                const data = await response.json();
                alert(data.message || data.error);
            } catch (error) {
                alert('Error starting monitoring: ' + error);
            }
        }
        
        async function stopMonitoring() {
            try {
                const response = await fetch('/api/stop', {
                    method: 'POST'
                });
                const data = await response.json();
                alert(data.message || data.error);
            } catch (error) {
                alert('Error stopping monitoring: ' + error);
            }
        }
        
        async function clearHistory() {
            if (!confirm('Are you sure you want to clear all detection history?')) {
                return;
            }
            try {
                const response = await fetch('/api/clear', {
                    method: 'POST'
                });
                const data = await response.json();
                detectionHistory = [];
                updateDetectionsTable();
                fetchStatistics();
                updateCharts();
            } catch (error) {
                alert('Error clearing history: ' + error);
            }
        }
        
        // Initialize on page load
        window.addEventListener('load', function() {
            initCharts();
            fetchStatistics();
            // Poll for updates every 2 seconds
            setInterval(fetchStatistics, 2000);
        });
    </script>
</body>
</html>"""
    
    html_path = os.path.join(templates_dir, 'dashboard.html')
    with open(html_path, 'w') as f:
        f.write(html_content)
    
    print(f"Created dashboard template at: {html_path}")


def main():
    """Main function to run the dashboard."""
    global monitor, detector
    
    # Load trained model
    model_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'intrusion_detector.joblib')
    if not os.path.exists(model_path):
        print(f"Error: No trained model found at {model_path}")
        print("Please train a model first with: python train.py")
        sys.exit(1)
    
    print("Loading trained model...")
    detector = NetworkIntrusionDetector.load(model_path)
    
    # Create templates directory and HTML file
    create_templates_directory()
    
    # Initialize monitor with simulation mode
    print("\nInitializing real-time monitor...")
    print("Note: Using simulation mode. For real packet capture, run with root privileges.")
    
    monitor = simulate_network_traffic(detector, duration=3600)  # 1 hour simulation
    monitor.callback = emit_detection
    
    # Start Flask app
    print("\n" + "="*60)
    print("🚀 Network Intrusion Detection Dashboard is starting...")
    print("="*60)
    print(f"\n📊 Open your browser and navigate to: http://localhost:5000")
    print("\n⚠️  Press Ctrl+C to stop the server\n")
    
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\n\nStopping dashboard...")
        if monitor:
            monitor.stop()
        print("Dashboard stopped.")


if __name__ == "__main__":
    main()
