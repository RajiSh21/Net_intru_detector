"""
Visual demonstration of the dashboard features.
Run this to see ASCII art representation of the dashboard layout.
"""

def print_dashboard_preview():
    """Print a visual preview of the dashboard."""
    
    dashboard = r"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                  🛡️  NETWORK INTRUSION DETECTION DASHBOARD                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌───────────────────────────────────────────────────────────────────────────┐
│ Status: 🟢 Connected - Monitoring Active                                  │
│ [▶ Start]  [⏹ Stop]  [🗑️ Clear History]                                  │
└───────────────────────────────────────────────────────────────────────────┘

╔═══════════════════╗  ╔═══════════════════╗  ╔═══════════════════╗  ╔═══════════════════╗
║ Total Packets     ║  ║ Normal Traffic    ║  ║ Attacks Detected  ║  ║ Detection Rate    ║
║                   ║  ║                   ║  ║                   ║  ║                   ║
║      12,453       ║  ║      11,234       ║  ║       1,219       ║  ║       9.8%        ║
╚═══════════════════╝  ╚═══════════════════╝  ╚═══════════════════╝  ╚═══════════════════╝

╔═══════════════════════════════════════════════════════════════════════════════╗
║                           ATTACK BREAKDOWN                                     ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  DoS     ████████████████████████████████████ 850                             ║
║  Probe   ████████████ 250                                                     ║
║  R2L     ██████ 100                                                           ║
║  U2R     ██ 19                                                                ║
╚═══════════════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────┬─────────────────────────────────────┐
│  Traffic Classification (Pie)      │  Detection Timeline (Line)          │
│                                     │                                     │
│         ╭─────╮                     │      Attacks                        │
│       ╱       ╲                     │        │                            │
│      │  90%    │                    │      1 │     ╱╲    ╱╲              │
│      │ Normal  │                    │        │    ╱  ╲  ╱  ╲   ╱╲        │
│       ╲       ╱                     │      0 │───╱────╲╱────╲─╱──╲───    │
│         ╰─────╯                     │        └───────────────────────→    │
│       ╱       ╲                     │             Packets                 │
│      │  10%    │                    │                                     │
│      │ Attack  │                    │                                     │
│       ╲       ╱                     │                                     │
└─────────────────────────────────────┴─────────────────────────────────────┘

╔═══════════════════════════════════════════════════════════════════════════════╗
║                          RECENT DETECTIONS                                     ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ Timestamp    │ Prediction │ Confidence │ Protocol │ Service │ Src Bytes       ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ 14:32:45.231 │ 🚨 DoS      │   94.2%    │   tcp    │  http   │   5,423        ║
║ 14:32:45.102 │ ✅ normal   │   99.8%    │   tcp    │  http   │   1,234        ║
║ 14:32:44.987 │ 🚨 Probe    │   87.5%    │   tcp    │  ssh    │     623        ║
║ 14:32:44.756 │ ✅ normal   │   98.1%    │   udp    │  domain │     156        ║
║ 14:32:44.523 │ 🚨 DoS      │   96.8%    │   tcp    │  http   │  12,456        ║
║ 14:32:44.234 │ ✅ normal   │   99.2%    │   tcp    │  https  │   2,345        ║
╚═══════════════════════════════════════════════════════════════════════════════╝

                    Open in browser: http://localhost:5000
"""
    
    print(dashboard)
    print("\n" + "="*80)
    print("Features of the Real-Time Dashboard:")
    print("="*80)
    print()
    print("✅ Live WebSocket updates - See attacks as they happen")
    print("✅ Interactive charts - Click and zoom on data")
    print("✅ Color-coded badges - Easily identify attack types")
    print("✅ Confidence scoring - Know how certain the detection is")
    print("✅ Protocol analysis - TCP, UDP, ICMP tracking")
    print("✅ Attack breakdown - See which attacks are most common")
    print("✅ Responsive design - Works on desktop and mobile")
    print("✅ Real-time statistics - Updated every second")
    print()
    print("="*80)
    print("Attack Types Detected:")
    print("="*80)
    print()
    print("🔴 DoS (Denial of Service)")
    print("   └─ Neptune, Smurf, Teardrop, Apache2, Mailbomb")
    print()
    print("🟡 Probe (Reconnaissance)")
    print("   └─ Nmap, Portsweep, IPsweep, Satan, MScan")
    print()
    print("🔵 R2L (Remote to Local)")
    print("   └─ FTP Write, Guess Password, IMAP, Multihop, Warezmaster")
    print()
    print("🟣 U2R (User to Root)")
    print("   └─ Buffer Overflow, Rootkit, Loadmodule, Perl, SQLattack")
    print()
    print("="*80)


def print_system_architecture():
    """Print the system architecture diagram."""
    
    architecture = r"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                        SYSTEM ARCHITECTURE                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

                              ┌─────────────────────┐
                              │   Web Browser       │
                              │  (User Interface)   │
                              └──────────┬──────────┘
                                         │
                              WebSocket (Socket.IO)
                                         │
                              ┌──────────▼──────────┐
┌──────────────┐              │   dashboard.py      │
│ Network      │  Packets     │  - Flask Server     │
│ Traffic      ├─────────────►│  - REST API         │
│ (Real/Sim)   │              │  - Real-time Events │
└──────────────┘              └──────────┬──────────┘
                                         │
                              ┌──────────▼──────────────────┐
                              │  realtime_detector.py       │
                              │  - Packet Capture (Scapy)   │
                              │  - Feature Extraction       │
                              │  - Flow Tracking            │
                              │  - Statistics               │
                              └──────────┬──────────────────┘
                                         │
                              Features (41 dimensions)
                                         │
                              ┌──────────▼──────────────────┐
                              │  intrusion_detector.py     │
                              │  - Random Forest Model     │
                              │  - Label Encoding          │
                              │  - Feature Scaling         │
                              │  - Prediction              │
                              └──────────┬──────────────────┘
                                         │
                              ┌──────────▼──────────────────┐
                              │      Classification         │
                              │   normal / DoS / Probe      │
                              │      R2L / U2R              │
                              └─────────────────────────────┘

╔══════════════════════════════════════════════════════════════════════════════╗
║                           DATA FLOW                                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

  Network        Feature       Model         Stats         Dashboard
  Packet    ──►  Extraction ──► Predict  ──►  Update   ──►   Display
  (Raw)          (41 dims)      (Class)       (Counter)      (Web UI)
     │               │              │             │              │
     │               │              │             │              │
  Scapy         NSL-KDD        Random        Thread-Safe    Socket.IO
  Capture       Features       Forest         Dictionary     Broadcast
"""
    
    print(architecture)


def main():
    """Main function to display all visualizations."""
    print("\n")
    print("="*80)
    print("        NETWORK INTRUSION DETECTION SYSTEM - VISUAL GUIDE")
    print("="*80)
    print("\n")
    
    print_dashboard_preview()
    print("\n" * 2)
    print_system_architecture()
    
    print("\n" + "="*80)
    print("                    HOW TO GET STARTED")
    print("="*80)
    print()
    print("Step 1: Install dependencies")
    print("        $ pip install -r requirements.txt")
    print()
    print("Step 2: Launch the dashboard")
    print("        $ python run_dashboard.py")
    print()
    print("Step 3: Open your browser")
    print("        Navigate to: http://localhost:5000")
    print()
    print("="*80)
    print()
    print("📚 For full documentation, see:")
    print("   • README.md - Complete feature documentation")
    print("   • QUICKSTART.md - Quick start guide")
    print("   • IMPLEMENTATION.md - Technical details")
    print("   • example_realtime.py - Code examples")
    print()
    print("="*80)


if __name__ == "__main__":
    main()
