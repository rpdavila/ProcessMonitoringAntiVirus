CyberDefender EDR 🛡️
CyberDefender is a lightweight, real-time Endpoint Detection and Response (EDR) system built in Python. It monitors system processes, analyzes behavioral anomalies, and integrates with the VirusTotal API to provide cloud-based malware detection and automated response.
This is a Project application for learning how EDR Heuristics work and is no way something to replace your own heuristics' application.
🚀 Features
Real-Time Monitoring: Tracks Process Name, PID, CPU usage, and Memory consumption.

Heuristic Detection: Automatically flags processes exceeding 500MB of RAM or exhibiting suspicious naming conventions.

VirusTotal Integration: Performs SHA-256 hashing on process executables and queries the cloud for engine detections.

Automated Response: Implements a "Kill-on-Sight" policy for confirmed threats.

Secure Quarantine: Moves malicious binaries to a protected directory to prevent re-execution.

Live Dashboard: A beautiful terminal UI powered by Rich that displays a live audit trail of all security actions.

🛠️ System Architecture
The project utilizes a Dual-Threaded Architecture:

Monitor Thread: Continuously snapshots the OS process tree using psutil.

Worker Thread: Handles asynchronous, high-latency tasks such as file hashing, VirusTotal uploads, and result polling.

Thread Safety: Uses threading.Lock to ensure data integrity between the backend worker and the live UI.

📋 Reaction Policy
The system follows a strict response hierarchy:

High Risk: If VirusTotal detections > 3, the process is terminated and the file is quarantined.

Anomalous: If a process uses > 500MB RAM, it is flagged in the UI for administrator review.

⚙️ Installation & Setup
1. Prerequisites
Python 3.8+

A VirusTotal API Key (Get one here)

2. Install Dependencies
Bash
pip install psutil vt-py python-dotenv rich
3. Environment Configuration
Create a .env file in the root directory:

Code snippet
API=your_virustotal_api_key_here
4. Run the EDR
Bash
python main.py
📂 Project Structure
main.py: The entry point and Security Worker logic.

processes.py: The core Heuristic Engine and process monitor.

virus_total_checker.py: Logic for API communication and status polling.

/quarantine/: Secure storage for neutralized threats.

🧪 Testing with EICAR
To test the detection capabilities safely, you can use the EICAR Standard Anti-Malware Test File. Simply rename the test file to test_threat.exe and run it; CyberDefender will detect the hash and neutralize it.
