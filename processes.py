import sys

import psutil
import threading
import time
import hashlib

class Processes:
    """
    Class to check processes and suspicious processes

    """
    def __init__(self):
        self.processes = []
        self.suspicious_processes = []
        self.threats = []
        self.running = False
        self.thread = None
        self.suspicious_processes_threshold = 3
        self.previous_high_mem_pids = set()  # Track previous high-memory PIDs
        self.reported_threats = set()


    def get_processes(self):
        """Get current snapshot of all processes"""
        temp_processes = []
        for process in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
            try:
                pid = process.info['pid']
                name = process.info['name']
                cpu = process.info['cpu_percent']
                mem = process.info['memory_info'][0]/2.0**20
                path = process.exe()
                temp_processes.append({"PID": pid, "Name": name, "CPU": cpu, "Mem": mem, "Path": path})

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                pass  # Silently skip processes we can't access

        self.processes = temp_processes

    def _monitor_loop(self, interval=2):
        """Background thread loop that continuously updates process list"""
        while self.running:
            self.get_processes()
            self.check_for_suspicious_processes()
            time.sleep(interval)

    def start_monitoring(self, interval=2):
        """Start monitoring processes in background thread"""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._monitor_loop, args=(interval,), daemon=True)
            self.thread.start()
            print(f"Process monitoring started (updates every {interval}s)")

    def stop_monitoring(self):
        """Stop the monitoring thread"""
        if self.running:
            self.running = False
            if self.thread:
                self.thread.join()
            print("Process monitoring stopped")

    def list_number_of_processes(self):
        """Print all current processes"""
        sys.stdout.write(f"\r--- Process List ({len(self.processes)} processes) ---")

    def check_for_suspicious_processes(self):
        self.suspicious_processes = []
        for proc in self.processes:
            if self._is_suspicious(proc):
                self.suspicious_processes.append(proc)

    def get_suspicious_processes(self):
        return self.suspicious_processes

    def get_high_memory_count(self):
        """Count processes using > 500MB memory"""
        return sum(1 for proc in self.processes if proc["Mem"] > 500)

    def display_high_memory_processes(self):
        """Display processes exceeding 500MB memory - only if list changed"""
        high_mem_procs = [proc for proc in self.processes if proc["Mem"] > 500]
        current_pids = set(proc["PID"] for proc in high_mem_procs)

        # Only display if the list changed
        if current_pids != self.previous_high_mem_pids:
            self.previous_high_mem_pids = current_pids
            print("\n" + "="*40)  # New line after status line

            if high_mem_procs:
                print(f"⚠️  High Memory Usage Detected ({len(high_mem_procs)} processes):")
                for proc in high_mem_procs:
                    # Using f-string padding to keep columns aligned
                    print(f"  - {proc['Name'][:25]:25} | PID: {proc['PID']:<6} | Mem: {proc['Mem']:>8.2f} MB")
            else:
                # This triggers when the last high-mem process finally closes
                print("✅ High memory usage has been cleared.")

            print("=" * 50 + "\n")

    def _is_suspicious(self, proc):
        high_cpu = proc["CPU"] > 80
        high_mem = proc["Mem"] > 500
        return high_cpu or high_mem

    def compute_hash(self, proc, algorithm="sha256"):
        try:
            hash_object = hashlib.new(algorithm)
            with open(proc["Path"], "rb") as f:
                while chunk := f.read(8192):
                    hash_object.update(chunk)
            return hash_object.hexdigest()
        except (FileNotFoundError, PermissionError, OSError):
            return None

    def check_suspicious_with_vt(self, vt_checker):
        self.threats = []  # Clear old threats
        for proc in self.suspicious_processes:
            pid = proc['PID']

            file_hash = self.compute_hash(proc)
            if not file_hash: continue  # Skip this process, check next one

            result = vt_checker.check_file_hash(file_hash)
            if not result: continue  # Skip this process, check next one

            if result["detections"] > self.suspicious_processes_threshold:
                threat = {
                    **proc,
                    "hash": file_hash,
                    "vt_detections": result["detections"],
                    "vt_total": result["total_vendors"]
                }

                if not any(t['PID'] == pid for t in self.threats):
                    self.threats.append(threat)

                if pid not in self.reported_threats:
                    print(f"\n[!] ALERT: {proc['Name']} (PID: {pid}) flagged by {result['detections']} vendors!")
                    self.reported_threats.add(pid)

        return self.threats
