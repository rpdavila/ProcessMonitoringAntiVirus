import shutil

import psutil
import threading
import time
import hashlib
import os


class Processes:
    def __init__(self):
        self.processes = []
        self.suspicious_processes = []
        self.threats = []
        self.running = False
        self.lock = threading.Lock()
        self.reported_pids = set()
        self.quarantine_folder = "C:\\Quarantine"
        if not os.path.exists(self.quarantine_folder): os.mkdir(self.quarantine_folder)

    def apply_policy(self, proc_data, detection_count):
        pid = proc_data["PID"]
        path = proc_data["Path"]
        name = proc_data["Name"]

        try:
            process = psutil.Process(pid)
            if name.lower() == "virus.exe":
                if process.is_running():
                    process.suspend()
                time.sleep(0.1)
                process.terminate()
                time.sleep(0.1)
                self.quarantine_file(path)
                return "Killed & Quarantined (Name Match)"

            if detection_count > 3:
                process.suspend()
                process.terminate()
                time.sleep(0.1)
                self.quarantine_file(path)
                return f"Suspended & Quarantined (High Detection Rate) {detection_count} Detections"
            if proc_data["Mem"] > 500:
                return "Warning: High Memory Usage"
        except psutil.AccessDenied:
            return "Action Denied (System Protected)"
        except Exception as e:
            return f"Action Failed: {e}"

        return "Clean"

    def quarantine_file(self, file_path):
        try:
            if os.path.exists(file_path):
                file_name = os.path.basename(file_path)
                dest = os.path.join(self.quarantine_folder, file_name)
                shutil.move(file_path, dest)
        except Exception:
            pass

    def create_dump(self, pid):
        """Captures memory state before killing the threat."""
        try:
            dump_file = os.path.join(self.quarantine_folder, f"dump_pid_{pid}.dmp")
            # Using subprocess to run the external procdump tool
            import subprocess
            subprocess.run(["procdump.exe", "-ma", str(pid), dump_file],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except:
            return False

    def get_processes_snapshot(self):
        """Standard scan of all system processes."""
        temp = []
        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                # Basic stats
                mem = proc.info['memory_info'].rss / (1024 * 1024)
                temp.append({
                    "PID": proc.info['pid'],
                    "Name": proc.info['name'],
                    "Mem": mem,
                    "Path": proc.exe()
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        with self.lock:
            self.processes = temp
            # Update suspicious list (e.g., processes > 500MB)
            self.suspicious_processes = [p for p in temp if p["Mem"] > 500]

    def _monitor_loop(self, interval):
        while self.running:
            self.get_processes_snapshot()
            time.sleep(interval)

    def start_monitoring(self, interval=2):
        self.running = True
        t = threading.Thread(target=self._monitor_loop, args=(interval,), daemon=True)
        t.start()

    def stop_monitoring(self):
        self.running = False

    def compute_hash(self, file_path):
        """Safely compute SHA-256 with a 100MB size limit."""
        try:
            if not file_path or not os.path.exists(file_path): return None
            if os.path.getsize(file_path) > 100 * 1024 * 1024: return "TOO_LARGE"

            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return None

    def check_suspicious_with_vt(self, vt_checker):
        """Heavy lifting: Hash and Check VT. Designed to run in background thread."""
        # Work on a copy to avoid locking the UI for too long
        with self.lock:
            to_check = list(self.suspicious_processes)

        for proc in to_check:
            pid = proc["PID"]
            if pid in self.reported_pids: continue

            file_hash = self.compute_hash(proc["Path"])
            if file_hash and file_hash != "TOO_LARGE":
                result = vt_checker.check_file_hash(file_hash)
                if result and result["detections"] > 3:
                    with self.lock:
                        self.threats.append({**proc, "detections": result["detections"]})

            self.reported_pids.add(pid)