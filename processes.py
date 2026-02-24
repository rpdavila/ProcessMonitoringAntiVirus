import shutil
import psutil
import threading
import time
import hashlib
import os
import subprocess


class Processes:
    def __init__(self):
        self.processes = []
        self.suspicious_processes = []
        self.process_cache = {}
        self.threats = []
        self.running = False
        self.lock = threading.Lock()
        self.reported_pids = set()
        self.action_history = []
        self.quarantine_folder = "C:\\Quarantine"

        # SYSTEM PROTECTION (Lab Safety)
        self.protected_pids = {0, 4}
        self.protected_names = {
            "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
            "lsass.exe", "winlogon.exe", "svchost.exe", "explorer.exe",
            "dwm.exe", "runtimebroker.exe", "searchhost.exe", "taskmgr.exe",
            "memcompression", "system", "registry"  # <--- Added these
        }
        self.vm_infra = {"vmware.exe", "vmware-vmx.exe", "vmnat.exe", "vmware-authd.exe"}

        if not os.path.exists(self.quarantine_folder):
            os.makedirs(self.quarantine_folder)

    def is_protected(self, pid, name, path):
        name_l = name.lower()
        path_l = path.lower() if path else ""
        if pid in self.protected_pids or pid == os.getpid():
            return True
        if name_l in self.protected_names or name_l in self.vm_infra:
            return True
        # Allow behavioral scan on user apps, but skip core Windows files
        if ("c:\\windows" in path_l or "c:\\program files" in path_l) and name_l != "virus.exe":
            return True
        return False

    def apply_policy(self, proc_data, detection_count):
        pid = proc_data["PID"]
        name = proc_data["Name"]
        path = proc_data["Path"]

        try:
            if not psutil.pid_exists(pid): return "NEUTRALIZED"

            is_malicious = (detection_count > 3)
            # Behavioral check: trigger if NOT protected and over limits
            is_anomaly = (proc_data["Mem"] > 500 or proc_data["CPU"] > 80) and not self.is_protected(pid, name, path)

            if is_malicious or is_anomaly:
                reason = "Cloud Intelligence" if is_malicious else "Resource Anomaly"

                # 1. Log to history FIRST so the UI updates immediately
                with self.lock:
                    if not any(h['PID'] == pid for h in self.action_history):
                        self.action_history.append({
                            "PID": pid,
                            "Name": name,
                            "Action": "QUARANTINED",
                            "Reason": reason,  # Match what Main.py expects
                            "Time": time.strftime("%H:%M:%S")
                        })

                # 2. Kill and Quarantine
                subprocess.run(["taskkill", "/F", "/T", "/IM", name], capture_output=True)
                self.quarantine_file(path)
                return "KILL_SUCCESS"

            if proc_data["Mem"] > 400: return "WARN: High RAM"
            if proc_data["CPU"] > 60: return "WARN: High CPU"

        except Exception as e:
            return f"Policy Error: {e}"
        return "ANALYZING BEHAVIOR"

    def get_processes_snapshot(self):
        temp = []
        active_pids = set()

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                active_pids.add(pid)

                # Maintain persistent process objects for accurate CPU tracking
                p = self.process_cache.setdefault(pid, proc)

                cpu = p.cpu_percent(interval=None) / psutil.cpu_count()
                mem = p.memory_info().rss / (1024 * 1024)

                try:
                    path = p.exe()
                except:
                    path = "N/A"

                p_data = {"PID": pid, "Name": proc.info['name'], "Mem": mem, "CPU": cpu, "Path": path}
                temp.append(p_data)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        self.process_cache = {pid: p for pid, p in self.process_cache.items() if pid in active_pids}

        with self.lock:
            self.processes = temp
            self.suspicious_processes = []
            for p in temp:
                path_l = p["Path"].lower()
                # If it's in a user folder (Desktop/Downloads), we are more aggressive
                is_user_area = "users" in path_l and ("desktop" in path_l or "downloads" in path_l)

                if (p["Mem"] > 100 and is_user_area) or p["Mem"] > 400 or p["CPU"] > 60:
                    if not self.is_protected(p["PID"], p["Name"], p["Path"]):
                        self.suspicious_processes.append(p)

    def quarantine_file(self, file_path):
        try:
            if os.path.exists(file_path):
                dest = os.path.join(self.quarantine_folder, os.path.basename(file_path))
                shutil.copy2(file_path, dest)
        except:
            pass

    def start_monitoring(self, interval=1):
        self.running = True
        threading.Thread(target=self._monitor_loop, args=(interval,), daemon=True).start()

    def _monitor_loop(self, interval):
        while self.running:
            self.get_processes_snapshot()
            time.sleep(interval)

    def stop_monitoring(self):
        self.running = False

    def compute_hash(self, file_path):
        try:
            if not file_path or not os.path.exists(file_path): return None
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (PermissionError, OSError):
            return None

    def check_suspicious_with_vt(self, vt_checker):
        with self.lock:
            to_check = list(self.suspicious_processes)

        for proc in to_check:
            if proc["PID"] in self.reported_pids: continue
            file_hash = self.compute_hash(proc["Path"])
            if file_hash:
                res = vt_checker.check_file_hash(file_hash, proc["Path"])
                if res and res.get("detections", 0) > 3:
                    with self.lock:
                        self.threats.append({**proc, "detections": res["detections"]})
            self.reported_pids.add(proc["PID"])
