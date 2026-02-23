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
        self.process_cache = {}
        self.threats = []
        self.running = False
        self.lock = threading.Lock()
        self.reported_pids = set()
        self.action_history = []
        self.quarantine_folder = "C:\\Quarantine"
        self.protected_pids = {0,4}
        self.protected_names = {
            "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
            "lsass.exe", "winlogon.exe", "svchost.exe", "explorer.exe",
            "dwm.exe", "runtimebroker.exe", "searchhost.exe", "taskmgr.exe",
            "conhost.exe", "fontdrvhost.exe", "shellexperiencehost.exe"
        }
        self.vm_infra = {"vmware.exe", "vmware-vmx.exe", "vmnat.exe", "vmware-authd.exe"}
        if not os.path.exists(self.quarantine_folder): os.mkdir(self.quarantine_folder)
    def is_protected(self, pid, name, path):
        """Tiered trust model"""
        name_l = name.lower()
        path_l = path.lower() if path else ""

        if pid in self.protected_pids or pid == os.getpid():
            return True

        if name_l in self.protected_names or name_l in self.vm_infra:
            return True
        if "c:\\windows" in path_l or "c:\\program files" in path_l:
            return True
        return False

    def apply_policy(self, proc_data, detection_count):
        pid = proc_data["PID"]
        path = proc_data["Path"]
        name = proc_data["Name"]
        history_entry = {
            "PID": proc_data["PID"],
            "Name": proc_data["Name"],
            "Action": "KILLED AND QUARANTINED",
            "Time": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        try:
            if not psutil.pid_exists(pid):
                return "NEUTRALIZED"
            process = psutil.Process(pid)
            if name.lower() == "virus.exe":
                self.action_history.append(history_entry)
                if process.is_running():
                    process.suspend()
                time.sleep(0.1)
                self.create_dump(pid)
                process.terminate()
                time.sleep(0.1)
                self.quarantine_file(path)

                return "Killed & Quarantined (Name Match)"

            if detection_count > 3:
                self.action_history.append(history_entry)
                process.suspend()
                # trigger mem dump
                self.create_dump(pid)
                process.terminate()
                time.sleep(0.1)
                self.quarantine_file(path)
                return f"Suspended & Quarantined (High Detection Rate) {detection_count} Detections"

            if proc_data["Mem"] > 500:
                return "Warning: High Memory Usage"
            if proc_data["CPU"] > 80:

                return "Warning: High CPU Usage"
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
        """Standard scan of all system processes with accurate CPU tracking."""
        temp = []
        active_pids = set()

        # We iterate over PIDs to manage our cache
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                active_pids.add(pid)

                # Retrieve the cached object or create a new one if it's new
                if pid not in self.process_cache:
                    # We create the object once and store it
                    self.process_cache[pid] = proc

                p = self.process_cache[pid]


                # IMPORTANT: Get stats from the persistent object
                # interval=None makes this non-blocking (required for UI performance)
                cpu = p.cpu_percent(interval=None)
                mem_info = p.memory_info()
                mem = mem_info.rss / (1024 * 1024)

                # Note: proc.exe() is slow/heavy, only call it if necessary or once
                try:
                    path = p.exe()
                except:
                    path = "N/A"

                temp.append({
                    "PID": pid,
                    "Name": proc.info['name'],
                    "Mem": mem,
                    "CPU": cpu,
                    "Path": path
                })

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Clean up the cache so we don't leak memory for closed processes
        self.process_cache = {pid: p for pid, p in self.process_cache.items() if pid in active_pids}

        with self.lock:
            self.processes = temp
            # This will now catch the 80% spikes correctly!
            self.suspicious_processes = [
                p for p in temp
                if p["Mem"] > 500 or p["CPU"] > 80 or p["Name"].lower() == "virus.exe"
            ]

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
            path = proc["Path"]
            if pid in self.reported_pids: continue

            file_hash = self.compute_hash(proc["Path"])
            if file_hash and file_hash != "TOO_LARGE":
                result = vt_checker.check_file_hash(file_hash, file_path=path)
                if result and result["detections"] > 3:
                    with self.lock:
                        self.threats.append({**proc, "detections": result["detections"]})

            self.reported_pids.add(pid)