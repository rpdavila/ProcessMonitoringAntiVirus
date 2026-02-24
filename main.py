import os
import time
import threading
from dotenv import load_dotenv
import vt
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
from rich import box
import psutil
import processes
import virus_total_checker

load_dotenv()
API_KEY = os.environ.get('API')
console = Console()


def generate_dashboard(pm):
    table = Table(title="[bold blue]EDR HEURISTIC MONITOR[/bold blue]", box=box.ROUNDED, expand=True)
    table.add_column("Type", width=12)
    table.add_column("PID", width=10, style="cyan")
    table.add_column("Process Name", ratio=1)
    table.add_column("Action / Status", width=35)
    table.add_column("Resource", width=15, justify="right")

    with pm.lock:
        # 1. Display History (Killed threats)
        # We use a reversed list so the newest kills are at the top
        for entry in reversed(pm.action_history[-5:]):
            # Get the raw status and clean it for comparison
            raw_status = str(entry.get("VT_Status", "Waiting...")).upper()

            # Logic to apply colors based on the clean string
            if any(word in raw_status for word in ["QUEUED", "SCANNING", "UPLOADING", "HASHING"]):
                status_display = f"[bold blink yellow]⏳ {raw_status}[/bold blink yellow]"
            elif any(word in raw_status for word in ["MALICIOUS", "THREAT"]):
                status_display = f"[bold red]❌ {raw_status}[/bold red]"
            elif "CLEAN" in raw_status:
                status_display = f"[bold green]✅ {raw_status}[/bold green]"
            else:
                status_display = f"[yellow]🔍 {raw_status}[/yellow]"

            table.add_row(
                "🛡️ HISTORY",
                str(entry['PID']),
                entry['Name'],
                f"[bold white on red] TERMINATED [/bold white on red]",
                status_display
            )


        # 2. Display Suspicious (Live threats being analyzed)
        for p in pm.suspicious_processes:
            # If this process name was just killed, don't show it as an anomaly anymore
            if any(h['Name'] == p['Name'] for h in pm.action_history):
                continue

            table.add_row(
                "⚠️ [bold yellow]ANOMALY[/bold yellow]",
                str(p['PID']),
                p['Name'],
                "[yellow]ANALYZING BEHAVIOR...[/yellow]",
                f"{p['Mem']:.1f} MB"
            )

    return Panel(table, title="[bold red]CyberDefender Active Protection[/bold red]",
                 subtitle="Heuristic Engine: ACTIVE")


def security_worker(pm, vt_checker, api_key):
    """The 'Executioner' thread - Manages kills, uploads, and status polling."""
    import vt
    import time
    import os

    # Initialize the client INSIDE the thread to satisfy Python 3.14/Asyncio requirements
    with vt.Client(api_key, timeout=30) as client:
        vt_checker.client = client

        while pm.running:
            # --- STEP 1: BEHAVIORAL KILL ---
            # Immediately terminate any process identified as suspicious by the monitor
            with pm.lock:
                to_process = list(pm.suspicious_processes)
            for p in to_process:
                pm.apply_policy(p, 0)

            # --- STEP 2: START NEW ANALYSES (The "Leftover" Code Logic) ---
            target_entry = None
            with pm.lock:
                for entry in pm.action_history:
                    # Pick up a file that was just killed but not yet checked in the cloud
                    if entry.get("VT_Status") in [None, "Waiting..."]:
                        target_entry = entry
                        # The "Reservation": Prevents other loop cycles from picking this up
                        entry["VT_Status"] = "INITIALIZING..."
                        break

            if target_entry:
                q_path = os.path.join(pm.quarantine_folder, target_entry["Name"])
                if os.path.exists(q_path):
                    target_entry["VT_Status"] = "HASHING..."
                    current_hash = pm.compute_hash(q_path)

                    if current_hash:
                        target_entry["VT_Status"] = "SCANNING..."
                        try:
                            # Check hash first; if unknown, vt_checker will handle the upload
                            result = vt_checker.check_file_hash(current_hash, q_path)

                            if result:
                                detections = result.get("detections", 0)
                                target_entry["detections"] = detections

                                # Format the status string immediately for the UI
                                if detections > 3:
                                    target_entry["VT_Status"] = f"MALICIOUS ({detections}/70)"
                                    target_entry["Action"] = "CONFIRMED MALICIOUS"
                                elif result.get("status") == "QUEUED/SCANNING":
                                    target_entry["VT_Status"] = "QUEUED/SCANNING"
                                    if "analysis_id" in result:
                                        target_entry["analysis_id"] = result["analysis_id"]
                                else:
                                    target_entry["VT_Status"] = f"CLEAN ({detections}/70)"
                        except Exception as e:
                            target_entry["VT_Status"] = "CONN ERROR"
                            console.print(f"[bold red][DEBUG] VT Error: {e}[/bold red]")
                else:
                    target_entry["VT_Status"] = "FILE MISSING"

            # --- STEP 3: POLLING PENDING ANALYSES ---
            # Every loop, check if any previously "QUEUED" file is now finished
            with pm.lock:
                for entry in pm.action_history:
                    # Look for files still in the scanning phase
                    current_status = str(entry.get("VT_Status", ""))
                    if "SCANNING" in current_status or "QUEUED" in current_status:

                        # ANTI-SPAM: Only poll once every 20 seconds per file
                        last_poll = entry.get("last_poll_time", 0)
                        if time.time() - last_poll < 20:
                            continue

                        entry["last_poll_time"] = time.time()
                        analysis_id = entry.get("analysis_id")

                        if analysis_id:
                            poll_result = vt_checker.check_analysis_status(analysis_id)

                            if poll_result and poll_result["status"] != "SCANNING...":
                                detections = poll_result["detections"]

                                # Update the UI based on the score
                                if detections > 3:
                                    entry["VT_Status"] = f"MALICIOUS ({detections}/70)"
                                    entry["Action"] = "CONFIRMED THREAT"
                                else:
                                    entry["VT_Status"] = f"CLEAN ({detections}/70)"

                                entry["detections"] = detections

            # --- STEP 4: SECONDARY THREAT KILL ---
            # If a scan just finished and found a threat, kill any new copies of it
            with pm.lock:
                for threat in pm.threats:
                    pm.apply_policy(threat, threat.get('detections', 0))

            # Loop delay: 0.5s keeps the UI snappy without burning the CPU
            time.sleep(0.5)


if __name__ == "__main__":
    pm = processes.Processes()
    vt_c = virus_total_checker.VirusTotalChecker(client=None)

    pm.start_monitoring(interval=1)

    sec_thread = threading.Thread(target=security_worker, args=(pm, vt_c, API_KEY), daemon=True)
    sec_thread.start()

    try:
        """Use screen=False if you want to see debug prints in the terminal"""
        with Live(generate_dashboard(pm), refresh_per_second=4, screen=True) as live:
            while True:
                live.update(generate_dashboard(pm))
                time.sleep(0.25)
        # console.print("[bold green]UI Disabled. Watching security_worker logs...[/bold green]")
        # while True:
        #     time.sleep(1)
    except KeyboardInterrupt:
        pm.stop_monitoring()
        console.print("\n[bold red]EDR System Offline.[/bold red]")