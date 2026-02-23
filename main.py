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
client = vt.Client(API_KEY)
console = Console()


def generate_dashboard(pm):
    table = Table(title="[bold blue]EDR HEURISTIC MONITOR[/bold blue]", box=box.ROUNDED, expand=True)
    table.add_column("Type", width=12)
    table.add_column("PID", width=10, style="cyan")
    table.add_column("Process Name", ratio=1)
    table.add_column("Action / Status", width=35)
    table.add_column("Resource", width=15, justify="right")

    with pm.lock:
        # Display Terminal History (The Kills)
        for entry in pm.action_history[-3:]:
            table.add_row("🛡️ HISTORY", str(entry['PID']), entry['Name'],
                          "[bold white on red] TERMINATED [/bold white on red]", "0.0 MB")

        # Display Suspicious Processes (Live Analysis)
        for p in pm.suspicious_processes:
            # Immediate behavior check
            action = pm.apply_policy(p, 0)
            table.add_row("⚠️ ANOMALY", str(p['PID']), p['Name'],
                          f"[yellow]{action}[/yellow]", f"{p['Mem']:.1f} MB")

    return Panel(table, title="[bold red]CyberDefender Active Protection[/bold red]")


def security_worker(pm, vt_checker):
    while pm.running:
        pm.check_suspicious_with_vt(vt_checker)
        with pm.lock:
            for threat in pm.threats:
                pm.apply_policy(threat, threat.get('detections', 0))
        time.sleep(1)


if __name__ == "__main__":
    pm = processes.Processes()
    vt_c = virus_total_checker.VirusTotalChecker(client)

    pm.start_monitoring(interval=1)

    sec_thread = threading.Thread(target=security_worker, args=(pm, vt_c), daemon=True)
    sec_thread.start()

    try:
        with Live(generate_dashboard(pm), refresh_per_second=2, screen=True) as live:
            while True:
                live.update(generate_dashboard(pm))
                time.sleep(0.5)
    except KeyboardInterrupt:
        pm.stop_monitoring()
        client.close()
        console.print("\n[bold red]EDR System Offline.[/bold red]")