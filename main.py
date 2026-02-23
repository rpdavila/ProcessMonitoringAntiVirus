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
        # 1. Display History (Killed threats)
        # We use a reversed list so the newest kills are at the top
        for entry in reversed(pm.action_history[-5:]):
            table.add_row(
                "🛡️ [bold cyan]HISTORY[/bold cyan]",
                str(entry['PID']),
                entry['Name'],
                f"[bold white on red] {entry['Action']} [/bold white on red]",
                f"[dim]{entry['Time']}[/dim]"
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


def security_worker(pm, vt_checker):
    """The 'Executioner' thread."""
    while pm.running:
        # Step 1: Check everything in the suspicious list for behavioral violations
        with pm.lock:
            # Create a local copy to avoid locking issues
            to_process = list(pm.suspicious_processes)

        for p in to_process:
            # We call apply_policy here. This is where the kill actually happens.
            pm.apply_policy(p, 0)

            # Step 2: Check Cloud Intelligence (VirusTotal)
        pm.check_suspicious_with_vt(vt_checker)

        # Step 3: If VT found something, kill it specifically
        with pm.lock:
            for threat in pm.threats:
                pm.apply_policy(threat, threat.get('detections', 0))

        time.sleep(0.5)


if __name__ == "__main__":
    pm = processes.Processes()
    vt_c = virus_total_checker.VirusTotalChecker(client)

    pm.start_monitoring(interval=1)

    sec_thread = threading.Thread(target=security_worker, args=(pm, vt_c), daemon=True)
    sec_thread.start()

    try:
        # Use screen=False if you want to see debug prints in the terminal
        with Live(generate_dashboard(pm), refresh_per_second=4, screen=True) as live:
            while True:
                live.update(generate_dashboard(pm))
                time.sleep(0.25)
    except KeyboardInterrupt:
        pm.stop_monitoring()
        client.close()
        console.print("\n[bold red]EDR System Offline.[/bold red]")