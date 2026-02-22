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


# Increase the priority of your defender
p = psutil.Process(os.getpid())
# 'high_priority_class' ensures the OS handles this process before 'normal' ones
p.nice(psutil.HIGH_PRIORITY_CLASS)
print("EDR Priority set to HIGH")

load_dotenv()
API_KEY = os.environ.get('API')
client = vt.Client(API_KEY)
console = Console()


def generate_dashboard(pm):
    # Use box.ROUNDED for better alignment across different terminal fonts
    table = Table(
        title="[bold blue]CyberDefender Live Monitor[/bold blue]",
        title_justify="left",
        box=box.ROUNDED
    )

    # We set fixed ratios or widths to keep everything perfectly vertical
    table.add_column("Type", width=10, style="bold")
    table.add_column("PID", width=8, style="cyan")
    table.add_column("Process Name", ratio=1, style="white")  # Ratio 1 takes remaining space
    table.add_column("Security Action", width=30, style="blue")
    table.add_column("Memory", width=12, justify="right", style="green")

    with pm.lock:

        for entry in pm.action_history:
            table.add_row(
                "History",
                str(entry['PID']),
                entry['Name'],
                f"[bold white on green] {entry["Action"]} at {entry['Time']}[/bold white on green]",
                "0.0 MB"
            )

        # Threats first
        for threat in pm.threats:
            import psutil
            is_active = psutil.pid_exists(threat['PID'])
            if is_active:
                status_text = "[bold white on red]ACTIVE THREAT[/bold white on red]"

            else:
                status_text = "[bold white on green]THREAT NEUTRALIZED[/bold white on green]"
            table.add_row(
                "THREAT",
                str(threat['PID']),
                threat['Name'],
                status_text,
                "[bold white on red]MALICIOUS[/bold white on red]",
                f"{threat['Mem']:.1f} MB"
            )
            time.sleep(5)

        # Show High Memory Warnings
        threat_pids = [t['PID'] for t in pm.threats]
        for p in pm.suspicious_processes:
            if p['PID'] not in threat_pids:
                status = pm.apply_policy(p, 0)
                table.add_row(
                    "[bold yellow]WARN[/bold yellow]",
                    str(p['PID']),
                    p['Name'],
                    f"[yellow]{status}[/yellow]",
                    f"{p['Mem']:.1f} MB"
                )

    return table

def security_worker(pm, vt_checker):
    """Background loop for VirusTotal checks."""
    while pm.running:
        pm.check_suspicious_with_vt(vt_checker)

        with pm.lock:
            for threat in pm.threats:
                # This is the line that actually kills/quarantines virus.exe or VT threats
                result = pm.apply_policy(threat, threat.get('detections', 0))
                # Optional: Log the result to console so you see it in the background
                print(f"Action on {threat['Name']}: {result}")
        time.sleep(0.5)

if __name__ == "__main__":
    pm = processes.Processes()
    vt_c = virus_total_checker.VirusTotalChecker(client)

    # 1. Start the background monitoring thread
    pm.start_monitoring(interval=0)

    # 2. NEW: Manually trigger the first scan in the main thread
    # so the UI isn't "empty" when it launches.
    console.print("[bold yellow]Scanning system for the first time...[/bold yellow]")
    pm.get_processes_snapshot()

    # 3. Start Security thread
    console.print("[bold Blue]Starting Security Worker...[/bold blue]")
    sec_thread = threading.Thread(target=security_worker, args=(pm, vt_c), daemon=True)
    sec_thread.start()

    console.print("[bold green]Data loaded. Launching UI...[/bold green]")
    time.sleep(0.5)

    try:
        # Use auto_refresh=True to let Rich handle the timing
        with Live(generate_dashboard(pm), refresh_per_second=2, screen=False) as live:
            while True:
                live.update(generate_dashboard(pm))
                time.sleep(0.5)
    except KeyboardInterrupt:
        pm.stop_monitoring()
        client.close()
        console.print("\n[bold red]System Deactivated Safely.[/bold red]")