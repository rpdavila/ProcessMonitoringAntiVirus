import os
import sys

from dotenv import load_dotenv
import vt
import processes
import virus_total_checker

load_dotenv()
api = os.environ['API']

# Initialize VT client
client = vt.Client(api)

if __name__ == "__main__":
    import time

    proc_monitor = processes.Processes()
    vt_checker = virus_total_checker.VirusTotalChecker(client)

    # Start monitoring in background thread (updates every 2 seconds)
    proc_monitor.start_monitoring(interval=2)

    try:
        while True:
            high_mem_count = proc_monitor.get_high_memory_count()

            # Display status line
            proc_monitor.list_number_of_processes()
            warning = f" | ⚠️  High Mem: {high_mem_count}" if high_mem_count > 0 else ""
            sys.stdout.write(f" | Suspicious: {len(proc_monitor.suspicious_processes)} | Threats: {len(proc_monitor.threats)}{warning}")
            sys.stdout.flush()

            # Display high memory processes (only if changed)
            proc_monitor.display_high_memory_processes()

            if proc_monitor.suspicious_processes:
                proc_monitor.check_suspicious_with_vt(vt_checker)

            time.sleep(3)  # Display every 3 seconds
    except KeyboardInterrupt:
        proc_monitor.stop_monitoring()
        print("\nExiting...")