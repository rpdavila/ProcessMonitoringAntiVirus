print("CPU stress test - Press Ctrl+C to stop")
while True:
    # Burns CPU cycles for testing
    sum([i ** 2 for i in range(10000)])