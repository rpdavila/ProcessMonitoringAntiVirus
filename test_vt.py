import os
from dotenv import load_dotenv
import vt
from virus_total_checker import VirusTotalChecker

# Load API key
load_dotenv()
api_key = os.environ['API']

# Initialize VT client and checker
client = vt.Client(api_key)
vt_checker = VirusTotalChecker(client)

# Test with EICAR hash (safe test file that triggers AV detection)
eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

print("Testing VirusTotal checker...")
print(f"Checking hash: {eicar_hash}\n")

# First check - should query VT API
print("First check (querying VT API):")
result = vt_checker.check_file_hash(eicar_hash)
print(f"Result: {result}\n")

# Second check - should use cache
print("Second check (from cache):")
result2 = vt_checker.check_file_hash(eicar_hash)
print(f"Cached result: {result2}\n")

# Display cache contents
print(f"Cache size: {len(vt_checker.vt_cache)} entries")

# Clean up
client.close()
print("\nTest complete!")
