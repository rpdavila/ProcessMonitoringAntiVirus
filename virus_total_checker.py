import vt
import os

class VirusTotalChecker:
    def __init__(self, client):
        self.client = client
        self.cache = {}

    def check_file_hash(self, file_hash, file_path=None):
        # Don't waste API calls on empty hashes
        if not file_hash:
            return None
        if file_hash in self.cache:
            return self.cache[file_hash]

        try:
            # VirusTotal API call
            file_obj = self.client.get_object(f"/files/{file_hash}")
            stats = file_obj.last_analysis_stats
            result = {"detections": stats.get('malicious', 0)}
            self.cache[file_hash] = result
            return result
        except vt.error.APIError as e:
            # If the file hasn't been seen by VT before
            if e.code == "NotFoundError" and file_path:
                return self.upload_and_scan(file_path, file_hash)
            return None
        except Exception:
            return None

    def upload_and_scan(self, file_path, file_hash):
        if not os.path.exists(file_path):
            return {"Detections": 0, "Status": "File not found"}
        try:
            with open(file_path, "rb") as f:
                analysis = self.client.scan_file(f)
                result = {
                    "Detections":0,
                    "Status": "QUEUED FOR ANALYSIS",
                    "analysis_id": analysis.id
                }
                self.cache[file_hash] = result
                return result
        except Exception:
            return {"Detections": 0, "Status": "Error uploading file"}

