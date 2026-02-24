import vt
import os

class VirusTotalChecker:
    def __init__(self, client):
        self.client = client
        self.cache = {}

    def check_file_hash(self, file_hash, file_path=None):
        if not self.client:
            return {'status': "CLIENT ERROR", "detections": 0}
        if not file_hash:
            return None
        if file_hash in self.cache:
            return self.cache[file_hash]

        try:
            # Step 1: Check Hash
            file_obj = self.client.get_object(f"/files/{file_hash}")
            stats = file_obj.last_analysis_stats
            result = {"detections": stats.get('malicious', 0), "status": "COMPLETE"}
            self.cache[file_hash] = result
            return result
        except vt.error.APIError as e:
            if e.code == "NotFoundError" and file_path:
                # Step 2: If unknown, start the upload process
                return self.upload_and_scan(file_path, file_hash)
            return {"detections": 0, "status": f"API ERROR: {e.code}"}

    def upload_and_scan(self, file_path, file_hash):
        try:
            with open(file_path, "rb") as f:
                # We add a small timeout to the client in Main.py configuration
                # so this doesn't hang forever.
                analysis = self.client.scan_file(f)

                result = {
                    "detections": 0,
                    "status": "QUEUED/SCANNING",
                    "analysis_id": analysis.id  # Store this to check later
                }
                self.cache[file_hash] = result
                return result
        except Exception as e:
            return {"detections": 0, "status": "UPLOAD FAILED"}

    def check_analysis_status(self, analysis_id):
        """Check status of pending scan"""
        if not self.client:
            return None
        try:
            analysis = self.client.get_object(f"/analysis/{analysis_id}")
            if analysis.status == "Completed":
                stats = analysis.stats
                detections = stats.get('malicious', 0)
                return {"detections": detections, "status": "Malicious" if detections > 3 else "Clean"}
            return {"detections": 0, "status": "Scanning"}
        except Exception:
            return None

