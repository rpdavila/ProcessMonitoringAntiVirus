import vt

class VirusTotalChecker:
    def __init__(self, client):
        self.client = client
        self.cache = {}

    def check_file_hash(self, file_hash, file_path=None):
        # Don't waste API calls on empty hashes
        if not file_hash: return None
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
            if e.code == "NotFoundError":
                return {"detections": 0, "status": "Clean/Unknown"}
            return None
        except Exception:
            return None