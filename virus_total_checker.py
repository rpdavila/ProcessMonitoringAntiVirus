import vt

class VirusTotalChecker:
    def __init__(self, client):
        self.client = client
        self.cache = {}

    def check_file_hash(self, file_hash):
        if file_hash in self.cache:
            return self.cache[file_hash]

        try:
            file_obj = self.client.get_object(f"/files/{file_hash}")
            stats = file_obj.last_analysis_stats
            result = {"detections": stats.get('malicious', 0)}
            self.cache[file_hash] = result
            return result
        except vt.error.APIError as e:
            if e.code == "NotFoundError":
                self.cache[file_hash] = {"detections": 0}
            return None
        except Exception:
            return None