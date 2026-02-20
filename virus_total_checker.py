import vt
import datetime


class VirusTotalChecker:
    def __init__(self, vt_client):
        self.vt_client = vt_client
        self.vt_cache = {}

    def check_file_hash(self, file_hash):
        """
        Checks the cache first. If not found, queries VT.
        Returns a dictionary with results or None if error.
        """
        # 1. Check local memory cache
        if file_hash in self.vt_cache:
            return self.vt_cache[file_hash]

        # 2. Query VirusTotal
        result = self._query_virustotal(file_hash)

        if result:
            stats = getattr(result, 'last_analysis_stats', {})

            cache_entry = {
                "detections": stats.get('malicious', 0),
                "total_vendors": sum(stats.values()) if stats else 0,
                "checked_at": getattr(result, 'last_analysis_date', datetime.datetime.now())
            }

            self.vt_cache[file_hash] = cache_entry
            return cache_entry

        return None

    def _query_virustotal(self, file_hash):
        """Internal method to handle the API communication"""
        try:
            # Request the file object from VT
            return self.vt_client.get_object(f"/files/{file_hash}")
        except vt.APIError as e:
            # Handle 'Not Found' (404) silently - it just means VT hasn't seen it
            if e.code == 'NotFoundError':
                return None
            # Log other errors (like Rate Limit) without crashing
            print(f"\n[!] VT API Error: {e}")
            return None
        except Exception as e:
            print(f"\n[!] Unexpected Error: {e}")
            return None