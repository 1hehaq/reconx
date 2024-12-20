import requests

class HeaderScanner:
    def __init__(self, status_queue=None):
        self.status_queue = status_queue
        self.is_scanning = False

    def scan(self, domain, proxy=None, user_agent=None):
        try:
            self.is_scanning = True
            self._update_status('message', 'Starting headers scan...')

            if not domain.startswith(("http://", "https://")):
                domain = f"https://{domain}"

            headers = {}
            if user_agent:
                headers['User-Agent'] = user_agent

            proxies = {}
            if proxy:
                proxies = {
                    'http': proxy,
                    'https': proxy
                }

            response = requests.get(
                domain, 
                headers=headers, 
                proxies=proxies, 
                verify=False,
                timeout=10
            )

            results = []
            total_headers = len(response.headers)
            for idx, (header, value) in enumerate(response.headers.items()):
                if not self.is_scanning:
                    break
                    
                progress = (idx + 1) / total_headers
                self._update_status('progress', progress)
                results.append((header, value))

            self._update_status('complete', None)
            return results

        except Exception as e:
            self._update_status('error', str(e))
            raise e

    def stop(self):
        self.is_scanning = False

    def _update_status(self, status_type, value):
        if self.status_queue:
            if status_type == 'progress':
                self.status_queue.put({'type': 'progress', 'value': value})
            elif status_type == 'message':
                self.status_queue.put({'type': 'message', 'text': value})
            elif status_type == 'complete':
                self.status_queue.put({'type': 'complete'})
            elif status_type == 'error':
                self.status_queue.put({'type': 'message', 'text': f'Error: {value}'}) 