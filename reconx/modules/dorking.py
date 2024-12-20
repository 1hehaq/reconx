from googlesearch import search
from github import Github
import time
import threading
import queue

class DorkScanner:
    def __init__(self, status_queue=None):
        self.status_queue = status_queue
        self.is_scanning = False

    def google_dork(self, query):
        """Execute Google dorking with advanced filters"""
        try:
            self.is_scanning = True
            self._update_status('message', 'Starting Google dork scan...')
            
            dork_patterns = [
                f'site:{query}',
                f'site:{query} inurl:admin',
                f'site:{query} filetype:pdf',
                f'site:{query} intitle:"index of"',
                f'site:{query} intext:password',
                f'site:{query} ext:php intext:mysql_connect',
                f'site:{query} inurl:wp-content',
                f'site:{query} ext:log',
                f'site:{query} inurl:config'
            ]

            results = []
            total_patterns = len(dork_patterns)
            
            for idx, pattern in enumerate(dork_patterns):
                if not self.is_scanning:
                    break

                progress = (idx + 1) / total_patterns
                self._update_status('progress', progress)
                self._update_status('message', f'Processing dork pattern {idx + 1}/{total_patterns}')

                try:
                    search_results = search(
                        pattern,
                        num_results=10,
                        lang="en",
                        advanced=True,
                        sleep_interval=5
                    )

                    for result in search_results:
                        if self.is_scanning:
                            results.append((
                                result.title,
                                result.url,
                                result.description
                            ))
                        time.sleep(2)

                except Exception as e:
                    print(f"Error with pattern {pattern}: {str(e)}")
                    continue

            self._update_status('complete', None)
            return results

        except Exception as e:
            self._update_status('error', str(e))
            raise e

    def github_dork(self, query, api_key):
        """Execute GitHub dorking with authentication"""
        try:
            self.is_scanning = True
            self._update_status('message', 'Starting GitHub dork scan...')

            g = Github(api_key)
            results = []

            dork_patterns = [
                f'"{query}" password',
                f'"{query}" secret',
                f'"{query}" api_key',
                f'"{query}" access_key',
                f'"{query}" config',
                f'"{query}" credentials',
                f'"{query}" token',
                f'org:{query}',
                f'user:{query}'
            ]

            total_patterns = len(dork_patterns)
            for idx, pattern in enumerate(dork_patterns):
                if not self.is_scanning:
                    break

                progress = (idx + 1) / total_patterns
                self._update_status('progress', progress)
                self._update_status('message', f'Processing GitHub dork pattern {idx + 1}/{total_patterns}')

                try:
                    search_results = g.search_code(
                        query=pattern,
                        sort='indexed',
                        order='desc'
                    )

                    for result in search_results[:10]:
                        if not self.is_scanning:
                            break

                        repo = result.repository
                        results.append((
                            f"{repo.full_name}/{result.path}",
                            result.html_url,
                            result.repository.description or "No description"
                        ))

                        time.sleep(2)

                except Exception as e:
                    print(f"Error with GitHub pattern {pattern}: {str(e)}")
                    continue

            self._update_status('complete', None)
            return results

        except Exception as e:
            self._update_status('error', str(e))
            raise e

    def stop(self):
        """Stop the scanning process"""
        self.is_scanning = False

    def _update_status(self, status_type, value):
        """Update status through queue"""
        if self.status_queue:
            if status_type == 'progress':
                self.status_queue.put({'type': 'progress', 'value': value})
            elif status_type == 'message':
                self.status_queue.put({'type': 'message', 'text': value})
            elif status_type == 'complete':
                self.status_queue.put({'type': 'complete'})
            elif status_type == 'error':
                self.status_queue.put({'type': 'message', 'text': f'Error: {value}'}) 