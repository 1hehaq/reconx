import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

class PortScanner:
    def __init__(self, status_queue=None):
        self.status_queue = status_queue
        self.is_scanning = False

    def scan(self, host, start_port=1, end_port=1024):
        try:
            self.is_scanning = True
            self._update_status('message', 'Starting port scan...')
            
            host = socket.gethostbyname(host)
            results = []
            total_ports = end_port - start_port + 1
            scanned = 0

            with ThreadPoolExecutor(max_workers=100) as executor:
                future_to_port = {
                    executor.submit(self._scan_port, host, port): port 
                    for port in range(start_port, end_port + 1)
                }
                
                for future in as_completed(future_to_port):
                    if not self.is_scanning:
                        break
                        
                    scanned += 1
                    progress = scanned / total_ports
                    self._update_status('progress', progress)
                    self._update_status('message', f'Scanning port {scanned}/{total_ports}')
                    
                    result = future.result()
                    if result:
                        results.append(result)

            self._update_status('complete', None)
            return results

        except Exception as e:
            self._update_status('error', str(e))
            raise e

    def _scan_port(self, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    return (port, service)
        except:
            pass
        return None

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