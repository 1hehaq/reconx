import shodan
import time
import json
import socket
from typing import Union, Dict, List

SHODAN_API_KEY = "iWflkVlY3yo2zM67d0ILuU7qEncsGz4A"
api = shodan.Shodan(SHODAN_API_KEY)

def get_ip_from_domain(domain: str) -> str:
    """Convert domain to IP address"""
    try:
        # Remove any protocol prefixes
        domain = domain.replace("https://", "").replace("http://", "").replace("www.", "")
        return socket.gethostbyname(domain)
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve domain {domain}: {e}")

def shodan_scan(domain: str, page=None, max_retries=3) -> List[str]:
    ips = []
    retry_count = 0
    delay = 1  # Initial delay in seconds

    while retry_count < max_retries:
        try:
            results = api.search(str(domain), page=page)
            for result in results['matches']:
                ips.append(result['ip_str'])
            return ips  # Return the list of IPs
        except shodan.exception.APIError as e:
            if "Search cursor timed out" in str(e) and retry_count < max_retries - 1:
                print(f"Search timed out. Retrying in {delay} seconds...")
                time.sleep(delay)
                retry_count += 1
                delay *= 2  # Exponential backoff
                page = None  # Reset page to start from the beginning
            else:
                raise  # Re-raise the exception if max retries reached or different error

def host_info(domain: str) -> Dict[str, str]:
    """Get host information from Shodan"""
    try:
        # First convert domain to IP if necessary
        ip = get_ip_from_domain(domain) if not domain.replace('.', '').isdigit() else domain
        
        host = api.host(ip)
        ports = []
        org = host.get('org', 'n/a')
        
        for item in host['data']:
            ports.append(item['port'])
        
        return {
            'ip': ip,
            'org': org,
            'ports': ','.join(map(str, ports))
        }
    except shodan.exception.APIError as e:
        print(f"Shodan API Error: {e}")
    except ValueError as e:
        print(f"Domain Resolution Error: {e}")
    except Exception as e:
        print(f"Unexpected Error: {e}")

def scan_single_ip(ip: str) -> Dict[str, str]:
    """Scan a single IP address with Shodan and return detailed information"""
    try:
        host = api.host(ip)
        if host:  # If we got data back
            # Extract basic information
            org = host.get('org', 'n/a')
            hostnames = host.get('hostnames', [])
            os = host.get('os', 'n/a')
            ports = []
            vulns = host.get('vulns', [])
            
            # Get detailed port information
            for item in host.get('data', []):
                if 'port' in item:
                    port_info = f"{item['port']}"
                    if 'product' in item:
                        port_info += f" ({item['product']})"
                    ports.append(port_info)
            
            return {
                'ip': ip,
                'org': org,
                'ports': ', '.join(ports) if ports else 'No open ports found',
                'hostnames': ', '.join(hostnames) if hostnames else 'n/a',
                'os': os,
                'vulns': ', '.join(vulns) if vulns else 'No known vulnerabilities'
            }
        else:  # If no data was returned
            return {
                'ip': ip,
                'org': 'No Data',
                'ports': 'No Shodan data available',
                'hostnames': 'n/a',
                'os': 'n/a',
                'vulns': 'n/a'
            }
            
    except shodan.exception.APIError as e:
        return {
            'ip': ip,
            'org': 'Error',
            'ports': str(e),
            'hostnames': 'n/a',
            'os': 'n/a',
            'vulns': 'n/a'
        }
    except Exception as e:
        return {
            'ip': ip,
            'org': 'Error',
            'ports': f"Unexpected error: {str(e)}",
            'hostnames': 'n/a',
            'os': 'n/a',
            'vulns': 'n/a'
        }