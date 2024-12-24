import shodan
import time
import json
import socket
from typing import Union, Dict, List


def get_api_key(api_key: str) -> shodan.Shodan:
    """Initialize and return Shodan API client"""
    if not api_key:
        raise ValueError("Shodan API key is required")
    return shodan.Shodan(api_key)


def get_ip_from_domain(domain: str) -> str:
    """Convert domain to IP address"""
    try:
        # Remove any protocol prefixes
        domain = domain.replace("https://", "").replace("http://", "").replace("www.", "")
        return socket.gethostbyname(domain)
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve domain {domain}: {e}")

def shodan_scan(domain: str, api_key: str) -> List[Dict[str, str]]:
    """Perform a Shodan search for all hosts related to a domain"""
    try:
        # Initialize API
        if not api_key:
            return [{'ip': domain, 'org': 'Error', 'ports': 'Shodan API key is required'}]
        
        api = shodan.Shodan(api_key)
        
        try:
            # Try direct host lookup first if domain is an IP
            if domain.replace('.', '').isdigit():
                host = api.host(domain)
                ports = []
                for item in host.get('data', []):
                    if 'port' in item:
                        port_info = f"{item['port']}"
                        if 'product' in item:
                            port_info += f" ({item['product']})"
                        ports.append(port_info)
                
                return [{
                    'hostnames': host.get('hostnames', ['n/a'])[0] if host.get('hostnames') else 'n/a',
                    'ip': host.get('ip_str', domain),
                    'org': host.get('org', 'n/a'),
                    'vulns': next(iter(host.get('vulns', [])), 'No known vulnerabilities')
                }]
        except:
            pass  # If direct lookup fails, fall back to search
            
        # Search for the domain
        results = api.search(f'hostname:"{domain}"')
        results_list = []

        for result in results['matches']:
            ports = []
            for item in result.get('data', []):
                if 'port' in item:
                    port_info = f"{item['port']}"
                    if 'product' in item:
                        port_info += f" ({item['product']})"
                    ports.append(port_info)
            
            host_data = {
                'hostnames': result.get('hostnames', ['n/a'])[0] if result.get('hostnames') else 'n/a',
                'ip': result.get('ip_str', 'n/a'),
                'org': result.get('org', 'n/a'),
                # 'ports': ', '.join(ports),
                # 'os': result.get('os', 'n/a'),
                'vulns': next(iter(result.get('vulns', [])), 'No known vulnerabilities')
            }
            results_list.append(host_data)
        
        return results_list if results_list else [{
            'hostnames': domain,
            'ip': 'No Results',
            'org': 'No Shodan data found',
            'vulns': 'n/a'
        }]

    except shodan.APIError as e:
        return [{
            'ip': domain,
            'org': 'Error',
            'ports': f"Shodan API Error: {str(e)}",
            'hostnames': 'n/a',
            'os': 'n/a',
            'vulns': 'n/a'
        }]
    except Exception as e:
        return [{
            'ip': domain,
            'org': 'Error',
            'ports': f"Unexpected Error: {str(e)}",
            'hostnames': 'n/a',
            'os': 'n/a',
            'vulns': 'n/a'
        }]

def host_info(domain: str, api_key: str) -> Dict[str, str]:
    """Get host information from Shodan"""
    try:
        # Initialize API
        api = get_api_key(api_key)
        
        # Convert domain to IP if necessary
        ip = get_ip_from_domain(domain) if not domain.replace('.', '').isdigit() else domain
        
        # Get host information
        host = api.host(ip)
        
        # Extract information
        ports = [str(item['port']) for item in host.get('data', [])]
        org = host.get('org', 'n/a')
        
        return {
            'ip': ip,
            'org': org,
            'ports': ','.join(ports) if ports else 'No open ports found'
        }
    except shodan.APIError as e:
        raise ValueError(f"Shodan API Error: {str(e)}")
    except ValueError as e:
        raise ValueError(f"Domain Resolution Error: {str(e)}")
    except Exception as e:
        raise ValueError(f"Unexpected Error: {str(e)}")

def scan_single_ip(ip: str, api_key: str) -> Dict[str, str]:
    """Scan a single IP address with Shodan and return detailed information"""
    api = get_api_key(api_key)
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
                'vulns': vulns[0] if vulns else 'No known vulnerabilities'
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