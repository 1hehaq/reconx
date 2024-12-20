import requests
import json
import subprocess
import os
import re
import dns.resolver
import socket
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import random

class SubdomainEnumerator:
    def __init__(self, domain, proxy=None, user_agent=None):
        self.domain = domain
        self.proxy = proxy
        
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15"
        ]
        self.user_agent = user_agent or random.choice(self.user_agents)
        
        self.session = requests.Session()
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.session.headers["User-Agent"] = self.user_agent
        self.session.verify = False

    def _make_request(self, url, headers=None):
        try:
            headers = headers or {}
            headers.update({"User-Agent": random.choice(self.user_agents)})
            return self.session.get(url, headers=headers, timeout=10)
        except Exception as e:
            print(f"Error making request to {url}: {e}")
            return None

    def waybackurls(self):
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}&output=json&fl=original&collapse=urlkey"
            r = self._make_request(url)
            if r and r.status_code == 200:
                data = r.json()
                subdomains = set()
                pattern = f"[a-zA-Z0-9-]+\.{self.domain}"
                for entry in data[1:]:
                    matches = re.findall(pattern, entry[0])
                    subdomains.update(matches)
                return subdomains
        except Exception as e:
            print(f"Wayback error: {e}")
        return set()

    def crt_sh(self):
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            r = self._make_request(url)
            if r and r.status_code == 200:
                data = r.json()
                subdomains = set()
                for cert in data:
                    domains = re.split(r'[\n,]', cert['name_value'])
                    for domain in domains:
                        domain = domain.strip()
                        if domain.endswith(self.domain) and '*' not in domain:
                            subdomains.add(domain)
                return subdomains
        except Exception as e:
            print(f"crt.sh error: {e}")
        return set()

    def alienvault(self):
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            r = self._make_request(url)
            if r and r.status_code == 200:
                data = r.json()
                return {entry["hostname"] for entry in data["passive_dns"] if self.domain in entry["hostname"]}
        except Exception as e:
            print(f"AlienVault error: {e}")
        return set()

    def threatcrowd(self):
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            r = self._make_request(url)
            if r and r.status_code == 200:
                data = r.json()
                return set(data.get("subdomains", []))
        except Exception as e:
            print(f"ThreatCrowd error: {e}")
        return set()

    def hackertarget(self):
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            r = self._make_request(url)
            if r and r.status_code == 200:
                return {line.split(',')[0] for line in r.text.splitlines() if line}
        except Exception as e:
            print(f"HackerTarget error: {e}")
        return set()

    def rapiddns(self):
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}"
            r = self._make_request(url)
            if r and r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                table = soup.find('table', {'class': 'table'})
                subdomains = set()
                if table:
                    for row in table.find_all('tr'):
                        cols = row.find_all('td')
                        if cols and len(cols) > 0:
                            subdomain = cols[0].text.strip()
                            if subdomain.endswith(self.domain):
                                subdomains.add(subdomain)
                return subdomains
        except Exception as e:
            print(f"RapidDNS error: {e}")
        return set()

    def dnsdumpster(self):
        try:
            url = "https://dnsdumpster.com/"
            r = self.session.get(url)
            if r.status_code == 200:
                csrf_token = re.findall(r"name='csrfmiddlewaretoken' value='(.*?)'", r.text)[0]
                cookies = r.cookies
                headers = {
                    'Referer': url,
                    'X-CSRFToken': csrf_token
                }
                data = {
                    'csrfmiddlewaretoken': csrf_token,
                    'targetip': self.domain
                }
                r = self.session.post(url, headers=headers, cookies=cookies, data=data)
                if r.status_code == 200:
                    pattern = f"[a-zA-Z0-9-]+\.{self.domain}"
                    return set(re.findall(pattern, r.text))
        except Exception as e:
            print(f"DNSDumpster error: {e}")
        return set()

    def certspotter(self):
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
            r = self._make_request(url)
            if r and r.status_code == 200:
                data = r.json()
                subdomains = set()
                for cert in data:
                    subdomains.update(cert.get('dns_names', []))
                return {s for s in subdomains if s.endswith(self.domain)}
        except Exception as e:
            print(f"CertSpotter error: {e}")
        return set()

    def urlscan(self):
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"
            r = self._make_request(url)
            if r and r.status_code == 200:
                data = r.json()
                subdomains = set()
                pattern = f"[a-zA-Z0-9-]+\.{self.domain}"
                for result in data.get('results', []):
                    page = result.get('page', {})
                    domain = page.get('domain', '')
                    if domain.endswith(self.domain):
                        subdomains.add(domain)
                    url = page.get('url', '')
                    matches = re.findall(pattern, url)
                    subdomains.update(matches)
                return subdomains
        except Exception as e:
            print(f"URLScan error: {e}")
        return set()

    def dns_brute(self, wordlist="subdomains.txt"):
        subdomains = set()
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1
        resolver.lifetime = 1
        
        try:
            if not os.path.exists(wordlist):
                wordlist = os.path.join(os.path.dirname(__file__), "wordlists", "subdomains.txt")
            
            with open(wordlist) as f:
                words = [line.strip() for line in f]
                
            def check_subdomain(word):
                try:
                    subdomain = f"{word}.{self.domain}"
                    resolver.resolve(subdomain, "A")
                    return subdomain
                except:
                    return None
                    
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(check_subdomain, word) for word in words]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        subdomains.add(result)
                        
        except Exception as e:
            print(f"DNS bruteforce error: {e}")
            
        return subdomains

    def enumerate(self, max_threads=10):
        methods = [
            self.waybackurls,
            self.crt_sh,
            self.alienvault,
            self.threatcrowd,
            self.hackertarget,
            self.rapiddns,
            self.dnsdumpster,
            self.certspotter,
            self.urlscan,
            self.dns_brute
        ]

        all_subdomains = set()
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_method = {executor.submit(method): method.__name__ 
                              for method in methods}
            
            for future in as_completed(future_to_method):
                method_name = future_to_method[future]
                try:
                    subdomains = future.result()
                    all_subdomains.update(subdomains)
                    print(f"{method_name}: Found {len(subdomains)} subdomains")
                except Exception as e:
                    print(f"{method_name} failed: {e}")

        return all_subdomains

    def save_results(self, domain, subdomains, output_dir="results"):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(output_dir, f"{domain}_subdomains_{timestamp}.txt")
        
        with open(filename, "w") as f:
            for subdomain in sorted(subdomains):
                f.write(f"{subdomain}\n") 