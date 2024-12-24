import os
from datetime import datetime

class SaveResults:
    def __init__(self, save_results_var, entry, shodan_tree, subdomain_tree, ports_tree, asn_tree, headers_tree, javascript_tree, links_tree, whois_tree):
        self.save_results_var = save_results_var
        self.entry = entry
        self.shodan_tree = shodan_tree
        self.subdomain_tree = subdomain_tree
        self.ports_tree = ports_tree
        self.asn_tree = asn_tree
        self.headers_tree = headers_tree
        self.javascript_tree = javascript_tree
        self.links_tree = links_tree
        self.whois_tree = whois_tree

    def save_scan_results(self, scan_type, results):
        """Save scan results to a file if checkbox is checked"""
        if not self.save_results_var.get():
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = self.entry.get().replace("https://", "").replace("http://", "").replace("/", "_")
        filename = f"results/{domain}_{scan_type}_{timestamp}.txt"

        # Create results directory if it doesn't exist
        os.makedirs("results", exist_ok=True)

        try:
            with open(filename, "w") as f:
                if scan_type == "shodan":
                    for result in results:
                        f.write(f"IP: {result.get('ip', 'N/A')}\n")
                        f.write(f"Organization: {result.get('org', 'N/A')}\n")
                        f.write(f"Ports: {result.get('ports', 'N/A')}\n")
                        f.write(f"Hostnames: {result.get('hostnames', 'N/A')}\n")
                        f.write(f"OS: {result.get('os', 'N/A')}\n")
                        f.write(f"Vulnerabilities: {result.get('vulns', 'N/A')}\n")
                        f.write("-" * 50 + "\n")

                elif scan_type == "subdomains":
                    for result in results:
                        f.write(f"Domain: {result.get('domain', 'N/A')}, ")
                        f.write(f"Status: {result.get('status', 'N/A')}, ")
                        f.write(f"IP: {result.get('ip', 'N/A')}, ")
                        f.write(f"Server: {result.get('server', 'N/A')}\n")

                elif scan_type == "ports":
                    for result in results:
                        f.write(f"Open Port: {result.get('port', 'N/A')}\n")

                elif scan_type == "asn":
                    for result in results:
                        f.write(f"{result.get('asn', 'N/A')}: {result.get('organization', 'N/A')}\n")

                elif scan_type == "headers":
                    for result in results:
                        f.write(f"{result.get('header_name', 'N/A')}: {result.get('header_value', 'N/A')}\n")

                elif scan_type == "javascript":
                    for result in results:
                        f.write(f"File: {result.get('file', 'N/A')}, Status: {result.get('status', 'N/A')}\n")

                elif scan_type == "links":
                    for result in results:
                        f.write(f"{result.get('link', 'N/A')}\n")

                elif scan_type == "whois":
                    for result in results:
                        f.write(f"{result.get('field', 'N/A')}: {result.get('value', 'N/A')}\n")

                else:
                    f.write("Unknown scan type.\n")

            print(f"Results saved to {filename}")

        except Exception as e:
            print(f"Error saving results: {e}")