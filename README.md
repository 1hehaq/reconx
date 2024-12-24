<div align="center">
   <a href="https://github.com/gotr00t0day/Reconnaissance/reconx.png"><img src="https://github.com/gotr00t0day/Reconnaissance/blob/main/reconx.png" width="650" height="450" align="center"/></a>
</div>

<br>
<br>
<br>

<div align="center">
   
|ReconX|Multi Reconnaissance Tool|for Information Gathering|
|----------------|--------------|-------------|
| `R`| `=`| `Reconnaissance & Research`|
| `E`| `=`| `Enumeration of Subdomains`|
| `C`| `=`| `Comprehensive Port Scanning`|
| `O`| `=`| `Open Source Intelligence`|
| `N`| `=`| `Network Information Gathering`|
| `X`| `=`| `eXtensive Analysis Tools`|

> **ReconX**! a comprehensive GUI based tool that do: <br><br> **`Subdomain Enumeration` - `Port Scanning` - `ASN Lookup` - `Header Analysis` - `Link Discovery` - `JavaScript Analysis` - `WHOIS Lookup`**. <br><br> *`Made by`* - [`c0d3ninja`](https://github.com/c0d3ninja) x [`1hehaq`](https://github.com/1hehaq)!

</div>

<hr>

<br>
<br>
<br>

<div align="center">
  
| Features                          | About                                                                       |
|-----------------------------------|-----------------------------------------------------------------------------|
| `Subdomain Enumeration`           | Discover and validate subdomains associated with target domain.             |
| `Port Scanning`                   | Identify open ports and running services with concurrent scanning.          |
| `ASN Information`                 | Retrieve detailed Autonomous System Number information.                      |
| `Header Analysis`                 | Examine and analyze HTTP headers of target websites.                        |
| `Link Discovery`                  | Extract and validate all links from target websites.                        |
| `JavaScript Analysis`             | Identify and analyze JavaScript files on target domains.                    |
| `WHOIS Lookup`                    | Retrieve comprehensive domain registration information.                      |
| `Multi-threaded Scanning`         | Improved performance through concurrent operations.                         |
| `Proxy Support`                   | Configure custom proxy settings for scans.                                  |
| `Custom User-Agent`               | Set custom User-Agent strings for requests.                                 |
| `Save Results`                    | Automatically save scan results to organized files.                         |
| `Auto Updates`                    | Built-in mechanism to keep tool updated.                                    |

</div>

<br>
<hr>
<br>
<br>

| Language                          | Packages                                                                    |
|-----------------------------------|-----------------------------------------------------------------------------|
| ***Python***| `Python 3.x` `customtkinter` `requests` `python-whois` `socket` `subprocess` `threading` `datetime` `json` `os` `sys`|

<br>
<hr>
<br>

## `Installation`

#### Prerequisites
<pre>
# Install Python 3.x
# Install Git
# Install Subfinder (for subdomain enumeration)
</pre>

#### Clone the repository
```bash
git clone https://github.com/c0d3ninja/Reconnaissance.git
```
```bash
cd reconx
```

#### Install the requirements
```bash
pip3 install -r requirements.txt
```

#### Run the Application
```bash
python3 main.py
```

----

| Scan Configuration        |                                                                                         |
|---------------------------|-----------------------------------------------------------------------------------------|
| Target Domain             | Enter the domain name to scan in the input field.                                       |
| Scan Type                 | Select from available scan types in the dropdown menu.                                  |
| Thread Settings           | Configure the number of concurrent threads for scanning.                                |
| Proxy Configuration       | Set up custom proxy settings for anonymous scanning.                                    |
| User-Agent Configuration  | Customize User-Agent strings for requests.                                             |

----

| Result Management          |                                                                                         |
|---------------------------|-----------------------------------------------------------------------------------------|
| Save Location             | Results automatically saved in `results` directory.                                      |
| File Format               | Files saved as `domain_scantype_timestamp.txt`                                          |
| Result Display            | Real-time display of scan results in the GUI.                                           |
| Export Options            | Save results in various formats for further analysis.                                   |

----

### Scanning Modules

1. **Subdomain Scanner**
   - Utilizes Subfinder for comprehensive enumeration
   - Validates discovered subdomains
   - Maps subdomains to IP addresses

2. **Port Scanner**
   - Multi-threaded port scanning
   - Service identification
   - Customizable port ranges

3. **ASN Lookup**
   - Organization details
   - Network ranges
   - Registration information

4. **Header Analyzer**
   - Security header checking
   - Server information
   - Response header analysis

5. **Link Discovery**
   - Extracts all website links
   - Validates link accessibility
   - Path analysis

6. **JavaScript Analyzer**
   - Discovers JS files
   - Checks file status
   - Basic content analysis

7. **WHOIS Lookup**
   - Registration details
   - Expiration information
   - Registrar data

<hr>

> [!WARNING]  
> ReconX is intended for educational and legitimate security testing purposes only. Users must ensure they have proper authorization before scanning any domains or systems. Unauthorized scanning may be illegal in your jurisdiction.
