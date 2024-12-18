# ReconX

<p align="center">
  <img src="icons/logo.png" alt="ReconX Logo" width="200"/>
</p>

ReconX is a powerful reconnaissance tool with a graphical user interface built using Python and CustomTkinter. It provides various features for gathering information about domains, including subdomain enumeration, port scanning, ASN lookup, and more.

## Features

- 🔍 **Subdomain Enumeration**: Discover subdomains associated with the target domain
- 🚪 **Port Scanning**: Scan for open ports and identify running services
- 🌐 **ASN Information**: Retrieve Autonomous System Number details
- 📋 **Header Analysis**: Examine HTTP headers of the target
- 🔗 **Link Discovery**: Extract all links from the target website
- 📜 **JavaScript Files**: Identify and analyze JavaScript files
- ℹ️ **WHOIS Lookup**: Get domain registration information
- 💾 **Save Results**: Option to save scan results to files
- 🔄 **Auto Updates**: Built-in update mechanism
- 🌐 **Proxy Support**: Configure custom proxy settings
- 🎯 **Custom User-Agent**: Set custom User-Agent strings

## Installation

### Prerequisites

- Python 3.x
- Git
- Subfinder (for subdomain enumeration)

### Setup

1. Clone the repository:

git clone https://github.com/c0d3ninja/reconx.git

2. Install required Python packages:

pip install -r requirements.txt

3. Install Subfinder:

go install -v github.com/projectdiscovery/subfinder/v2@latest

4. Run the script:

python reconx.py

## Usage

2. Enter a domain name in the input field

3. Select the desired scan type from the dropdown menu:
   - Headers
   - Port Scan
   - ASN
   - Subdomains
   - Links
   - JavaScript
   - Whois

4. Click the start button to begin scanning

### Configuration

#### Scan Settings
- **Max Threads**: Configure the number of concurrent threads
- **Port Range**: Set custom port ranges for scanning
- **Proxy**: Add custom proxy settings
- **User-Agent**: Set custom User-Agent string
- **Save Results**: Toggle automatic saving of scan results

## Screenshots

[Add screenshots of your application here]

## Features in Detail

### Subdomain Enumeration
- Uses Subfinder for efficient subdomain discovery
- Validates subdomains and checks their status
- Displays IP addresses and server information

### Port Scanning
- Concurrent port scanning for faster results
- Service identification for open ports
- Customizable port ranges

### ASN Information
- Retrieves detailed ASN information
- Shows organization details
- Displays network ranges

### Header Analysis
- Examines HTTP response headers
- Security header checking
- Server information discovery

### JavaScript Analysis
- Discovers JavaScript files
- Checks file accessibility
- Shows response status codes

### Link Discovery
- Extracts all links from the target website
- Validates link accessibility
- Shows relative and absolute paths

### WHOIS Information
- Detailed domain registration info
- Expiration dates
- Registrar information

## Saving Results

Results can be automatically saved in the `results` directory with the following format:

results/domain_scantype_timestamp.txt

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[Add your license information here]

## Acknowledgments

- CustomTkinter for the modern UI components
- Subfinder for subdomain enumeration capabilities
- All other open-source tools and libraries used in this project

## Author

ReconX by c0d3ninja

## Disclaimer

This tool is for educational purposes only. Ensure you have permission to scan any target domains.