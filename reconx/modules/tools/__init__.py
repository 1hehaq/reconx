from .base import ToolInstaller
from .go import GoToolInstaller
from .python import PythonToolInstaller
from .ruby import RubyToolInstaller
from .node import NodeToolInstaller

# Define required tools with their installation stesp
REQUIRED_TOOLS = {
    'subfinder': {
        'language': 'go',
        'package': 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
        'check_command': 'subfinder -version',
        'description': 'Subdomain enumeration tool'
    },
    'assetfinder': {
        'language': 'go',
        'package': 'github.com/tomnomnom/assetfinder@latest',
        'check_command': 'assetfinder -version',
        'description': 'Find domains and subdomains (same like subfinder)'
    },
    'httpx': {
        'language': 'go',
        'package': 'github.com/projectdiscovery/httpx/cmd/httpx@latest',
        'check_command': 'httpx -version',
        'description': 'HTTP prober tool'
    }
}

def get_installer(language):
    installers = {
        'go': GoToolInstaller,
        'python': PythonToolInstaller,
        'ruby': RubyToolInstaller,
        'node': NodeToolInstaller
    }
    return installers.get(language)

def check_and_install_tools():
    results = []
    for tool_name, tool_info in REQUIRED_TOOLS.items():
        installer_class = get_installer(tool_info['language'])
        if installer_class:
            installer = installer_class()
            status = installer.check_and_install(
                tool_name,
                tool_info['package'],
                tool_info['check_command']
            )
            results.append({
                'tool': tool_name,
                'status': status,
                'description': tool_info['description']
            })
    return results 