import subprocess
import shutil
import os

class ToolInstaller:
    
    def __init__(self):
        self.language_cmd = None
        self.install_cmd = None
    
    # Checking for tools
    def is_installed(self, command):
        try:
            result = subprocess.run(
                command.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return result.returncode == 0
        except:
            return False

    # Checking for the langauges
    def check_language(self):
        return shutil.which(self.language_cmd) is not None

    def install_tool(self, package):
        try:
            subprocess.run(
                f"{self.install_cmd} {package}",
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return True
        except subprocess.CalledProcessError:
            return False

    #Check/Install
    def check_and_install(self, tool_name, package, check_command):
        if not self.check_language():
            return f"ERROR: {self.language_cmd} not installed"
            
        if self.is_installed(check_command):
            return "Already installed"
            
        if self.install_tool(package):
            return "Successfully installed"
        
        return "Installation failed" 