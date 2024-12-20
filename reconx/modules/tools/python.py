from .base import ToolInstaller

class PythonToolInstaller(ToolInstaller):
    def __init__(self):
        super().__init__()
        self.language_cmd = "python3"
        self.install_cmd = "pip3 install" 