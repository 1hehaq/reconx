from .base import ToolInstaller

class NodeToolInstaller(ToolInstaller):
    def __init__(self):
        super().__init__()
        self.language_cmd = "node"
        self.install_cmd = "npm install -g" 