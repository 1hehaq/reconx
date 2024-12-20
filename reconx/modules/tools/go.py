from .base import ToolInstaller

class GoToolInstaller(ToolInstaller):
    def __init__(self):
        super().__init__()
        self.language_cmd = "go"
        self.install_cmd = "go install" 