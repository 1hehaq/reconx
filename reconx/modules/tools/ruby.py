from .base import ToolInstaller

class RubyToolInstaller(ToolInstaller):
    def __init__(self):
        super().__init__()
        self.language_cmd = "ruby"
        self.install_cmd = "gem install" 