import subprocess
from bxp_secretsonar.plugins.plugin_loader import PayloadPlugin
from bxp_secretsonar.core.models_v2 import PluginMeta, PluginType

class SystemCommand(PayloadPlugin):
    meta = PluginMeta(
        name="system_command",
        description="Execute arbitrary system command",
        plugin_type=PluginType.PAYLOAD
    )
    def run(self, command, options=None):
        try:
            out = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=10)
            return {"output": out.decode().strip()}
        except Exception as e:
            return {"output": str(e)}
