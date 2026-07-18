import shutil, subprocess
from typing import Optional, Dict, Any

class FallbackProvider:
    @staticmethod
    def ssh_exec(target, credentials, command) -> Optional[Dict[str, Any]]:
        """Fallback SSH via commande système (sshpass + ssh) si paramiko indisponible."""
        if not shutil.which("ssh"):
            return None
        user = credentials.get("username", "root")
        password = credentials.get("password", "")
        host = target.split(":")[0]
        port = target.split(":")[1] if ":" in target else "22"
        if password:
            sshpass = shutil.which("sshpass")
            if not sshpass:
                return None  # pas de sshpass
            cmd = [sshpass, "-p", password, "ssh", "-o", "StrictHostKeyChecking=no", "-p", port, f"{user}@{host}", command]
        else:
            key_file = credentials.get("private_key")
            if key_file:
                cmd = ["ssh", "-i", key_file, "-o", "StrictHostKeyChecking=no", "-p", port, f"{user}@{host}", command]
            else:
                return None
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return {"success": res.returncode == 0, "output": res.stdout, "error": res.stderr}
        except Exception as e:
            return {"success": False, "output": str(e)}

    @staticmethod
    def smb_exec(target, credentials, command) -> Optional[Dict[str, Any]]:
        """Fallback SMB via smbclient natif (si installé)."""
        if not shutil.which("smbclient"):
            return None
        user = credentials.get("username", "Administrator")
        password = credentials.get("password", "")
        domain = credentials.get("domain", "")
        share = "C$"  # simplifié
        host = target
        # smbclient //host/share -U user%password -c "exec command"
        auth = f"{domain}/{user}%{password}" if domain else f"{user}%{password}"
        cmd = ["smbclient", f"//{host}/{share}", "-U", auth, "-c", command]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return {"success": res.returncode == 0, "output": res.stdout, "error": res.stderr}
        except Exception as e:
            return {"success": False, "output": str(e)}

    @staticmethod
    def http_rce(target, param, payload) -> Optional[Dict[str, Any]]:
        """Fallback HTTP RCE via curl si httpx non disponible."""
        import urllib.request
        import urllib.error
        url = f"{target.rstrip('/')}?{param}={payload}"
        try:
            with urllib.request.urlopen(url, timeout=8) as resp:
                data = resp.read().decode()
                return {"success": True, "output": data[:2000]}
        except Exception as e:
            return {"success": False, "output": str(e)}
