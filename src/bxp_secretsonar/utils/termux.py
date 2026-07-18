"""Utilitaires pour l'environnement Termux."""
import os, subprocess

def is_termux():
    return "TERMUX_VERSION" in os.environ

def get_termux_prefix():
    return os.environ.get("PREFIX", "/data/data/com.termux/files/usr")

def has_command(cmd):
    return subprocess.call(["which", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def get_available_shell():
    """Retourne le shell disponible (bash, sh, zsh)."""
    if is_termux():
        # Termux a bash par défaut
        return "bash"
    if os.path.exists("/bin/bash"):
        return "/bin/bash"
    return "/bin/sh"
