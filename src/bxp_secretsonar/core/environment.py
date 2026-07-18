import os, sys, platform, shutil
from pathlib import Path
from typing import Optional

class EnvironmentProfile:
    def __init__(self):
        self.system = platform.system()  # Linux, Darwin, Windows, Android?
        self.machine = platform.machine()  # x86_64, aarch64, armv7l...
        self.is_android = False
        self.is_termux = False
        self.is_proot = False
        self.is_windows = self.system == "Windows"
        self.is_linux = self.system == "Linux"
        self.is_macos = self.system == "Darwin"
        self._detect_android()
        self._detect_shell()
        self.max_concurrency = 20
        self.ssl_verify = True
        self._adjust_for_env()

    def _detect_android(self):
        if "TERMUX_VERSION" in os.environ:
            self.is_termux = True
            self.is_android = True
        elif "ANDROID_ROOT" in os.environ or Path("/system/build.prop").exists():
            self.is_android = True
        proot_indicators = [
            Path("/etc/proot-release").exists(),
            "PROOT_NO_SECCOMP" in os.environ,
            shutil.which("proot") is not None,
        ]
        if Path("/proc/self/maps").exists():
            try:
                maps = Path("/proc/self/maps").read_text()
                proot_indicators.append("libproot" in maps)
            except Exception:
                pass
        self.is_proot = any(proot_indicators)

    def _detect_shell(self):
        if self.is_windows:
            # On Windows, prefer PowerShell, fallback to cmd
            if shutil.which("powershell.exe") or shutil.which("pwsh"):
                self.default_shell = "powershell"
            else:
                self.default_shell = "cmd"
        else:
            # Unix-like
            if Path("/bin/bash").exists():
                self.default_shell = "/bin/bash"
            else:
                self.default_shell = "/bin/sh"

    def _adjust_for_env(self):
        if self.is_android:
            self.max_concurrency = 10
            self.ssl_verify = False
        if self.machine.startswith("arm") or self.machine.startswith("aarch64"):
            self.max_concurrency = min(self.max_concurrency, 15)  # léger ralentissement

    def summary(self) -> dict:
        return {
            "system": self.system,
            "machine": self.machine,
            "android": self.is_android,
            "termux": self.is_termux,
            "proot": self.is_proot,
            "windows": self.is_windows,
            "linux": self.is_linux,
            "macos": self.is_macos,
            "shell": self.default_shell,
            "concurrency": self.max_concurrency,
            "ssl_verify": self.ssl_verify,
        }
