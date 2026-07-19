#!/usr/bin/env python3
"""Installe les dépendances TLS depuis le dossier vendor/ (mode offline)."""
import platform, sys, os, subprocess, json

VENDOR_DIR = "vendor"
MANIFEST = os.path.join(VENDOR_DIR, "manifest.json")

def get_platform():
    os_name = sys.platform
    if os_name.startswith("linux"):
        os_name = "linux"
    elif os_name.startswith("darwin"):
        os_name = "darwin"
    elif os_name.startswith("win"):
        os_name = "windows"
    else:
        raise RuntimeError(f"OS non supporté : {os_name}")

    arch = platform.machine()
    if arch in ("x86_64", "AMD64"):
        arch = "x86_64"
    elif arch in ("aarch64", "arm64"):
        arch = "aarch64"
    elif arch == "armv7l":
        arch = "armv7l"
    else:
        raise RuntimeError(f"Architecture non supportée : {arch}")

    py_ver = f"cp{sys.version_info.major}{sys.version_info.minor}"
    return os_name, arch, py_ver

def install(package: str):
    if not os.path.exists(MANIFEST):
        print("❌ vendor/manifest.json introuvable. Téléchargez les wheels depuis les releases GitHub.")
        return False

    with open(MANIFEST, "r") as f:
        data = json.load(f)

    os_name, arch, py_ver = get_platform()

    for wheel in data["wheels"]:
        if wheel["package"] == package:
            for target in wheel["targets"]:
                if target["os"] == os_name and target["arch"] == arch and target["python"] == py_ver:
                    wheel_path = os.path.join(VENDOR_DIR, target["file"])
                    if os.path.exists(wheel_path):
                        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", wheel_path])
                        return True
                    else:
                        print(f"❌ Wheel introuvable : {wheel_path}")
                        return False
            print(f"❌ Aucun wheel trouvé pour {package} sur {os_name}/{arch}/{py_ver}")
            return False
    print(f"❌ Package {package} non listé dans le manifeste.")
    return False

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("package", choices=["tls_client", "curl_cffi"])
    args = parser.parse_args()
    success = install(args.package)
    if success:
        print(f"✅ {args.package} installé depuis vendor/")
    else:
        print(f"❌ Échec de l'installation de {args.package}")
