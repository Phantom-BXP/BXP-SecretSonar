from cryptography.fernet import Fernet
import os, json

KEY_FILE = ".secret_key"

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    return key

def load_key():
    if not os.path.exists(KEY_FILE):
        return generate_key()
    with open(KEY_FILE, 'rb') as f:
        return f.read()

def encrypt_file(filepath):
    key = load_key()
    fernet = Fernet(key)
    with open(filepath, 'r') as f:
        data = json.load(f)
    encrypted = fernet.encrypt(json.dumps(data).encode())
    with open(filepath + '.enc', 'wb') as f:
        f.write(encrypted)
    print(f"✅ Clés chiffrées dans {filepath}.enc")

def decrypt_file(filepath):
    key = load_key()
    fernet = Fernet(key)
    with open(filepath, 'rb') as f:
        encrypted = f.read()
    decrypted = fernet.decrypt(encrypted).decode()
    return json.loads(decrypted)
