import os
import sys
import hashlib

# ============================================================
#  DEPENDENCY CHECK / INSTALL
# ============================================================
def check_for_needed_tools():
    print("Checking for the needed tools and libs...")
    installing_needed_tools_and_libs()

def installing_needed_tools_and_libs():
    print("Installing the needed tools...")
    for pkg, mod in [
        ("bcrypt", "bcrypt"),
        ("argon2-cffi", "argon2"),
        ("blake3", "blake3"),
        ("cryptography", "cryptography"),
    ]:
        try:
            __import__(mod)
        except ImportError:
            os.system(f"pip install {pkg} --quiet")
    print("All tools ready.")

# ============================================================
#  HASH GENERATORS
# ============================================================
def generate_md5(text):
    print("MD5:", hashlib.md5(text.encode()).hexdigest())

def generate_sha1(text):
    print("SHA1:", hashlib.sha1(text.encode()).hexdigest())

def generate_sha256(text):
    print("SHA256:", hashlib.sha256(text.encode()).hexdigest())

def generate_sha2(text):
    print("SHA224:", hashlib.sha224(text.encode()).hexdigest())
    print("SHA256:", hashlib.sha256(text.encode()).hexdigest())
    print("SHA384:", hashlib.sha384(text.encode()).hexdigest())
    print("SHA512:", hashlib.sha512(text.encode()).hexdigest())

def generate_sha3(text):
    print("SHA3-256:", hashlib.sha3_256(text.encode()).hexdigest())
    print("SHA3-512:", hashlib.sha3_512(text.encode()).hexdigest())

def generate_bcrypt(text):
    import bcrypt
    print("bcrypt:", bcrypt.hashpw(text.encode(), bcrypt.gensalt()).decode())

def generate_argon2(text):
    from argon2 import PasswordHasher
    print("Argon2id:", PasswordHasher().hash(text))

def generate_pbkdf2(text):
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', text.encode(), salt, 100000)
    print("PBKDF2 salt (hex):", salt.hex())
    print("PBKDF2 key  (hex):", key.hex())

def generate_blake3(text):
    import blake3
    print("BLAKE3:", blake3.blake3(text.encode()).hexdigest())

# ============================================================
#  HASH CRACKERS (dictionary attack)
# ============================================================
def identify_hash(h):
    h = h.strip()
    n = len(h)
    if n == 32:
        print("Possible: MD5")
    elif n == 40:
        print("Possible: SHA1")
    elif n == 56:
        print("Possible: SHA224")
    elif n == 64:
        print("Possible: SHA256 / SHA3-256 / BLAKE3")
    elif n == 96:
        print("Possible: SHA384")
    elif n == 128:
        print("Possible: SHA512")
    elif h.startswith(("$2a$", "$2b$", "$2y$")):
        print("Possible: bcrypt")
    elif h.startswith("$argon2"):
        print("Possible: Argon2")
    else:
        print("Unknown hash type.")

def load_wordlist():
    path = input("Path to wordlist (Enter for /usr/share/wordlists/rockyou.txt): ").strip()
    if not path:
        path = "/usr/share/wordlists/rockyou.txt"
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f]
    except FileNotFoundError:
        print(f"Wordlist not found: {path}")
        return []

def crack_hash(target, algo):
    words = load_wordlist()
    if not words:
        return
    print(f"Cracking with {algo}...")
    for w in words:
        try:
            if algo == "md5"    and hashlib.md5(w.encode()).hexdigest() == target:
                return print(f"[+] Found: {w}")
            if algo == "sha1"   and hashlib.sha1(w.encode()).hexdigest() == target:
                return print(f"[+] Found: {w}")
            if algo == "sha256" and hashlib.sha256(w.encode()).hexdigest() == target:
                return print(f"[+] Found: {w}")
            if algo == "sha2"   and hashlib.sha512(w.encode()).hexdigest() == target:
                return print(f"[+] Found: {w}")
            if algo == "sha3"   and hashlib.sha3_256(w.encode()).hexdigest() == target:
                return print(f"[+] Found: {w}")
            if algo == "blake3":
                import blake3
                if blake3.blake3(w.encode()).hexdigest() == target:
                    return print(f"[+] Found: {w}")
            if algo == "bcrypt":
                import bcrypt
                if bcrypt.checkpw(w.encode(), target.encode()):
                    return print(f"[+] Found: {w}")
        except Exception:
            continue
    print("[-] Not found in wordlist.")

# ============================================================
#  SYMMETRIC ENCRYPTION (AES via Fernet)
# ============================================================
def aes_encrypt(text):
    from cryptography.fernet import Fernet
    key = Fernet.generate_key()
    token = Fernet(key).encrypt(text.encode())
    print("Key (save this!):", key.decode())
    print("Ciphertext:", token.decode())

def aes_decrypt(token, key):
    from cryptography.fernet import Fernet
    try:
        print("Plaintext:", Fernet(key.encode()).decrypt(token.encode()).decode())
    except Exception as e:
        print("Decryption failed:", e)

# ============================================================
#  ASYMMETRIC ENCRYPTION — RSA
# ============================================================
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

def rsa_generate_keys():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()

def rsa_encrypt(pub, message):
    return pub.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def rsa_decrypt(priv, ciphertext):
    return priv.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    ).decode()

def rsa_menu():
    print("""
    1) Generate RSA key pair
    2) Encrypt with RSA (public key)
    3) Decrypt with RSA (private key)
    4) Back
    """)
    c = input("> ").strip()
    if c == "1":
        priv, pub = rsa_generate_keys()
        pem_priv = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        pem_pub = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        print("\n--- Private Key (keep secret) ---\n" + pem_priv)
        print("--- Public Key (share freely) ---\n" + pem_pub)
        input("Press Enter...")
    elif c == "2":
        pub = serialization.load_pem_public_key(input("Paste PUBLIC key (PEM): ").strip().encode())
        msg = input("Message to encrypt: ")
        try:
            print("Ciphertext (hex):", rsa_encrypt(pub, msg).hex())
        except ValueError as e:
            print("Encryption failed (message too long for RSA):", e)
        input("Press Enter...")
    elif c == "3":
        priv = serialization.load_pem_private_key(
            input("Paste PRIVATE key (PEM): ").strip().encode(), password=None
        )
        try:
            print("Plaintext:", rsa_decrypt(priv, bytes.fromhex(input("Ciphertext (hex): ").strip())))
        except Exception as e:
            print("Decryption failed:", e)
        input("Press Enter...")

# ============================================================
#  ASYMMETRIC ENCRYPTION — ECC (ECDSA sign/verify)
# ============================================================
def ecc_generate_keys():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()

def ecc_sign(priv, message):
    return priv.sign(message.encode(), ec.ECDSA(hashes.SHA256()))

def ecc_verify(pub, message, signature):
    try:
        pub.verify(signature, message.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

def ecc_menu():
    print("""
    1) Generate ECC key pair (secp256r1)
    2) Sign message with ECC (private key)
    3) Verify signature with ECC (public key)
    4) Back
    """)
    c = input("> ").strip()
    if c == "1":
        priv, pub = ecc_generate_keys()
        pem_priv = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        pem_pub = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        print("\n--- ECC Private Key ---\n" + pem_priv)
        print("--- ECC Public Key ---\n" + pem_pub)
        input("Press Enter...")
    elif c == "2":
        priv = serialization.load_pem_private_key(
            input("Paste PRIVATE key (PEM): ").strip().encode(), password=None
        )
        print("Signature (hex):", ecc_sign(priv, input("Message to sign: ")).hex())
        input("Press Enter...")
    elif c == "3":
        pub = serialization.load_pem_public_key(input("Paste PUBLIC key (PEM): ").strip().encode())
        msg = input("Original message: ")
        sig = bytes.fromhex(input("Signature (hex): ").strip())
        print("Signature valid:", ecc_verify(pub, msg, sig))
        input("Press Enter...")

# ============================================================
#  SUB-MENUS
# ============================================================
def hash_generator_menu():
    print("""
    1) Generate MD5 hash
    2) Generate SHA1 hash
    3) Generate SHA256 hash
    4) Generate bcrypt hash
    5) Generate Argon2id
    6) Generate PBKDF2
    7) Generate BLAKE3
    8) Generate SHA2 hash
    9) Generate SHA3 hash
    10) Back
    """)
    c = input("> ").strip()
    if c == "10":
        return
    text = input("Type your text: ")
    {
        "1": generate_md5, "2": generate_sha1, "3": generate_sha256,
        "4": generate_bcrypt, "5": generate_argon2, "6": generate_pbkdf2,
        "7": generate_blake3, "8": generate_sha2, "9": generate_sha3,
    }.get(c, lambda t: print("Invalid choice"))(text)
    input("Press Enter...")

def hash_cracker_menu():
    print("""
    1) Identify the hash type
    2) Crack MD5 hash
    3) Crack SHA1 hash
    4) Crack SHA256 hash
    5) Crack bcrypt hash
    6) Crack Argon2id (unsupported, use hashcat)
    7) Crack PBKDF2 (unsupported)
    8) Crack BLAKE3
    9) Crack SHA2 hash
    10) Crack SHA3 hash
    11) Back
    """)
    c = input("> ").strip()
    if c == "11":
        return
    if c == "1":
        identify_hash(input("Hash: "))
        input("Press Enter...")
        return
    target = input("Hash to crack: ").strip()
    algo = {
        "2": "md5", "3": "sha1", "4": "sha256", "5": "bcrypt",
        "6": "argon2", "7": "pbkdf2", "8": "blake3", "9": "sha2", "10": "sha3",
    }.get(c)
    if algo in ("argon2", "pbkdf2"):
        print("Not implemented (use hashcat/john).")
    elif algo:
        crack_hash(target, algo)
    input("Press Enter...")

def symmetric_menu():
    print("""
    1) AES (Fernet)
    2) DES (not implemented)
    3) Blowfish (not implemented)
    4) Back
    """)
    c = input("> ").strip()
    if c == "4":
        return
    if c == "1":
        print("1) Decrypt\n2) Encrypt")
        a = input("> ").strip()
        if a == "1":
            key = input("Type the decryption key: ").strip()
            text = input("Type the text to decrypt: ").strip()
            aes_decrypt(text, key)
        elif a == "2":
            aes_encrypt(input("Type the text to encrypt: "))
    else:
        print("Not implemented.")
    input("Press Enter...")

def asymmetric_menu():
    print("""
    1) RSA (encrypt/decrypt)
    2) ECC (sign/verify)
    3) Back
    """)
    c = input("> ").strip()
    if c == "1":
        rsa_menu()
    elif c == "2":
        ecc_menu()

# ============================================================
#  MAIN MENU
# ============================================================
def menu():
    while True:
        os.system("clear" if os.name != "nt" else "cls")
        print(r"""
   ___  _ _____              __
  / _ \(_) ___/_____ _____  / /____
 / // / / /__/ __/ // / _ \/ __/ _ \
/____/_/\___/_/  \_, / .__/\__/\___/
                /___/_/

|-------------------------------------------------------|
|Developed By DIAA | For Educational Purpose | Version:1|
|-------------------------------------------------------|

Choose:
1) Hash Generator (MD5, SHA1, SHA256, bcrypt, etc..)
2) Hash Cracker (MD5, SHA1, SHA256, bcrypt, etc..)
3) Symmetric Encryption (AES, ChaCha20, 3DES, etc..)
4) Asymmetric Encryption (RSA, ECC, etc..)
5) Exit
""")
        choice = input("> ").strip()
        if   choice == "1": hash_generator_menu()
        elif choice == "2": hash_cracker_menu()
        elif choice == "3": symmetric_menu()
        elif choice == "4": asymmetric_menu()
        elif choice == "5":
            print("Goodbye!")
            sys.exit(0)

# ============================================================
#  ENTRY POINT
# ============================================================
if __name__ == "__main__":
    check_for_needed_tools()
    menu()
