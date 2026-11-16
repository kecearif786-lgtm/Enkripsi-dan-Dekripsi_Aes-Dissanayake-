import os
import random
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def is_prime(n, k=12):
    if n < 2: return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
        if n == p: return True
        if n % p == 0: return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

def generate_prime(bits=256):
    while True:
        p = random.getrandbits(bits)
        p |= (1 << (bits - 1)) | 1
        if is_prime(p): return p

def egcd(a, b):
    if b == 0: return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y

def mod_inv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1: raise ValueError("Inverse modulo tidak ditemukan")
    return (x % m + m) % m

class Dissanayake:
    @staticmethod
    def keygen(bits=256):
        p, q = generate_prime(bits), generate_prime(bits)
        while q == p: q = generate_prime(bits)
        n = p * q
        phi = (p - 1) * (q - 1)
        d = 65537
        while egcd(d, phi)[0] != 1: d += 2
        e = mod_inv(d, phi)
        return str(n), str(e), str(d)

    @staticmethod
    def hash_msg(msg: str) -> int:
        return int(hashlib.sha256(msg.encode('utf-8')).hexdigest(), 16)

    @staticmethod
    def sign(msg: str, d_str: str, n_str: str):
        d, n = int(d_str), int(n_str)
        M = Dissanayake.hash_msg(msg)
        r = 0
        while (M + r) % 4 != 0: r += 1
        a = M + r - 2
        S = pow(a, d, n)
        return hex(S)[2:], str(r)

    @staticmethod
    def verify(msg: str, sig_hex: str, r_str: str, n_str: str, e_str: str) -> bool:
        try:
            M = Dissanayake.hash_msg(msg)
            S, r = int(sig_hex, 16), int(r_str)
            n, e = int(n_str), int(e_str)
            a_prime = pow(S, e, n)
            a = M + r - 2
            return a_prime == a
        except Exception:
            return False

def derive_key(password: str, salt: bytes, iterations: int = 200000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_aes_gcm(plaintext: str, password: str):
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)
    return salt.hex(), iv.hex(), ciphertext.hex()

def decrypt_aes_gcm(ciphertext_hex: str, password: str, salt_hex: str, iv_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None).decode('utf-8')
