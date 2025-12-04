import os
import re
import base64
from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

HEX64_RE = re.compile(r'^[0-9a-f]{64}$')

def decrypt_seed(encrypted_seed_b64: str, private_key_pem_path: str, password: Optional[bytes]=None) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP (SHA-256 / MGF1).

    Args:
        encrypted_seed_b64: Base64-encoded ciphertext
        private_key_pem_path: Path to PEM private key file
        password: Optional password bytes for encrypted PEM (if any)

    Returns:
        Decrypted hex seed (64-character lowercase hex string)

    Raises:
        ValueError on invalid input or decryption failure.
    """
    
    # Load private key
    if not os.path.isfile(private_key_pem_path):
        raise ValueError(f"private key file not found: {private_key_pem_path}")
    
    with open(private_key_pem_path, "rb") as f:
        key_data = f.read()
    
    try:
        private_key = serialization.load_pem_private_key(
            key_data, password=password, backend=default_backend()
        )
    except Exception as e:
        raise ValueError(f"Failed to load private key: {e}")
    
    # Decode base64
    try:
        ct = base64.b64decode(encrypted_seed_b64)
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}")
    
    # Decrypt with OAEP(SHA-256, MGF1(SHA-256))
    try:
        pt = private_key.decrypt(
            ct,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")
    
    # Decode to string and normalize
    try:
        seed = pt.decode("utf-8").strip()
    except Exception as e:
        raise ValueError(f"Failed to decode plaintext to UTF-8: {e}")
    
    seed = seed.lower()
    
    # Validate 64-character hex
    if not isinstance(seed, str) or len(seed) != 64 or not HEX64_RE.match(seed):
        raise ValueError(f"Decrypted seed validation failed. Expect 64-char hex, got: {repr(seed)}")
    
    return seed
