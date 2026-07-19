import os
import base64
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("FileVault")

class FileVault:
    """
    FileVault: A secure file encryption/decryption tool.
    Uses AES-GCM (Authenticated Encryption) for confidentiality and integrity.
    """
    ITERATIONS = 100_000
    SALT_SIZE = 16

    def __init__(self, password: str):
        self.password = password.encode()

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive a 256-bit key from the password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.ITERATIONS,
        )
        return kdf.derive(self.password)

    def encrypt_file(self, file_path: str):
        """Encrypts a file and appends .vault extension."""
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return

        salt = os.urandom(self.SALT_SIZE)
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)

        with open(file_path, 'rb') as f:
            data = f.read()

        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        with open(file_path + ".vault", 'wb') as f:
            f.write(salt + nonce + ciphertext)
        
        logger.info(f"File encrypted: {file_path}.vault")

    def decrypt_file(self, vault_path: str):
        """Decrypts a .vault file."""
        if not os.path.exists(vault_path):
            logger.error(f"Vault file not found: {vault_path}")
            return

        with open(vault_path, 'rb') as f:
            content = f.read()

        salt = content[:self.SALT_SIZE]
        nonce = content[self.SALT_SIZE:self.SALT_SIZE+12]
        ciphertext = content[self.SALT_SIZE+12:]

        key = self._derive_key(salt)
        aesgcm = AESGCM(key)

        try:
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
            original_path = vault_path.replace(".vault", "")
            with open(original_path, 'wb') as f:
                f.write(decrypted_data)
            logger.info(f"File decrypted: {original_path}")
        except InvalidTag:
            logger.error("Decryption failed: Invalid password or corrupted data.")

if __name__ == "__main__":
    # Example usage (locally tested during dev)
    vault = FileVault("super-secret-password")
    # shield_py_path = "vault_test.txt"
    # with open(shield_py_path, 'w') as f: f.write("Sensitive data here")
    # vault.encrypt_file(shield_py_path)
    # vault.decrypt_file(shield_py_path + ".vault")
