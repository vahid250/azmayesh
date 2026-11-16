import base64
from cryptography.fernet import Fernet, InvalidToken


class SecretEncryption:
    """Authenticated encryption helper. Supply a Fernet key from a secret manager."""

    def __init__(self, key: str):
        try:
            self._fernet = Fernet(key.encode("ascii"))
        except Exception as exc:
            raise ValueError("CONFIG_ENCRYPTION_KEY must be a valid Fernet key") from exc

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        try:
            return self._fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeError) as exc:
            raise ValueError("Encrypted secret could not be authenticated") from exc

    @staticmethod
    def generate_key() -> str:
        return Fernet.generate_key().decode("ascii")
