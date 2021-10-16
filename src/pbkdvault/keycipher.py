"""Module for making a key based on a master key, a salt, and a passphrase
"""
import dataclasses
import os
import pbkdf2

DEFAULT_ENTRY_KEY_SIZE = 256 // 8
DEFAULT_ENTRY_SALT_SIZE = 128 // 8
DEFAULT_SALT_SIZE = 64 // 8


@dataclasses.dataclass(frozen=True)
class KeyCipher:
    """Can generate a new key, and recreate an old.
    """
    master_key: bytes
    entry_key_size: int = DEFAULT_ENTRY_KEY_SIZE
    entry_salt_size: int = DEFAULT_ENTRY_SALT_SIZE
    salt_size: int = DEFAULT_SALT_SIZE

    def _make_salt(self) -> bytes:
        return os.urandom(self.salt_size)

    def get_key(self, passphrase: str, salt: bytes) -> bytes:
        """Create a key base on the master_key, the given salt and passphrase.

        Args:
            passphrase (str): The passphrase used to generate the key
            salt (bytes): The salt used to generate to key

        Raises:
            ValueError: If the salt is the wrong length

        Returns:
            (bytes): The created key
        """
        if len(salt) != self.salt_size:
            raise ValueError("invalid salt length")
        entry_salt = pbkdf2.PBKDF2(passphrase.encode('utf-8'),
                            salt).read(self.salt_size)
        return pbkdf2.PBKDF2(self.master_key, entry_salt).read(self.entry_key_size)

    def make_key(self, passphrase: str) -> tuple[bytes, bytes]:
        """Creates a new key base on the master_key, a random salt, and the given passphrase

        Args:
            passphrase (str): The passphrase used to generate the key

        Returns:
            tuple[bytes, bytes]: The key and the salt
        """
        salt = self._make_salt()
        return self.get_key(passphrase, salt), salt
