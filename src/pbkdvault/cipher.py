"""Module to descripe the Cipher Protocol
"""
from typing import Protocol
import typing
from .cipher_gcm import GCMCipher

Packet = typing.TypeVar('Packet')

class Cipher(Protocol[Packet]):
    """Protocol that Cipher's should implement to be used with this library
    """
    def decrypt(self, key: bytes, packet: Packet) -> bytes:
        """Decrypt packet with key

        Args:
            key (bytes): key used to decrypt
            packet (Packet): a packet matching the Cipher used

        Returns:
            bytes: decrypted data
        """


    def encrypt(self, key: bytes, msg: bytes) -> Packet:
        """Encrypt data with key

        Args:
            key (bytes): key used to encrypt
            msg (bytes): data that should be encrypted

        Returns:
            Packet: packet encrypted via the Cipher
        """


DEFAULT_CIPHER: Cipher = GCMCipher()
