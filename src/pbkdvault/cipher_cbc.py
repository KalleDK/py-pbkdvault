"""
Implementation of CBC as a Cipher
"""
import dataclasses
import os
from Crypto.Cipher import AES
from Crypto.Util import Padding
from . import b64

DEFAULT_CBC_BLOCK_SIZE = 16  # Bits
DEFAULT_CBC_IV_SIZE = 128 // 8  # Bytes


@dataclasses.dataclass
class CBCCipher:
    """
    Implementation of CBC as a pbkdvault.Cipher
    """
    iv_size: int = DEFAULT_CBC_IV_SIZE
    block_size: int = DEFAULT_CBC_BLOCK_SIZE

    def _pad(self, packet: bytes):
        return Padding.pad(packet, self.block_size)

    def _unpad(self, packet: bytes):
        return Padding.unpad(packet, self.block_size)

    def decrypt(self, key: bytes, packet: str) -> bytes:
        """Decrypt packet with key

        Args:
            key (bytes): key used to decrypt
            packet (Packet): a packet created with the CBCCipher

        Returns:
            bytes: decrypted data
        """
        raw_packet = b64.decode(packet)
        init_vector, encrypted = raw_packet[:self.iv_size], raw_packet[self.iv_size:]
        cipher = AES.new(key, AES.MODE_CBC, init_vector)
        padded = cipher.decrypt(encrypted)
        return self._unpad(padded)

    def encrypt(self, key: bytes, msg: bytes) -> str:
        """Encrypt data with key

        Args:
            key (bytes): key used to encrypt
            msg (bytes): data that should be encrypted

        Returns:
            Packet: packet encrypted via the CBCCipher
        """
        init_vector = os.urandom(self.iv_size)
        cipher = AES.new(key, AES.MODE_CBC, init_vector)
        padded = self._pad(msg)
        encrypted = cipher.encrypt(padded)
        raw_packet = init_vector + encrypted
        packet = b64.encode(raw_packet)
        return packet
