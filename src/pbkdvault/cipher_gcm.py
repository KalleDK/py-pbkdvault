"""
Implementation of GCM as a Cipher
"""
import dataclasses
from Crypto.Cipher import AES
from Crypto.Cipher._mode_gcm import GcmMode
from . import b64


@dataclasses.dataclass
class GCMCipher:
    """
    Implementation of GCM as a pbkdvault.Cipher
    """

    @staticmethod
    def decrypt(key: bytes, packet: dict[str, str]) -> bytes:
        """Decrypt packet with key

        Args:
            key (bytes): key used to decrypt
            packet (Packet): a packet created with the CBCCipher

        Returns:
            bytes: decrypted data
        """
        raw_packet = {k: b64.decode(v) for k, v in packet.items()}
        cipher: GcmMode = AES.new(key, AES.MODE_GCM, nonce=raw_packet['nonce']) # type: ignore
        msg = cipher.decrypt_and_verify(raw_packet['ciphertext'], raw_packet['tag'])
        return msg

    @staticmethod
    def encrypt(key: bytes, msg: bytes) -> dict[str, str]:
        """Encrypt data with key

        Args:
            key (bytes): key used to encrypt
            msg (bytes): data that should be encrypted

        Returns:
            Packet: packet encrypted via the CBCCipher
        """
        cipher: GcmMode = AES.new(key, AES.MODE_GCM) # type: ignore
        ciphertext, tag = cipher.encrypt_and_digest(msg)
        raw_packet = {'ciphertext': ciphertext, 'tag': tag, 'nonce': cipher.nonce}
        packet = {k: b64.encode(v) for k, v in raw_packet.items()}
        return packet
