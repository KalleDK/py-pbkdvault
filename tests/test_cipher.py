import pytest
from pbkdvault.cipher import CBCCipher, GCMCipher, Cipher


messages = [
        " " * x for x in range(1, 50, 1)
    ] + [
        "a" * x for x in range(1, 50, 1)
    ] + [
        " fds fds ",
        "fdsfds",
        " fds(^ f*ds-",
    ]

@pytest.mark.parametrize('message_str', messages)
def test_decrypt(message_str: str):
    for CipherCLS in [CBCCipher, GCMCipher]:
        key = bytes(256 // 8)
        message = message_str.encode('utf-8')
        c: Cipher = CipherCLS()
        encrypted = c.encrypt(key, message)
        decrypted = c.decrypt(key, encrypted)
        assert decrypted == message