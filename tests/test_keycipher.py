
import pytest
from pbkdvault.keycipher import KeyCipher

def test_get_key():
    want = b'\xf6\x07\xfc\x8bD\x01\x01\xf0L\xb8Pr\x88\xc0\xfd\xee\xdb\x87\x9b\xff\x87\xf8\x07,\x0b\x9b\xa1};\x06Cv'
    salt = b'^\xbd\xbd<\xd2\x19W\x12'
    passphrase = "dummy_passphrase"
    master_key = bytes(512)
    kc = KeyCipher(master_key)
    got = kc.get_key(passphrase, salt)
    assert got == want

def test_make_key():
    passphrase = "dummy_passphrase"
    master_key = bytes(512)
    kc = KeyCipher(master_key)
    want, salt = kc.make_key(passphrase)
    got = kc.get_key(passphrase, salt)
    assert want == got

def test_invalid_salt_raises():
    passphrase = "dummy_passphrase"
    master_key = bytes(512)
    kc = KeyCipher(master_key)
    invalid_salt = bytes(2)

    with pytest.raises(ValueError):
        kc.get_key(passphrase, invalid_salt)
