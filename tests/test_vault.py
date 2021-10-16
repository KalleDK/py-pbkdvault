import pytest
import tempfile
import pathlib
from pbkdvault import vault

def test_vault():
    with tempfile.TemporaryDirectory() as tmppath:
        key = bytes(512 // 8)
        path = pathlib.Path(tmppath, "db")
        v1 = vault.create_vault(key, path)
        want = "secret"
        v1.store("entry", "pass", want)
        v2 = vault.open_vault(key, path)
        got = v2.retrive("entry", "pass")
        assert want == got