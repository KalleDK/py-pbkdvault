import pytest
import tempfile
import pathlib
from pbkdvault import keyfile

def test_create_keyfile():
    with tempfile.TemporaryDirectory() as tmppath:
        path = pathlib.Path(tmppath, "key")
        want = keyfile.create(path)
        got = keyfile.load(path)
        assert want == got
        assert len(got) == keyfile.DEFAULT_MASTER_KEY_SIZE


def test_invalid_keylength():
    with pytest.raises(ValueError):
        with tempfile.TemporaryDirectory() as tmppath:
            path = pathlib.Path(tmppath, "key")
            keyfile.create(path, key_size=10)
            keyfile.load(path)
