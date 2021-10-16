import pytest
import pathlib
import tempfile
import stat
from pbkdvault import securefile


def test_invalid_permission():
    with pytest.raises(Exception):
        with tempfile.TemporaryDirectory() as tmppath:
            path = pathlib.Path(tmppath, "key")
            with securefile.sopen(path, mode="wb", permissions=(securefile.URW_G_O | stat.S_IROTH)) as fp:
                fp.write(b'1')
            with securefile.sopen(path, mode="rb", permissions=securefile.URW_G_O) as fp:
                fp.read()