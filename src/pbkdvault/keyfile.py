"""Module to create and load a key from a file
"""

import pathlib
import os
from . import b64
from . import securefile


DEFAULT_MASTER_KEY_SIZE = 512 // 8


def create(path: pathlib.Path, key_size: int = DEFAULT_MASTER_KEY_SIZE) -> bytes:
    """Create a random key with the lenght key_size, and store it in path

    Args:
        path (pathlib.Path): Path to store the key in
        key_size (int, optional): The size of the key to create in bytes.
            Defaults to DEFAULT_MASTER_KEY_SIZE.

    Returns:
        (bytes): The key created
    """
    key = os.urandom(key_size)
    b64_key = b64.encode(key)
    with securefile.sopen(path, mode='wt') as fp:
        fp.write(b64_key)
    return key


def load(path: pathlib.Path, key_size: int = DEFAULT_MASTER_KEY_SIZE) -> bytes:
    """Load a key from the path, and verify the lenth

    Args:
        path (pathlib.Path): Path to the file storing the key
        key_size (int, optional): Expected size of key. Defaults to DEFAULT_MASTER_KEY_SIZE.

    Raises:
        Exception: Key has a wrong size

    Returns:
        (bytes): The key
    """
    with securefile.sopen(path, mode='rt') as fp:
        b64_key = fp.read()

    key = b64.decode(b64_key)
    if len(key) != key_size:
        raise ValueError("invalid key length")
    return key


__all__ = ['load', 'create']
