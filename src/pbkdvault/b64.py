"""
Module to encode and decode base64 str
"""
import base64

def encode(data: bytes) -> str:
    """Encode bytes in a base64 str

    Args:
        data (bytes): data to encode

    Returns:
        str: base64 encoded str
    """
    return base64.b64encode(data).decode('utf-8')

def decode(data: str) -> bytes:
    """Decode a base64 str to bytes

    Args:
        data (str): base64 encoded str

    Returns:
        bytes: decoded bytes
    """
    return base64.b64decode(data.encode('utf-8'))
