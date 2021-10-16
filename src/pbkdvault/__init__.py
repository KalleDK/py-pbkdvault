"""Module to keep entries encrypted in a vaultfile
"""
from .vault import create_vault, open_vault, Vault
from .keyfile import create as create_keyfile
from .keyfile import load as load_keyfile
