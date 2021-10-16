"""Module to manage a Vault with secrets
"""
import pathlib
import logging
import json
import dataclasses
from typing import Any, Union, Protocol
from . import securefile
from . import b64
from .cipher import Cipher, DEFAULT_CIPHER
from .keycipher import KeyCipher



log = logging.getLogger(__name__)

EntryID = Union[str, int]
VaultEntry = dict[str, Any]
VaultEntries = dict[EntryID, VaultEntry]


class VaultBackend(Protocol): # coverage: ignore
    """Protocol to descripte what a VaultBackend should implement
    """
    def load(self) -> VaultEntries:
        """Retrieves the vault from the backend

        Returns:
            VaultEntries: All entries in the vault
        """
        raise NotImplementedError()

    def save(self, vault: VaultEntries) -> None:
        """Stores the vault in the backend
        """
        raise NotImplementedError()


@dataclasses.dataclass
class VaultBackendFile:
    """VaultBackend that is based on a json file
    """
    path: pathlib.Path

    def load(self) -> VaultEntries:
        """Retrieves the vault from the backend

        Returns:
            VaultEntries: All entries in the vault
        """
        with securefile.sopen(self.path, mode="rt") as fp:
            return json.load(fp)

    def save(self, vault: VaultEntries):
        """Stores the vault in the backend
        """
        with securefile.sopen(self.path, mode="wt") as fp:
            json.dump(vault, fp, indent=4)


@dataclasses.dataclass
class Vault:
    """Vault that keeps all the secrets
    """
    keycipher: KeyCipher
    backend: VaultBackend
    persist: bool = True
    cipher: Cipher = DEFAULT_CIPHER
    entries: VaultEntries = dataclasses.field(default_factory=dict, init=False)

    def save(self):
        """Save the vault in the backend
        """
        self.backend.save(self.entries)

    def load(self) -> None:
        """Load the vault from the backend
        """
        self.entries = self.backend.load()

    def _get(self, entry_id: EntryID) -> VaultEntry:
        if self.entries is None or self.persist:
            self.load()

        entry = self.entries[entry_id]

        return entry

    def _set(self, entry_id: EntryID, entry: VaultEntry):
        if self.entries is None or self.persist:
            self.load()
        self.entries[entry_id] = entry
        if self.persist:
            self.save()

    def _decrypt(self, passphrase: str, entry: VaultEntry) -> bytes:
        salt = b64.decode(entry['salt'])
        packet = entry['packet']
        key = self.keycipher.get_key(passphrase, salt)
        msg = self.cipher.decrypt(key, packet)
        return msg

    def _encrypt(self, passphrase: str, msg: bytes) -> VaultEntry:
        key, salt = self.keycipher.make_key(passphrase)
        entry = {
            'salt': b64.encode(salt),
            'packet': self.cipher.encrypt(key, msg)
        }
        return entry

    def retrive(self, entry_id: EntryID, passphrase: str) -> str:
        """Retrieve an entry with stored at entry_id, and decrypt it with passphrase

        Args:
            entry_id (EntryID): The id that selects the entry
            passphrase (str): Passphrase to decrypt the entry

        Returns:
            str: The entry
        """
        encrypted_entry = self._get(entry_id)
        entry = self._decrypt(passphrase, encrypted_entry).decode('utf-8')
        return entry

    def store(self, entry_id: EntryID, passphrase: str, entry: str):
        """Store an entry at entry_id, and encrypt it with the passphrase

        Args:
            entry_id (EntryID): The id that selects the entry
            passphrase (str): Passphrase to encrypt the entry
            msg (str): The entry
        """
        encrypted_entry = self._encrypt(passphrase, entry.encode('utf-8'))
        self._set(entry_id, encrypted_entry)


def create_vault(master_key: bytes, vault_file: pathlib.Path, persist: bool = True) -> Vault:
    """Create a file vault

    Args:
        master_key (bytes): Master key to encrypt the entries
        vault_file (pathlib.Path): Path to file the vault should be saved in
        persist (bool, optional): Load and save on all changes. Defaults to True.

    Returns:
        Vault: The newly created vault
    """
    vault = Vault(KeyCipher(master_key), VaultBackendFile(vault_file), persist=persist)
    vault.save()
    return vault


def open_vault(master_key: bytes, vault_file: pathlib.Path, persist: bool = True) -> Vault:
    """Load an existing vault

    Args:
        master_key (bytes): Master key to encrypt and decrypt the entries
        vault_file (pathlib.Path): Path to the vault file
        persist (bool, optional): Load and save on all changes. Defaults to True.

    Returns:
        Vault: The loaded vault
    """
    vault = Vault(KeyCipher(master_key), VaultBackendFile(vault_file), persist=persist)
    vault.load()
    return vault
