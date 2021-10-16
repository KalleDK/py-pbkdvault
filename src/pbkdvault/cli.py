"""PBKDVault.

Usage:
  pbkdvault [-k <keyfile>] genkey
  pbkdvault [-k <keyfile> -f <vaultfile>] init
  pbkdvault [-k <keyfile> -f <vaultfile>] add <name> [<password>] <secret>
  pbkdvault [-k <keyfile> -f <vaultfile>] get <name> [<password>]

Options:
  -h --help               Show this screen.
  --version               Show version.
  -f, --vaultfile=<file>  Vaultfile [default: vault.db].
  -k, --keyfile=<file>    Keyfile [default: vault.key].

"""
import pathlib
from typing import Any
from docopt import docopt
from . import keyfile
from . import vault


def main():
    """Main cli entrypoint
    """
    args = docopt(__doc__, version='PBKDVault 1.0')
    print(args)
    cmds = {
        'genkey': cmd_genkey,
        'init': cmd_init,
        'add': cmd_add,
        'get': cmd_get
    }
    for action, cmd in cmds.items():
        if args[action]:
            cmd(args)
            break


def cmd_genkey(args: dict[str, Any]):
    """Action to generate keyfile"""
    keyfile.create(pathlib.Path(args["--keyfile"]))

def cmd_init(args: dict[str, Any]):
    """Action to initialize vaultfile"""
    key = keyfile.load(pathlib.Path(args["--keyfile"]))
    vault.create_vault(key, pathlib.Path(args["--vaultfile"]))

def cmd_add(args: dict[str, Any]):
    """Action to add secret to vaultfile"""
    key = keyfile.load(pathlib.Path(args["--keyfile"]))
    vaultfile = vault.open_vault(key, pathlib.Path(args["--vaultfile"]))
    vaultfile.store(args["<name>"], args["<password>"], args["<secret>"])

def cmd_get(args: dict[str, Any]):
    """Action to gen secret from vaultfile"""
    key = keyfile.load(pathlib.Path(args["--keyfile"]))
    vaultfile = vault.open_vault(key, pathlib.Path(args["--vaultfile"]))
    print(vaultfile.retrive(args["<name>"], args["<password>"]))
