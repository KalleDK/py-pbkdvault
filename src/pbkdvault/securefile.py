"""Module to secure opening of files. There is still race conditions, but is better than none."""
import pathlib
import stat
import sys

URW_G_O = (stat.S_IRUSR | stat.S_IWUSR)


def _mask(perm: int):
    return (stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO) & (~perm)


if sys.platform != "win32":
    def sopen(path: pathlib.Path, mode: str, buffering=-1, encoding=None, # pylint: disable=too-many-arguments
              errors=None, newline=None, permissions: int = URW_G_O):
        """Open path securely using file permissions but without locking

        Args:
            path (pathlib.Path): path to file
            mode (str): see builtin open
            buffering (int, optional): see builtin open
            encoding (str, optional): see builtin open
            errors ([type], optional): see builtin open
            newline ([type], optional): see builtin open
            permissions (int, optional): which permission should be validated. Defaults to URW_G_O.

        Raises:
            Exception: filepermissions are wrong

        Returns:
            (IO): see builtin open
        """

        if 'r' in mode:
            if path.stat().st_mode & _mask(permissions):
                raise Exception("to open file permissions")

        if 'w' in mode:
            path.touch(permissions)
            path.chmod(permissions)

        return path.open(mode=mode, buffering=buffering,
                         encoding=encoding, errors=errors, newline=newline)

else:
    def sopen(path: pathlib.Path, mode: str, buffering=-1, encoding=None, # pylint: disable=too-many-arguments
              errors=None, newline=None, permissions=URW_G_O):
        """Open path securely using file permissions but without locking.
        NOT working on windows

        Args:
            path (pathlib.Path): path to file
            mode (str): see builtin open
            buffering (int, optional): see builtin open
            encoding (str, optional): see builtin open
            errors ([type], optional): see builtin open
            newline ([type], optional): see builtin open
            permissions (int, optional): which permission should be validated. Defaults to URW_G_O.

        Raises:
            Exception: filepermissions are wrong

        Returns:
            (IO): see builtin open
        """
        _ = permissions
        return path.open(mode=mode, buffering=buffering,
                         encoding=encoding, errors=errors, newline=newline)
