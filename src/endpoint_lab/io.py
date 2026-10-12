import os
import stat
from pathlib import Path

from .limits import DEFAULT, InputError, Limits


def read_local(path: Path, limits: Limits = DEFAULT) -> bytes:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limits.file_bytes:
        raise InputError("Only regular files up to 8 MiB are accepted; symlinks are rejected.")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise InputError("Input changed while opening.")
        content = handle.read(limits.file_bytes + 1)
        after = os.fstat(handle.fileno())
    if len(content) > limits.file_bytes or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise InputError("Input is too large or changed while reading.")
    return content


def write_new(path: Path, value: str):
    with path.open("x", encoding="utf-8") as handle:
        handle.write(value)
