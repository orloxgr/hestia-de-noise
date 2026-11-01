"""No-follow file access and durable replacement of addon-owned files."""
from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import secrets
import stat

from policy import MARKER


@contextmanager
def parent(path):
    """Pin every ancestor with openat; never follow user-controlled symlinks."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('An absolute managed path is required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for piece in path.parent.parts[1:]:
            new = os.open(piece, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = new
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Managed directory must be owned and writable only by root: ' + str(path.parent))
        yield fd
    finally:
        os.close(fd)


def read(path):
    with parent(path) as fd:
        try:
            handle = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        except FileNotFoundError:
            return None
        with os.fdopen(handle, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('Refusing a non-regular or untrusted managed file: ' + str(path))
            data = stream.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise ValueError('Managed file is unexpectedly large: ' + str(path))
            return data


def read_hestia_include(path):
    """Read native snippets, including Hestia's specific SSL ACME link."""
    path = Path(path)
    try:
        return read(path)
    except OSError as error:
        if error.errno != errno.ELOOP:
            raise
        if path.name != 'nginx.ssl.conf_letsencrypt':
            raise ValueError('Unsupported symbolic include: ' + str(path)) from error
    expected = path.with_name('nginx.conf_letsencrypt')
    with parent(path) as fd:
        info = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
            raise ValueError('The native ACME include link must belong to root: ' + str(path))
        link = os.readlink(path.name, dir_fd=fd)
        if link not in (expected.name, './' + expected.name, str(expected)):
            raise ValueError('Unexpected target for the native ACME include: ' + str(path))
    # Inspect the HTTP counterpart, never follow the link itself. The normal
    # no-follow reader validates its ancestors, type and root-only ownership.
    content = read(expected)
    if content is None:
        raise ValueError('The native ACME include target is missing: ' + str(expected))
    return content


def replace(path, data, mode=0o644):
    path = Path(path)
    with parent(path) as fd:
        temporary = '.' + path.name + '.tmp-' + secrets.token_hex(8)
        if data is None:
            try:
                os.unlink(path.name, dir_fd=fd)
            except FileNotFoundError:
                pass
        else:
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                                 mode, dir_fd=fd)
            try:
                with os.fdopen(descriptor, 'wb') as stream:
                    os.fchmod(stream.fileno(), mode)
                    stream.write(data); stream.flush(); os.fsync(stream.fileno())
                os.replace(temporary, path.name, src_dir_fd=fd, dst_dir_fd=fd)
            finally:
                try:
                    os.unlink(temporary, dir_fd=fd)
                except FileNotFoundError:
                    pass
        os.fsync(fd)


def owned(path):
    data = read(path)
    if data is not None and not data.startswith((MARKER + '\n').encode()):
        raise ValueError('Refusing an existing file not owned by De-Noise: ' + str(path))
    return data


def json_bytes(data):
    return (json.dumps(data, indent=2, sort_keys=True) + '\n').encode()


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, exist_ok=True)
    # Validate ancestors, ownership and exact privacy before using a root lock.
    with parent(path / '.check'):
        if path.stat().st_mode & 0o077:
            raise ValueError('State directory must be root-private: ' + str(path))
