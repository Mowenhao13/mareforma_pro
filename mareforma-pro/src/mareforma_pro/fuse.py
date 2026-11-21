"""Rootless, read-only FUSE3 passthrough adapter.

This module speaks the Linux ``/dev/fuse`` protocol directly.  It deliberately
does not depend on libfuse or a Python FUSE binding: unprivileged users may ask
the setuid ``fusermount3`` helper to open ``/dev/fuse`` and mount a filesystem,
but the mount helper only performs the mount.  The read/readdir callbacks run
in this process and are the observation points.

The proxy is intentionally a *read-only view of one host directory*.  It never
serves writes, and every successful non-empty FUSE read is reported to the
collector against the host path that was actually opened.  This is a different
trust boundary from ``strace``: it sees bytes crossing the FUSE filesystem for
this view, not unrelated host filesystem activity.  A citation outside the
proxied root therefore cannot be made ``GROUNDED`` by this backend.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path
import select
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
import threading
from typing import Iterable, Mapping

from .collector import RootlessCollector
from .errors import FuseMountError, RootlessUnavailableError
from .evidence import OPAQUE_TRACE_INCOMPLETE

_FUSE_ROOT_ID = 1
_FUSE_LOOKUP = 1
_FUSE_FORGET = 2
_FUSE_GETATTR = 3
_FUSE_SETATTR = 4
_FUSE_READLINK = 5
_FUSE_SYMLINK = 6
_FUSE_MKNOD = 8
_FUSE_MKDIR = 9
_FUSE_UNLINK = 10
_FUSE_RMDIR = 11
_FUSE_RENAME = 12
_FUSE_LINK = 13
_FUSE_OPEN = 14
_FUSE_READ = 15
_FUSE_WRITE = 16
_FUSE_STATFS = 17
_FUSE_RELEASE = 18
_FUSE_FSYNC = 20
_FUSE_SETXATTR = 21
_FUSE_GETXATTR = 22
_FUSE_LISTXATTR = 23
_FUSE_REMOVEXATTR = 24
_FUSE_FLUSH = 25
_FUSE_INIT = 26
_FUSE_OPENDIR = 27
_FUSE_READDIR = 28
_FUSE_RELEASEDIR = 29
_FUSE_FSYNCDIR = 30
_FUSE_GETLK = 31
_FUSE_SETLK = 32
_FUSE_SETLKW = 33
_FUSE_ACCESS = 34
_FUSE_CREATE = 35
_FUSE_INTERRUPT = 36
_FUSE_BMAP = 37
_FUSE_DESTROY = 38
_FUSE_IOCTL = 39
_FUSE_POLL = 40
_FUSE_NOTIFY_REPLY = 41
_FUSE_BATCH_FORGET = 42
_FUSE_FALLOCATE = 43
_FUSE_READDIRPLUS = 44
_FUSE_RENAME2 = 45
_FUSE_LSEEK = 46
_FUSE_COPY_FILE_RANGE = 47
_FUSE_SETUPMAPPING = 48
_FUSE_REMOVEMAPPING = 49
_FUSE_SYNCFS = 50

_IN_HEADER = struct.Struct("<IIQQIIII")
_OUT_HEADER = struct.Struct("<IiQ")
_ATTR = struct.Struct("<QQQQQQIIIIIIIIII")
_DIRENT = struct.Struct("<QQII")
_INIT_IN = struct.Struct("<IIII")
_INIT_OUT = struct.Struct("<IIIIHHIIHH8I")
_ENTRY_PREFIX = struct.Struct("<QQQQII")
_ATTR_OUT_PREFIX = struct.Struct("<QII")
_OPEN_OUT = struct.Struct("<QII")
_READ_IN = struct.Struct("<QQIIQII")
_RELEASE_IN = struct.Struct("<Q")
_ACCESS_IN = struct.Struct("<I")
_STATFS = struct.Struct("<QQQQQIIII6I")

_FUSE_KERNEL_VERSION = 7
_FUSE_KERNEL_MINOR = 31
_MAX_WRITE = 4096
_DT = {
    stat.S_IFDIR: 4,   # DT_DIR
    stat.S_IFREG: 8,   # DT_REG
    stat.S_IFLNK: 10,  # DT_LNK
    stat.S_IFCHR: 2,   # DT_CHR
    stat.S_IFBLK: 6,   # DT_BLK
    stat.S_IFIFO: 1,   # DT_FIFO
    stat.S_IFSOCK: 12, # DT_SOCK
}
_WRITE_OPS = frozenset(
    {
        _FUSE_SETATTR,
        _FUSE_SYMLINK,
        _FUSE_MKNOD,
        _FUSE_MKDIR,
        _FUSE_UNLINK,
        _FUSE_RMDIR,
        _FUSE_RENAME,
        _FUSE_RENAME2,
        _FUSE_LINK,
        _FUSE_WRITE,
        _FUSE_SETXATTR,
        _FUSE_REMOVEXATTR,
        _FUSE_CREATE,
        _FUSE_FALLOCATE,
        _FUSE_COPY_FILE_RANGE,
        _FUSE_SYNCFS,
    }
)
_NO_REPLY_OPS = frozenset({_FUSE_FORGET, _FUSE_INTERRUPT, _FUSE_BATCH_FORGET, _FUSE_NOTIFY_REPLY})


def _ns(timestamp: float) -> int:
    return int(timestamp * 1_000_000_000)


def _attr_bytes(st: os.stat_result) -> bytes:
    """Encode the Linux ``struct fuse_attr`` (protocol 7.31)."""
    atime_ns = getattr(st, "st_atime_ns", _ns(st.st_atime))
    mtime_ns = getattr(st, "st_mtime_ns", _ns(st.st_mtime))
    ctime_ns = getattr(st, "st_ctime_ns", _ns(st.st_ctime))
    return _ATTR.pack(
        int(st.st_ino),
        int(st.st_size),
        int(getattr(st, "st_blocks", 0)),
        int(st.st_atime),
        int(st.st_mtime),
        int(st.st_ctime),
        int(atime_ns % 1_000_000_000),
        int(mtime_ns % 1_000_000_000),
        int(ctime_ns % 1_000_000_000),
        int(st.st_mode),
        int(st.st_nlink),
        int(st.st_uid),
        int(st.st_gid),
        int(st.st_rdev),
        int(getattr(st, "st_blksize", 4096) or 4096),
        0,
    )


def _entry_bytes(nodeid: int, st: os.stat_result) -> bytes:
    # Zero timeouts keep the mount's view fresh while a run is in progress.
    return _ENTRY_PREFIX.pack(nodeid, 0, 0, 0, 0, 0) + _attr_bytes(st)


def _attr_out_bytes(st: os.stat_result) -> bytes:
    return _ATTR_OUT_PREFIX.pack(0, 0, 0) + _attr_bytes(st)


class FuseReadOnlyProxy:
    """Expose one host directory as a rootless read-only FUSE mount.

    ``start()`` asks ``fusermount3`` to mount the view and creates the protocol
    loop.  ``stop()`` lazily unmounts it and joins the loop.  The object owns a
    temporary mountpoint unless the caller supplies one.
    """

    def __init__(
        self,
        collector: RootlessCollector,
        scope_id: str,
        source_root: str | os.PathLike[str],
        *,
        mountpoint: str | os.PathLike[str] | None = None,
        mount_parent: str | os.PathLike[str] | None = None,
        fusermount_binary: str | None = None,
        mount_options: Iterable[str] = (),
        max_read: int = 128 * 1024,
        mount_timeout: float = 10.0,
    ) -> None:
        if not scope_id:
            raise ValueError("scope_id must not be empty")
        source = Path(source_root)
        try:
            source = source.resolve(strict=True)
        except OSError as exc:
            raise ValueError(f"FUSE source root is not accessible: {source_root}") from exc
        if not source.is_dir():
            raise ValueError(f"FUSE source root is not a directory: {source_root}")
        if max_read < 4096:
            raise ValueError("max_read must be at least 4096 bytes")
        self.collector = collector
        self.scope_id = scope_id
        self.source_root = source
        self._provided_mountpoint = Path(mountpoint) if mountpoint is not None else None
        self._mount_parent = Path(mount_parent) if mount_parent is not None else None
        self._fusermount_binary = fusermount_binary or shutil.which("fusermount3") or shutil.which("fusermount")
        self._mount_options = tuple(str(value) for value in mount_options)
        self._max_read = int(max_read)
        self._read_buffer = self._max_read + 4096
        self._mount_timeout = float(mount_timeout)
        self._mountpoint: Path | None = None
        self._fd: int | None = None
        self._helper: subprocess.Popen[bytes] | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._init_event = threading.Event()
        self._loop_done = threading.Event()
        self._mounted = False
        self._unmount_requested = False
        self._premature_exit = False
        self._owns_mountpoint = mountpoint is None
        self._node_paths: dict[int, str] = {_FUSE_ROOT_ID: str(self.source_root)}
        self._path_nodes: dict[str, int] = {str(self.source_root): _FUSE_ROOT_ID}
        self._next_node = 2
        self._files: dict[int, tuple[int, str]] = {}
        self._dirs: dict[int, str] = {}
        self._next_handle = 1
        self.errors: list[BaseException] = []
        self.cleanup_errors: list[BaseException] = []

    @property
    def mountpoint(self) -> Path:
        if self._mountpoint is None:
            raise RuntimeError("FUSE proxy has not been started")
        return self._mountpoint

    @property
    def mounted(self) -> bool:
        return self._mounted

    @property
    def trace_complete(self) -> bool:
        """Whether the protocol loop ended without an unexplained I/O gap."""
        return not self.errors and not self._premature_exit

    @property
    def premature_exit(self) -> bool:
        """True when the mount ended without this proxy requesting unmount."""
        return self._premature_exit

    def __enter__(self) -> "FuseReadOnlyProxy":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def start(self) -> "FuseReadOnlyProxy":
        if self._thread is not None:
            raise RuntimeError("FUSE proxy was already started")
        if not self._fusermount_binary:
            raise RootlessUnavailableError("fusermount3 is required for the rootless FUSE proxy")
        if not Path("/dev/fuse").exists():
            raise RootlessUnavailableError("/dev/fuse is not available for the rootless FUSE proxy")
        if self._provided_mountpoint is not None:
            mountpoint = self._provided_mountpoint
            if not mountpoint.is_dir():
                raise FuseMountError(f"FUSE mountpoint is not a directory: {mountpoint}")
            self._mountpoint = mountpoint
        else:
            parent = self._mount_parent
            if parent is not None:
                parent.mkdir(parents=True, exist_ok=True)
            self._mountpoint = Path(tempfile.mkdtemp(prefix="mf_fuse_", dir=str(parent) if parent else None))
            self._mountpoint.chmod(0o700)

        try:
            self._fd = self._mount()
            self._mounted = True
            self._thread = threading.Thread(
                target=self._loop,
                name=f"mareforma-fuse-{self.scope_id}",
                daemon=True,
            )
            self._thread.start()
        except BaseException:
            self._cleanup_after_failed_start()
            raise
        if not self._init_event.wait(self._mount_timeout):
            self.stop()
            raise FuseMountError("FUSE mount did not complete the INIT handshake")
        if self.errors:
            error = self.errors[0]
            self.stop()
            raise FuseMountError(f"FUSE INIT failed: {error}") from error
        return self

    def _mount(self) -> int:
        assert self._mountpoint is not None
        assert self._fusermount_binary is not None
        parent_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        env = os.environ.copy()
        env["_FUSE_COMMFD"] = str(child_sock.fileno())
        options = [
            "ro",
            "nosuid",
            "nodev",
            f"fsname={_fsname(self.scope_id)}",
            "subtype=mareforma",
            f"max_read={self._max_read}",
            *self._mount_options,
        ]
        try:
            self._helper = subprocess.Popen(
                [self._fusermount_binary, "-o", ",".join(options), "--", str(self._mountpoint)],
                pass_fds=(child_sock.fileno(),),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            child_sock.close()
            parent_sock.settimeout(self._mount_timeout)
            try:
                _msg, ancdata, _flags, _addr = parent_sock.recvmsg(
                    1, socket.CMSG_SPACE(struct.calcsize("i"))
                )
            except socket.timeout as exc:
                raise FuseMountError("timed out waiting for fusermount3 to pass /dev/fuse") from exc
            fd: int | None = None
            for level, kind, data in ancdata:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS and len(data) >= 4:
                    fd = struct.unpack("i", data[:4])[0]
                    break
            try:
                stdout, stderr = self._helper.communicate(timeout=self._mount_timeout)
            except subprocess.TimeoutExpired as exc:
                self._helper.kill()
                stdout, stderr = self._helper.communicate()
                raise FuseMountError("fusermount3 did not exit after mounting") from exc
            if fd is None or self._helper.returncode != 0:
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                detail = _helper_detail(stdout, stderr)
                raise FuseMountError(
                    f"fusermount3 could not mount {self._mountpoint}"
                    + (f": {detail}" if detail else "")
                )
            os.set_inheritable(fd, False)
            return fd
        finally:
            parent_sock.close()
            child_sock.close()

    def _loop(self) -> None:
        assert self._fd is not None
        fd = self._fd
        try:
            while not self._stop_event.is_set():
                try:
                    ready, _w, _x = select.select([fd], [], [], 0.5)
                except InterruptedError:
                    continue
                except OSError as exc:
                    if exc.errno in (errno.EBADF, errno.ENODEV):
                        break
                    self.errors.append(exc)
                    break
                if not ready:
                    continue
                try:
                    data = os.read(fd, self._read_buffer)
                except InterruptedError:
                    continue
                except OSError as exc:
                    if exc.errno in (errno.ENODEV, errno.EBADF):
                        break
                    self.errors.append(exc)
                    break
                if not data:
                    break
                try:
                    self._dispatch(data)
                except BaseException as exc:  # noqa: BLE001 - one malformed request must not wedge the mount
                    self.errors.append(exc)
                    try:
                        header = _IN_HEADER.unpack_from(data, 0)
                        self._reply(int(header[2]), errno.EIO)
                    except BaseException:
                        pass
                    if not self._init_event.is_set():
                        break
        finally:
            if not self._unmount_requested:
                self._premature_exit = True
            self._loop_done.set()

    def _dispatch(self, data: bytes) -> None:
        if len(data) < _IN_HEADER.size:
            raise ValueError("short FUSE request")
        length, opcode, unique, nodeid, _uid, _gid, _pid, _pad = _IN_HEADER.unpack_from(data, 0)
        if length < _IN_HEADER.size or length > len(data):
            raise ValueError(f"invalid FUSE request length: {length}")
        payload = data[_IN_HEADER.size:length]

        if opcode == _FUSE_INIT:
            self._handle_init(unique, payload)
            return
        if opcode in _NO_REPLY_OPS:
            return
        if opcode == _FUSE_DESTROY:
            self._reply(unique)
            self._stop_event.set()
            return
        if opcode in _WRITE_OPS:
            self._reply(unique, errno.EROFS)
            return
        if opcode == _FUSE_LOOKUP:
            self._handle_lookup(unique, nodeid, payload)
            return
        if opcode == _FUSE_GETATTR:
            self._handle_getattr(unique, nodeid, payload)
            return
        if opcode == _FUSE_OPEN:
            self._handle_open(unique, nodeid, payload)
            return
        if opcode == _FUSE_READ:
            self._handle_read(unique, payload)
            return
        if opcode == _FUSE_RELEASE:
            self._handle_release(unique, payload, directory=False)
            return
        if opcode == _FUSE_OPENDIR:
            self._handle_opendir(unique, nodeid)
            return
        if opcode == _FUSE_READDIR:
            self._handle_readdir(unique, payload)
            return
        if opcode == _FUSE_RELEASEDIR:
            self._handle_release(unique, payload, directory=True)
            return
        if opcode == _FUSE_READLINK:
            self._handle_readlink(unique, nodeid)
            return
        if opcode == _FUSE_STATFS:
            self._handle_statfs(unique)
            return
        if opcode == _FUSE_ACCESS:
            self._handle_access(unique, nodeid, payload)
            return
        if opcode in {_FUSE_FLUSH, _FUSE_FSYNC, _FUSE_FSYNCDIR}:
            self._reply(unique)
            return
        if opcode in {_FUSE_GETLK, _FUSE_SETLK, _FUSE_SETLKW, _FUSE_BMAP, _FUSE_POLL, _FUSE_LSEEK}:
            self._reply(unique, errno.ENOSYS)
            return
        if opcode in {_FUSE_GETXATTR, _FUSE_LISTXATTR, _FUSE_READDIRPLUS}:
            self._reply(unique, errno.ENOSYS)
            return
        if opcode == _FUSE_IOCTL:
            self._reply(unique, errno.ENOTTY)
            return
        # Unknown optional operations are refused, never treated as a read.
        self._reply(unique, errno.ENOSYS)

    def _handle_init(self, unique: int, payload: bytes) -> None:
        if len(payload) < _INIT_IN.size:
            raise ValueError("short FUSE INIT request")
        major, minor, _max_readahead, _flags = _INIT_IN.unpack_from(payload, 0)
        if major < _FUSE_KERNEL_VERSION:
            self._reply(unique, errno.EPROTO)
            return
        # A major bump asks for a 7.x reply first; we only implement 7.x.
        if major > _FUSE_KERNEL_VERSION:
            out = _INIT_OUT.pack(_FUSE_KERNEL_VERSION, _FUSE_KERNEL_MINOR, 0, 0, 0, 0, _MAX_WRITE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            self._reply(unique, payload=out)
            return
        version_minor = min(int(minor), _FUSE_KERNEL_MINOR)
        out = _INIT_OUT.pack(
            _FUSE_KERNEL_VERSION,
            version_minor,
            0,  # no readahead: every data transfer stays visible to this callback
            0,  # no optional capabilities; no READDIRPLUS or writeback cache
            0,
            0,
            _MAX_WRITE,
            1,  # time_gran
            0,
            0,
            0, 0, 0, 0, 0, 0, 0, 0,
        )
        self._reply(unique, payload=out)
        self._init_event.set()

    def _handle_lookup(self, unique: int, parent: int, payload: bytes) -> None:
        raw_name = payload.split(b"\0", 1)[0]
        path = self._lookup_path(parent, os.fsdecode(raw_name))
        if path is None:
            self._reply(unique, errno.ENOENT)
            return
        try:
            st = os.lstat(path)
        except OSError as exc:
            self._reply(unique, exc.errno or errno.EIO)
            return
        nodeid = self._node_for(path)
        self._reply(unique, payload=_entry_bytes(nodeid, st))

    def _handle_getattr(self, unique: int, nodeid: int, payload: bytes) -> None:
        path = self._node_paths.get(nodeid)
        fh = 0
        if len(payload) >= 16:
            fh = int(struct.unpack_from("<Q", payload, 8)[0])
        try:
            item = self._files.get(fh)
            if item is not None:
                st = os.fstat(item[0])
            elif path is not None:
                st = os.lstat(path)
            else:
                self._reply(unique, errno.ENOENT)
                return
        except OSError as exc:
            self._reply(unique, exc.errno or errno.EIO)
            return
        self._reply(unique, payload=_attr_out_bytes(st))

    def _handle_open(self, unique: int, nodeid: int, payload: bytes) -> None:
        path = self._node_paths.get(nodeid)
        if path is None:
            self._reply(unique, errno.ENOENT)
            return
        flags = int(struct.unpack_from("<I", payload, 0)[0]) if len(payload) >= 4 else 0
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | getattr(os, "O_APPEND", 0)):
            self._reply(unique, errno.EROFS)
            return
        open_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        open_flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, open_flags)
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                os.close(fd)
                self._reply(unique, errno.EOPNOTSUPP)
                return
        except OSError as exc:
            self._reply(unique, exc.errno or errno.EIO)
            return
        if not self._record(opened_only=(path,)):
            os.close(fd)
            self._reply(unique, errno.EIO)
            return
        fh = self._next_handle
        self._next_handle += 1
        self._files[fh] = (fd, path)
        self._reply(unique, payload=_OPEN_OUT.pack(fh, 0, 0))

    def _handle_read(self, unique: int, payload: bytes) -> None:
        if len(payload) < _READ_IN.size:
            self._reply(unique, errno.EINVAL)
            return
        fh, offset, size, _read_flags, _lock_owner, _flags, _pad = _READ_IN.unpack_from(payload, 0)
        item = self._files.get(int(fh))
        if item is None:
            self._reply(unique, errno.EBADF)
            return
        fd, path = item
        try:
            chunk = os.pread(fd, min(int(size), self._max_read), int(offset))
        except OSError as exc:
            self._reply(unique, exc.errno or errno.EIO)
            return
        if chunk and not self._record(observed_files=(path,)):
            self._reply(unique, errno.EIO)
            return
        self._reply(unique, payload=chunk)

    def _handle_release(self, unique: int, payload: bytes, *, directory: bool) -> None:
        if len(payload) < _RELEASE_IN.size:
            self._reply(unique, errno.EINVAL)
            return
        fh = int(_RELEASE_IN.unpack_from(payload, 0)[0])
        if directory:
            self._dirs.pop(fh, None)
        else:
            item = self._files.pop(fh, None)
            if item is not None:
                try:
                    os.close(item[0])
                except OSError:
                    pass
        self._reply(unique)

    def _handle_opendir(self, unique: int, nodeid: int) -> None:
        path = self._node_paths.get(nodeid)
        if path is None:
            self._reply(unique, errno.ENOENT)
            return
        try:
            st = os.lstat(path)
        except OSError as exc:
            self._reply(unique, exc.errno or errno.EIO)
            return
        if not stat.S_ISDIR(st.st_mode):
            self._reply(unique, errno.ENOTDIR)
            return
        if not self._record(observed_dirs=(path,)):
            self._reply(unique, errno.EIO)
            return
        fh = self._next_handle
        self._next_handle += 1
        self._dirs[fh] = path
        self._reply(unique, payload=_OPEN_OUT.pack(fh, 0, 0))

    def _handle_readdir(self, unique: int, payload: bytes) -> None:
        if len(payload) < _READ_IN.size:
            self._reply(unique, errno.EINVAL)
            return
        fh, offset, size, _read_flags, _lock_owner, _flags, _pad = _READ_IN.unpack_from(payload, 0)
        path = self._dirs.get(int(fh))
        if path is None:
            self._reply(unique, errno.EBADF)
            return
        names = [".", ".."]
        try:
            names.extend(entry.name for entry in os.scandir(path))
        except OSError as exc:
            self._reply(unique, exc.errno or errno.EIO)
            return
        out = bytearray()
        start = max(0, int(offset))
        for index, name in enumerate(names[start:], start=start):
            if name == ".":
                child_path = path
            elif name == "..":
                parent = os.path.dirname(path)
                child_path = parent if self._within_root(parent) else self.source_root
                child_path = str(child_path)
            else:
                child_path = os.path.join(path, name)
                if not self._within_root(child_path):
                    continue
            try:
                st = os.lstat(child_path)
            except OSError:
                continue
            raw_name = os.fsencode(name)
            record = _DIRENT.pack(
                self._node_for(child_path),
                index + 1,
                len(raw_name),
                _DT.get(stat.S_IFMT(st.st_mode), 0),
            ) + raw_name
            record += b"\0" * ((-len(record)) % 8)
            if len(out) + len(record) > int(size):
                break
            out.extend(record)
        self._reply(unique, payload=bytes(out))

    def _handle_readlink(self, unique: int, nodeid: int) -> None:
        path = self._node_paths.get(nodeid)
        if path is None:
            self._reply(unique, errno.ENOENT)
            return
        try:
            target = os.readlink(path)
            resolved = os.path.realpath(
                target if os.path.isabs(target) else os.path.join(os.path.dirname(path), target)
            )
            if not self._within_root(resolved):
                raise OSError(errno.EACCES, "symlink escapes the FUSE root")
        except OSError as exc:
            self._reply(unique, exc.errno or errno.EIO)
            return
        # An absolute host symlink would bypass the FUSE view. Rewrite links
        # that point back inside the source root to the corresponding point in
        # this read-only view; relative links already stay inside the mount.
        if os.path.isabs(target):
            relative = os.path.relpath(resolved, self.source_root)
            target = str(self.mountpoint if relative == "." else self.mountpoint / relative)
        self._reply(unique, payload=os.fsencode(target))

    def _handle_statfs(self, unique: int) -> None:
        try:
            st = os.statvfs(self.source_root)
        except OSError as exc:
            self._reply(unique, exc.errno or errno.EIO)
            return
        payload = _STATFS.pack(
            st.f_blocks,
            st.f_bfree,
            st.f_bavail,
            st.f_files,
            st.f_ffree,
            st.f_bsize,
            255,
            st.f_frsize or st.f_bsize,
            0,
            0, 0, 0, 0, 0, 0,
        )
        self._reply(unique, payload=payload)

    def _handle_access(self, unique: int, nodeid: int, payload: bytes) -> None:
        path = self._node_paths.get(nodeid)
        if path is None:
            self._reply(unique, errno.ENOENT)
            return
        mask = int(_ACCESS_IN.unpack_from(payload, 0)[0]) if len(payload) >= 4 else 0
        if mask & os.W_OK:
            self._reply(unique, errno.EROFS)
            return
        if os.access(path, mask):
            self._reply(unique)
        else:
            self._reply(unique, errno.EACCES)

    def _lookup_path(self, parent: int, name: str) -> str | None:
        parent_path = self._node_paths.get(parent)
        if parent_path is None:
            return None
        if name == ".":
            return parent_path
        if name == "..":
            candidate = os.path.dirname(parent_path)
            return candidate if self._within_root(candidate) else str(self.source_root)
        if not name or name == "." or "/" in name or "\0" in name:
            return None
        candidate = os.path.normpath(os.path.join(parent_path, name))
        if not self._within_root(candidate):
            return None
        try:
            # Reject a symlink that would resolve outside the observed tree.
            if not self._within_root(os.path.realpath(candidate)):
                return None
        except OSError:
            return None
        return candidate

    def _node_for(self, path: str) -> int:
        path = os.path.normpath(path)
        existing = self._path_nodes.get(path)
        if existing is not None:
            return existing
        node = self._next_node
        self._next_node += 1
        self._path_nodes[path] = node
        self._node_paths[node] = path
        return node

    def _within_root(self, path: str | os.PathLike[str]) -> bool:
        root = os.fspath(self.source_root)
        candidate = os.path.normpath(os.fspath(path))
        if root == os.sep:
            return candidate.startswith(os.sep)
        if candidate == root:
            return True
        return candidate.startswith(root + os.sep)

    def _record(
        self,
        *,
        observed_files: Iterable[str] = (),
        observed_dirs: Iterable[str] = (),
        opened_only: Iterable[str] = (),
        opaque_reasons: Iterable[str] = (),
    ) -> bool:
        try:
            self.collector.ingest_events(
                self.scope_id,
                observed_files=observed_files,
                observed_dirs=observed_dirs,
                opened_only=opened_only,
                opaque_reasons=opaque_reasons,
            )
            return True
        except BaseException as exc:  # noqa: BLE001 - fail closed at the data channel
            self.errors.append(exc)
            return False

    def _reply(self, unique: int, error: int = 0, payload: bytes = b"") -> None:
        if self._fd is None:
            return
        wire = _OUT_HEADER.pack(_OUT_HEADER.size + len(payload), -error if error else 0, unique) + payload
        view = memoryview(wire)
        while view:
            try:
                written = os.write(self._fd, view)
            except InterruptedError:
                continue
            except OSError as exc:
                self.errors.append(exc)
                self._stop_event.set()
                return
            if written <= 0:
                self.errors.append(OSError(errno.EIO, "short FUSE reply"))
                self._stop_event.set()
                return
            view = view[written:]

    def _unmount(self) -> None:
        if self._mountpoint is None or not self._fusermount_binary:
            return
        if not self._mounted and not os.path.ismount(self._mountpoint):
            return
        self._unmount_requested = True
        try:
            result = subprocess.run(
                [self._fusermount_binary, "-u", "-q", "-z", "--", str(self._mountpoint)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self._mount_timeout,
                check=False,
                text=True,
            )
            if result.returncode != 0 and os.path.ismount(self._mountpoint):
                self.cleanup_errors.append(
                    FuseMountError("fusermount3 could not unmount the FUSE view: " + _helper_detail(result.stdout, result.stderr))
                )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.cleanup_errors.append(exc)
        self._mounted = False

    def _cleanup_after_failed_start(self) -> None:
        self._stop_event.set()
        if self._mountpoint is not None and (self._mounted or os.path.ismount(self._mountpoint)):
            self._unmount()
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        if self._mountpoint is not None and self._owns_mountpoint:
            try:
                self._mountpoint.rmdir()
            except OSError:
                pass
            self._mountpoint = None

    def stop(self) -> None:
        if self._thread is None and self._mountpoint is None and self._fd is None:
            return
        self._stop_event.set()
        self._unmount()
        if self._thread is not None:
            self._thread.join(timeout=max(5.0, self._mount_timeout))
            if self._thread.is_alive():
                self.errors.append(OSError(errno.EIO, "FUSE loop did not stop after unmount"))
                if self._fd is not None:
                    try:
                        os.close(self._fd)
                    except OSError:
                        pass
                    self._fd = None
                self._thread.join(timeout=5.0)
        if self._premature_exit:
            self._record(opaque_reasons=(OPAQUE_TRACE_INCOMPLETE,))
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        for fd, _path in list(self._files.values()):
            try:
                os.close(fd)
            except OSError:
                pass
        self._files.clear()
        self._dirs.clear()
        if self._mountpoint is not None and self._owns_mountpoint:
            try:
                self._mountpoint.rmdir()
            except OSError as exc:
                if not (self._mounted or os.path.ismount(self._mountpoint)):
                    self.cleanup_errors.append(exc)
            self._mountpoint = None


def _fsname(scope_id: str) -> str:
    safe = "".join(char if char.isalnum() or char in "_-" else "_" for char in scope_id)
    return "mareforma-" + (safe or "scope")


def _helper_detail(stdout: bytes | str | None, stderr: bytes | str | None) -> str:
    def decode(value: bytes | str | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", "replace")
        return value

    return (decode(stderr) or decode(stdout) or "no helper output").strip()[:500]


__all__ = ["FuseReadOnlyProxy"]
