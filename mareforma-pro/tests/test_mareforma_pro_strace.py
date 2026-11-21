"""Deterministic parser tests for the rootless strace path."""

from __future__ import annotations

from mareforma_pro.paths import MountResolver
from mareforma_pro.strace import parse_strace


def _resolver() -> MountResolver:
    return MountResolver.from_mounts(
        {"/tmp/work": "/data/exp42"},
        tmpfs_mounts=("/tmp",),
        root_passthrough=True,
    )


def test_open_and_read_are_distinct_and_split_lines_stitch():
    lines = [
        '100 openat(AT_FDCWD, "/tmp/work/data.csv", O_RDONLY <unfinished ...>\n',
        '100 <... openat resumed>) = 3</tmp/work/data.csv>\n',
        '100 read(3</tmp/work/data.csv>, "a,b\\n", 8) = 4\n',
        '100 openat(AT_FDCWD, "/tmp/work/open-only.csv", O_RDONLY) = 4</tmp/work/open-only.csv>\n',
        '100 openat(AT_FDCWD, "/tmp/work/out.csv", O_WRONLY|O_CREAT, 0644) = 5</tmp/work/out.csv>\n',
        '100 openat(AT_FDCWD, "/tmp/work", O_RDONLY|O_DIRECTORY) = 6</tmp/work>\n',
        '100 openat(AT_FDCWD, "/tmp/scratch.csv", O_RDONLY) = 7</tmp/scratch.csv>\n',
        '100 execve("/bin/cat", ["cat", "/tmp/work/data.csv"], 0x0) = 0\n',
    ]
    result = parse_strace(lines, _resolver())
    assert result.observed_files == {"/data/exp42/data.csv"}
    assert result.opened_only == {"/data/exp42/open-only.csv"}
    assert result.observed_dirs == {"/data/exp42"}
    assert result.opaque_reasons == {"open_only", "unmapped_tmpfs"}
    assert result.unmapped_paths == {"/tmp/scratch.csv"}
    assert result.skipped_writes == 1
    assert result.stitched_lines == 1
    assert result.processes[-1]["binary"] == "/bin/cat"


def test_unfinished_read_is_fail_closed():
    result = parse_strace(
        ['1 read(3</data/file>, "x", 1 <unfinished ...>\n'],
        MountResolver.from_mounts({}, root_passthrough=True),
    )
    assert "trace_incomplete" in result.opaque_reasons


def test_clone_and_exec_edges_are_recorded():
    result = parse_strace(
        [
            "10 execve(\"/bin/sh\", [\"sh\"], 0x0) = 0\n",
            "10 clone(child_stack=0, flags=0) = 11\n",
            "11 execve(\"/bin/cat\", [\"cat\"], 0x0) = 0\n",
        ],
        MountResolver.from_mounts({}, root_passthrough=True),
    )
    assert {"pid": 11, "parent_pid": 10, "syscall": "clone"} in result.processes
    assert any(p.get("binary") == "/bin/cat" for p in result.processes)


def test_mount_boundary_does_not_match_work2():
    resolver = MountResolver.from_mounts({"/work": "/host/work"})
    assert resolver.resolve("/work/file").resolved == "/host/work/file"
    assert resolver.resolve("/work2/file").opaque_reason == "unmapped_sandbox_path"


def test_socket_events_are_diagnostic_only():
    result = parse_strace(
        [
            "1 connect(3, {sa_family=AF_INET}, 16) = 0\n",
            '1 recvmsg(3, {msg_name=NULL}, 0) = 5\n',
        ],
        MountResolver.from_mounts({}, root_passthrough=True),
    )
    assert result.socket_events == ["connect", "recvmsg"]
    assert result.observed_files == set()


def test_read_on_socket_is_marked_as_a_seam():
    result = parse_strace(
        ['1 read(3<socket:[12345]>, "x", 1) = 1\n'],
        MountResolver.from_mounts({}, root_passthrough=True),
    )
    assert "read:socket" in result.socket_events
    assert result.observed_files == set()

