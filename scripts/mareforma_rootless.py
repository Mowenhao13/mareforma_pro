#!/usr/bin/env python3
"""
mareforma_pro v1 纯免 sudo（Rootless）可运行原型（适配 gpu3 环境，仅依赖 Python 标准库）。

核心能力:
  1. 用 `strace --seccomp-bpf -f -y -qq` 封装 `bwrap` 运行（每 scope 独立日志，零并发串台）
  2. 确定性 strace 解析器：处理多线程 unfinished/resumed 拆行、过滤 O_WRONLY/O_PATH/O_DIRECTORY
  3. 挂载表最长前缀还原：同时处理 --ro-bind/--bind 与嵌套 --tmpfs，未映射路径诚实标 OPAQUE
  4. HMAC-SHA256 收据签发、验签与非对称 Fail-Closed assert_claim() 判定

运行方式:
  python3 mareforma_rootless.py --unit-test   # 离线解析与边界单测
  python3 mareforma_rootless.py --gpu3-e2e    # 在 gpu3 上执行真实 strace + bwrap 4 类回归测试
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
import posixpath
import re
import subprocess
import tempfile
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
import uuid


# ===========================================================================
# 1. HMAC-SHA256 收据签名与校验（独立原型；正式接入请用 mareforma_pro）
# ===========================================================================

def _canonical_receipt_bytes(receipt: Dict[str, Any]) -> bytes:
    """剔除签名字段并规范化 JSON，确保跨进程签名与验签字节流严格一致。"""
    unsigned = {k: v for k, v in receipt.items() if k != "hmac_signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_receipt(receipt: Dict[str, Any], secret: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"),
        _canonical_receipt_bytes(receipt),
        hashlib.sha256,
    ).hexdigest()
    return f"hmac-sha256:{digest}"


def verify_receipt(receipt: Dict[str, Any], secret: str) -> bool:
    provided = receipt.get("hmac_signature")
    if not isinstance(provided, str) or not provided.startswith("hmac-sha256:"):
        return False
    expected = sign_receipt(receipt, secret)
    return hmac.compare_digest(expected, provided)


def assert_claim(
    cited_files: Sequence[str],
    receipt: Dict[str, Any],
    hmac_secret: str,
) -> Dict[str, Any]:
    """
    mareforma_pro 的核心非对称 Fail-Closed 判定逻辑:
      1. 验签失败 -> 视为 DECLARED，强制降级为 OPAQUE (unsigned_declared)
      2. 全部 cited_files 命中 observed_files -> GROUNDED（若存在无关盲区仍附带 opaque_reasons 提示）
      3. 存在未命中的 cited_files:
         - 若 opaque_reasons 为空（零盲区） -> UNGROUNDED（确证幻觉）
         - 若 opaque_reasons 非空（存在盲区） -> 强制降级为 OPAQUE（禁止冤枉为幻觉）
    """
    if not verify_receipt(receipt, hmac_secret):
        return {
            "verdict": "OPAQUE",
            "attestation": "DECLARED",
            "missing_files": list(cited_files),
            "opaque_reasons": ["unsigned_declared"],
        }

    observed = {posixpath.normpath(p) for p in receipt.get("observed_files", [])}
    normalized_cited = [posixpath.normpath(p) for p in cited_files]
    missing = [p for p in normalized_cited if p not in observed]
    opaque_reasons = list(receipt.get("opaque_reasons", []))

    if not missing:
        return {
            "verdict": "GROUNDED",
            "attestation": "ATTESTED",
            "missing_files": [],
            "opaque_reasons": opaque_reasons,
        }

    if opaque_reasons:
        return {
            "verdict": "OPAQUE",
            "attestation": "ATTESTED",
            "missing_files": missing,
            "opaque_reasons": opaque_reasons,
        }

    return {
        "verdict": "UNGROUNDED",
        "attestation": "ATTESTED",
        "missing_files": missing,
        "opaque_reasons": [],
    }


# ===========================================================================
# 2. bwrap 挂载表确定性路径还原（同时处理 bind mount 与嵌套 tmpfs）
# ===========================================================================

DEFAULT_IGNORE_SYSTEM_PREFIXES: Tuple[str, ...] = (
    "/proc",
    "/sys",
    "/dev",
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/etc",
)


def _match_prefix(norm_path: str, prefix: str) -> Optional[str]:
    """严格按目录边界匹配前缀，防止 /tmp/work 误匹配 /tmp/work2。"""
    if prefix == "/":
        return norm_path.lstrip("/")
    if norm_path == prefix:
        return ""
    if norm_path.startswith(prefix + "/"):
        return norm_path[len(prefix) + 1 :]
    return None


@dataclass(frozen=True)
class MountResolver:
    """
    根据 bwrap 挂载参数确定性还原沙箱内路径：
    - 统一按最长挂载前缀优先匹配（例如 /tmp/work 优先于 /tmp；更深层的 tmpfs 优先于外层 bind）
    - 命中显式 bind mount -> 还原为宿主机真实路径
    - 命中 tmpfs 挂载 -> 诚实返回 unmapped_tmpfs（绝不猜测）
    - 命中系统运行时只读目录（/lib, /usr, /etc, /proc 等）-> 过滤噪声
    """
    mount_map: Dict[str, str] = field(default_factory=dict)  # {sandbox_path: host_path}
    tmpfs_mounts: Tuple[str, ...] = ()                       # e.g. ("/tmp",)
    root_passthrough: bool = False                           # 是否使用了 --ro-bind / /
    ignore_system_prefixes: Tuple[str, ...] = DEFAULT_IGNORE_SYSTEM_PREFIXES

    def resolve(self, path_in_ns: str) -> Tuple[Optional[str], Optional[str], bool]:
        """
        返回 (resolved_host_path, opaque_reason, ignored_noise):
          - (host_path, None, False): 成功还原为宿主机路径
          - (None, reason, False):    未映射或临时路径，需记入 opaque_reasons
          - (None, None, True):       系统动态库/proc 等运行噪声，静默忽略
        """
        norm = posixpath.normpath(path_in_ns)

        # 汇总显式 bind 与 tmpfs，按前缀长度降序匹配最深层挂载点
        entries: List[Tuple[str, str, Optional[str]]] = []
        for sbx, host in self.mount_map.items():
            entries.append((posixpath.normpath(sbx), "bind", posixpath.normpath(host)))
        for tmp_dir in self.tmpfs_mounts:
            entries.append((posixpath.normpath(tmp_dir), "tmpfs", None))

        # 长度降序；若同一路径重复声明，tmpfs 保守优先于 bind
        entries.sort(key=lambda item: (len(item[0]), 1 if item[1] == "tmpfs" else 0), reverse=True)

        for mount_point, kind, host_prefix in entries:
            rel = _match_prefix(norm, mount_point)
            if rel is None:
                continue
            if kind == "bind" and host_prefix is not None:
                resolved = host_prefix if rel == "" else posixpath.join(host_prefix, rel)
                return posixpath.normpath(resolved), None, False
            return None, "unmapped_tmpfs", False

        # 未命中任何显式业务挂载时，先过滤系统库与虚拟文件系统噪声
        for sys_prefix in self.ignore_system_prefixes:
            if _match_prefix(norm, posixpath.normpath(sys_prefix)) is not None:
                return None, None, True

        # 若 bwrap 做了 --ro-bind / / 且不在 tmpfs/系统噪声下，则直接对应宿主机路径
        if self.root_passthrough:
            return norm, None, False

        return None, "unmapped_sandbox_path", False


# ===========================================================================
# 3. 确定性 strace 解析器（支持 unfinished/resumed 拆行与 O_WRONLY 过滤）
# ===========================================================================

LINE_RE = re.compile(r"^(?:\[pid\s+(\d+)\]|(\d+))\s+(.*)$")
UNFINISHED_RE = re.compile(r"^([a-zA-Z0-9_]+)\((.*)\s*<unfinished \.\.\.>$")
RESUMED_RE = re.compile(r"^<\.\.\.\s+([a-zA-Z0-9_]+)\s+resumed>(.*)$")
SYSCALL_RE = re.compile(r"^([a-zA-Z0-9_]+)\((.*)\)\s*=\s*(-?\d+.*)$")
FD_PATH_RE = re.compile(r"^(\d+)<(.+)>\s*$")
QUOTED_STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')

FLAG_O_WRONLY = re.compile(r"\bO_WRONLY\b")
FLAG_O_RDWR = re.compile(r"\bO_RDWR\b")
FLAG_O_DIRECTORY = re.compile(r"\bO_DIRECTORY\b")
FLAG_O_PATH = re.compile(r"\bO_PATH\b")

OPEN_SYSCALLS = {"open", "openat", "openat2"}
EXEC_SYSCALLS = {"execve", "execveat"}


@dataclass
class ParsedStraceResult:
    observed_files: Set[str] = field(default_factory=set)
    observed_dirs: Set[str] = field(default_factory=set)
    unmapped_paths: Set[str] = field(default_factory=set)
    opaque_reasons: Set[str] = field(default_factory=set)
    processes: List[Dict[str, Any]] = field(default_factory=list)
    total_open_read_events: int = 0
    skipped_wronly_events: int = 0
    stitched_split_lines: int = 0


def parse_strace_lines(
    lines: Iterable[str],
    resolver: MountResolver,
) -> ParsedStraceResult:
    """
    解析 `strace --seccomp-bpf -f -y -qq -e trace=open,openat,openat2,execve,execveat` 输出。
    """
    result = ParsedStraceResult()
    # 按 pid 缓存多线程被中断的 <unfinished ...> 片段: pid -> (syscall_name, prefix_str)
    pending: Dict[str, Tuple[str, str]] = {}

    for raw_line in lines:
        line = raw_line.rstrip("\r\n")
        if not line:
            continue

        m_line = LINE_RE.match(line)
        if not m_line:
            continue
        pid = m_line.group(1) or m_line.group(2)
        body = m_line.group(3).strip()

        # 1) 处理拆行前半段: openat(..., O_RDONLY <unfinished ...>
        m_unfin = UNFINISHED_RE.match(body)
        if m_unfin:
            sc_name = m_unfin.group(1)
            prefix = f"{sc_name}({m_unfin.group(2)}"
            pending[pid] = (sc_name, prefix)
            continue

        # 2) 处理拆行后半段: <... openat resumed>) = 3</tmp/work/a.csv>
        m_res = RESUMED_RE.match(body)
        if m_res:
            sc_name = m_res.group(1)
            suffix = m_res.group(2)
            saved = pending.pop(pid, None)
            if saved is None or saved[0] != sc_name:
                # 出现孤立 resumed，说明日志可能被截断
                if sc_name in OPEN_SYSCALLS:
                    result.opaque_reasons.add("trace_incomplete")
                continue
            body = saved[1] + suffix
            result.stitched_split_lines += 1

        # 3) 解析完整系统调用
        m_sc = SYSCALL_RE.match(body)
        if not m_sc:
            continue
        sc_name, args_str, ret_str = m_sc.group(1), m_sc.group(2), m_sc.group(3).strip()

        # 3a) 记录成功的进程 exec
        if sc_name in EXEC_SYSCALLS:
            if ret_str.startswith("0"):
                m_bin = QUOTED_STR_RE.search(args_str)
                binary = m_bin.group(1) if m_bin else "<unknown>"
                result.processes.append({"pid": int(pid), "syscall": sc_name, "binary": binary})
            continue

        # 3b) 处理 open / openat / openat2
        if sc_name not in OPEN_SYSCALLS:
            continue

        # 仅保留返回非负 fd 且带 -y 路径标注的成功打开（自动排除 -1 ENOENT / EACCES）
        m_fd = FD_PATH_RE.match(ret_str)
        if not m_fd:
            continue
        path_in_ns = m_fd.group(2)
        if path_in_ns.endswith(" (deleted)"):
            path_in_ns = path_in_ns[: -len(" (deleted)")]
        if not path_in_ns.startswith("/"):
            continue

        # 从文件名引号之后提取 flags 段，避免文件名本身包含 "O_WRONLY" 造成误判
        m_path_lit = QUOTED_STR_RE.search(args_str)
        flags_segment = args_str[m_path_lit.end() :] if m_path_lit else args_str

        # O_PATH 仅获取路径引用不能 read()，排除
        if FLAG_O_PATH.search(flags_segment):
            continue

        # 仅写不读（O_WRONLY 且非 O_RDWR），不能作为读取证据
        if FLAG_O_WRONLY.search(flags_segment) and not FLAG_O_RDWR.search(flags_segment):
            result.skipped_wronly_events += 1
            continue

        # O_DIRECTORY 单独归档，避免 ls 目录被误判为读取数据文件
        is_dir = bool(FLAG_O_DIRECTORY.search(flags_segment))

        host_path, opaque_reason, ignored = resolver.resolve(path_in_ns)
        if ignored:
            continue

        if is_dir:
            if host_path is not None:
                result.observed_dirs.add(host_path)
            continue

        if host_path is not None:
            result.observed_files.add(host_path)
            result.total_open_read_events += 1
        else:
            result.unmapped_paths.add(path_in_ns)
            if opaque_reason:
                result.opaque_reasons.add(opaque_reason)

    # 若日志结束仍有未闭合的 open* 系统调用，按 Fail-Closed 记为 trace_incomplete
    for _pid, (sc_name, _prefix) in pending.items():
        if sc_name in OPEN_SYSCALLS:
            result.opaque_reasons.add("trace_incomplete")

    return result


# ===========================================================================
# 4. 免 sudo Collector 与 bwrap Runner 封装
# ===========================================================================

@dataclass
class ScopeRecord:
    scope_id: str
    resolver: MountResolver
    opened_at: float = field(default_factory=time.time)
    closed_at: Optional[float] = None
    observed_files: Set[str] = field(default_factory=set)
    observed_dirs: Set[str] = field(default_factory=set)
    unmapped_paths: Set[str] = field(default_factory=set)
    opaque_reasons: Set[str] = field(default_factory=set)
    processes: List[Dict[str, Any]] = field(default_factory=list)


class RootlessCollector:
    """纯用户态内存/本地 Collector，负责聚合 strace 日志并签发 HMAC 收据。"""

    def __init__(self, hmac_secret: str) -> None:
        self._secret = hmac_secret
        self._scopes: Dict[str, ScopeRecord] = {}

    def open_scope(self, scope_id: str, resolver: MountResolver) -> None:
        self._scopes[scope_id] = ScopeRecord(scope_id=scope_id, resolver=resolver)

    def ingest_strace_log(self, scope_id: str, log_path: str) -> ParsedStraceResult:
        rec = self._scopes[scope_id]
        if not os.path.exists(log_path) or os.path.getsize(log_path) == 0:
            rec.opaque_reasons.add("trace_incomplete")
            return ParsedStraceResult(opaque_reasons={"trace_incomplete"})

        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            parsed = parse_strace_lines(fh, rec.resolver)

        rec.observed_files.update(parsed.observed_files)
        rec.observed_dirs.update(parsed.observed_dirs)
        rec.unmapped_paths.update(parsed.unmapped_paths)
        rec.opaque_reasons.update(parsed.opaque_reasons)
        rec.processes.extend(parsed.processes)
        return parsed

    def close_and_sign(self, scope_id: str) -> Dict[str, Any]:
        rec = self._scopes[scope_id]
        rec.closed_at = time.time()
        receipt: Dict[str, Any] = {
            "schema_version": "mareforma_pro.rootless_receipt/v1",
            "scope_id": rec.scope_id,
            "collector_mode": "strace_seccomp_bpf",
            "opened_at": round(rec.opened_at, 6),
            "closed_at": round(rec.closed_at, 6),
            "observed_files": sorted(rec.observed_files),
            "observed_dirs": sorted(rec.observed_dirs),
            "unmapped_paths": sorted(rec.unmapped_paths),
            "opaque_reasons": sorted(rec.opaque_reasons),
            "processes": rec.processes,
        }
        receipt["hmac_signature"] = sign_receipt(receipt, self._secret)
        return receipt


class RootlessBwrapRunner:
    """
    免 sudo 执行器：自动用 `strace --seccomp-bpf -f -y -qq` 包裹 `bwrap`，
    将当前任务的挂载映射与独占 trace 日志确定性地交给 Collector 签发收据。
    """

    def __init__(self, collector: RootlessCollector, log_dir: Optional[str] = None) -> None:
        self.collector = collector
        self.log_dir = log_dir or tempfile.gettempdir()

    def run_in_bwrap(
        self,
        cmd: Sequence[str],
        *,
        ro_binds: Optional[Dict[str, str]] = None,   # {host_path: sandbox_path}
        rw_binds: Optional[Dict[str, str]] = None,   # {host_path: sandbox_path}
        tmpfs_mounts: Sequence[str] = ("/tmp",),
        ro_bind_root: bool = True,
        unshare_pid: bool = True,
        clearenv: bool = True,
        keep_log: bool = False,
        timeout_sec: int = 60,
    ) -> Tuple[subprocess.CompletedProcess[str], Dict[str, Any]]:
        scope_id = f"scp_{uuid.uuid4().hex[:12]}"
        trace_log = os.path.join(self.log_dir, f"mf_trace_{scope_id}.log")

        # 组装 mount_map（key 为沙箱内路径，value 为宿主机路径）
        mount_map: Dict[str, str] = {}
        bwrap_cmd: List[str] = ["bwrap"]
        if ro_bind_root:
            bwrap_cmd.extend(["--ro-bind", "/", "/"])
        bwrap_cmd.extend(["--dev", "/dev", "--proc", "/proc"])

        for tmp_dir in tmpfs_mounts:
            bwrap_cmd.extend(["--tmpfs", tmp_dir])

        for host_path, sbx_path in (ro_binds or {}).items():
            bwrap_cmd.extend(["--ro-bind", host_path, sbx_path])
            mount_map[sbx_path] = os.path.abspath(host_path)

        for host_path, sbx_path in (rw_binds or {}).items():
            bwrap_cmd.extend(["--bind", host_path, sbx_path])
            mount_map[sbx_path] = os.path.abspath(host_path)

        if unshare_pid:
            bwrap_cmd.append("--unshare-pid")
        if clearenv:
            bwrap_cmd.append("--clearenv")

        bwrap_cmd.extend(cmd)

        strace_cmd = [
            "strace",
            "--seccomp-bpf",
            "-f",
            "-y",
            "-qq",
            "-e",
            "trace=open,openat,openat2,execve,execveat",
            "-o",
            trace_log,
            "--",
            *bwrap_cmd,
        ]

        resolver = MountResolver(
            mount_map=mount_map,
            tmpfs_mounts=tuple(tmpfs_mounts),
            root_passthrough=ro_bind_root,
        )
        self.collector.open_scope(scope_id, resolver)

        try:
            proc = subprocess.run(
                strace_cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
            self.collector.ingest_strace_log(scope_id, trace_log)
            receipt = self.collector.close_and_sign(scope_id)
            return proc, receipt
        finally:
            if not keep_log and os.path.exists(trace_log):
                try:
                    os.remove(trace_log)
                except OSError:
                    pass


# ===========================================================================
# 5. 离线解析单测 & gpu3 真实 bwrap 端到端 4 类回归测试
# ===========================================================================

def run_unit_tests() -> None:
    print(">>> 运行离线解析器与边界单测...")
    secret = "unit-test-secret"
    resolver = MountResolver(
        mount_map={"/tmp/work": "/data/exp42"},
        tmpfs_mounts=("/tmp", "/tmp/work/volatile"),
        root_passthrough=True,
    )

    mock_lines = [
        # 1) 多线程 unfinished / resumed 交叉拆行（openat 成功读取）
        '1001 openat(AT_FDCWD</tmp/work>, "results.csv", O_RDONLY <unfinished ...>',
        # 2) 另一线程写入 O_WRONLY（应被过滤，不计入读取证据）
        '1002 openat(AT_FDCWD</tmp/work>, "output.csv", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4</tmp/work/output.csv>',
        # 3) 线程 1001 恢复执行
        '1001 <... openat resumed>) = 3</tmp/work/results.csv>',
        # 4) openat2 成功读取（带 O_RDWR，允许作为读取证据）
        '1003 openat2(AT_FDCWD</tmp/work>, "meta.json", {flags=O_RDWR|O_CLOEXEC, resolve=0}, 24) = 5</tmp/work/meta.json>',
        # 5) 仅列目录 O_DIRECTORY（进 observed_dirs，不进 observed_files）
        '1003 openat(AT_FDCWD</tmp/work>, ".", O_RDONLY|O_DIRECTORY) = 6</tmp/work>',
        # 6) 系统库噪声（应静默过滤，不污染 observed_files 也不报 opaque）
        '1001 openat(AT_FDCWD</tmp/work>, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 7</lib/x86_64-linux-gnu/libc.so.6>',
        # 7) 打开失败 ENOENT（应过滤）
        '1001 openat(AT_FDCWD</tmp/work>, "nope.csv", O_RDONLY) = -1 ENOENT (No such file or directory)',
        # 8) 读取更深层嵌套 tmpfs 路径（应优先命中 /tmp/work/volatile -> unmapped_tmpfs）
        '1001 openat(AT_FDCWD</tmp/work>, "volatile/cache.bin", O_RDONLY) = 8</tmp/work/volatile/cache.bin>',
    ]

    parsed = parse_strace_lines(mock_lines, resolver)
    assert parsed.stitched_split_lines == 1, parsed
    assert parsed.skipped_wronly_events == 1, parsed
    assert parsed.observed_files == {"/data/exp42/results.csv", "/data/exp42/meta.json"}, parsed.observed_files
    assert parsed.observed_dirs == {"/data/exp42"}, parsed.observed_dirs
    assert parsed.unmapped_paths == {"/tmp/work/volatile/cache.bin"}, parsed.unmapped_paths
    assert parsed.opaque_reasons == {"unmapped_tmpfs"}, parsed.opaque_reasons

    # 验证签发与篡改拦截
    receipt = {
        "scope_id": "scp_unit_1",
        "observed_files": sorted(parsed.observed_files),
        "opaque_reasons": [],
    }
    receipt["hmac_signature"] = sign_receipt(receipt, secret)
    assert assert_claim(["/data/exp42/results.csv"], receipt, secret)["verdict"] == "GROUNDED"
    assert assert_claim(["/data/exp42/output.csv"], receipt, secret)["verdict"] == "UNGROUNDED"

    tampered = dict(receipt)
    tampered["observed_files"] = list(receipt["observed_files"]) + ["/data/exp42/output.csv"]
    res_tampered = assert_claim(["/data/exp42/output.csv"], tampered, secret)
    assert res_tampered["verdict"] == "OPAQUE" and res_tampered["opaque_reasons"] == ["unsigned_declared"]

    print("[PASS] 全部离线单测通过（拆行拼接、O_WRONLY 过滤、O_DIRECTORY 分离、嵌套 tmpfs、HMAC 防篡改）。")


def run_gpu3_e2e() -> None:
    print(">>> 在本机执行真实 strace --seccomp-bpf + bwrap 4 类回归测试...")
    secret = os.environ.get("MAREFORMA_HMAC_SECRET", "gpu3-e2e-demo-secret")
    collector = RootlessCollector(hmac_secret=secret)
    runner = RootlessBwrapRunner(collector)

    with tempfile.TemporaryDirectory(prefix="mf_gpu3_e2e_") as host_dir:
        results_csv = os.path.join(host_dir, "results.csv")
        out_csv = os.path.join(host_dir, "out.csv")
        with open(results_csv, "w", encoding="utf-8") as fh:
            fh.write("metric,value\naccuracy,0.942\n")

        # 用例 1: bwrap 真实读取绑定文件 -> GROUNDED
        proc1, r1 = runner.run_in_bwrap(
            ["/bin/sh", "-c", "cd /tmp/work && /bin/cat results.csv > /dev/null"],
            ro_binds={host_dir: "/tmp/work"},
        )
        assert proc1.returncode == 0, f"bwrap 失败: {proc1.stderr}"
        v1 = assert_claim([results_csv], r1, secret)
        print(f"\n[用例 1: bwrap 真实读取] verdict={v1['verdict']} | observed={r1['observed_files']}")
        assert v1["verdict"] == "GROUNDED", (v1, r1)

        # 用例 2: bwrap 仅以 O_WRONLY 写入 out.csv（从未读取），Agent 宣称读过 -> UNGROUNDED
        proc2, r2 = runner.run_in_bwrap(
            ["/bin/sh", "-c", "echo '1,2' > /tmp/work/out.csv"],
            rw_binds={host_dir: "/tmp/work"},
        )
        assert proc2.returncode == 0, f"bwrap 失败: {proc2.stderr}"
        v2 = assert_claim([out_csv], r2, secret)
        print(f"[用例 2: 仅写不读 / 幻觉引用] verdict={v2['verdict']} | observed={r2['observed_files']}")
        assert v2["verdict"] == "UNGROUNDED", (v2, r2)

        # 用例 3: bwrap 读取未映射的 --tmpfs /tmp 临时文件，且未读 results.csv -> Fail-Closed 降级 OPAQUE
        proc3, r3 = runner.run_in_bwrap(
            ["/bin/sh", "-c", "echo 'temp' > /tmp/scratch.csv && /bin/cat /tmp/scratch.csv > /dev/null"],
            ro_binds={host_dir: "/tmp/work"},
        )
        assert proc3.returncode == 0, f"bwrap 失败: {proc3.stderr}"
        v3 = assert_claim([results_csv], r3, secret)
        print(
            f"[用例 3: 未映射 tmpfs 盲区] verdict={v3['verdict']} | "
            f"reasons={v3['opaque_reasons']} | unmapped={r3['unmapped_paths']}"
        )
        assert v3["verdict"] == "OPAQUE" and "unmapped_tmpfs" in v3["opaque_reasons"], (v3, r3)

        # 用例 4: 篡改收据（伪造读取了未读文件）-> 验签失败降级 OPAQUE (unsigned_declared)
        forged = dict(r2)
        forged["observed_files"] = [out_csv]
        v4 = assert_claim([out_csv], forged, secret)
        print(f"[用例 4: 篡改外部收据] verdict={v4['verdict']} | reasons={v4['opaque_reasons']}")
        assert v4["verdict"] == "OPAQUE" and v4["opaque_reasons"] == ["unsigned_declared"], v4

        print("\n[PASS] gpu3 全部 4 类真实 strace + bwrap 回归用例通过！")
        print("\n--- 示例：用例 1 签发的完整 HMAC 收据 ---")
        print(json.dumps(r1, indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="mareforma_pro v1 rootless prototype")
    parser.add_argument("--unit-test", action="store_true", help="运行离线解析与边界单测")
    parser.add_argument("--gpu3-e2e", action="store_true", help="运行真实 strace + bwrap 4 类回归测试")
    args = parser.parse_args()

    if not args.unit_test and not args.gpu3_e2e:
        run_unit_tests()
        run_gpu3_e2e()
        return

    if args.unit_test:
        run_unit_tests()
    if args.gpu3_e2e:
        run_gpu3_e2e()


if __name__ == "__main__":
    main()