"""Command line interface for the rootless observation extension."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from typing import Iterable

import click

from .collector import RootlessCollector
from .errors import MareformaProError
from .evidence import SOURCE_REQUIREMENTS
from .observe import verify_and_verdict
from .otel import AsyncJsonlSpanExporter
from .runner import RootlessBwrapRunner, RootlessFuseRunner
from .server import CollectorServer
from .supervisor import (
    DEFAULT_INTERNAL_PORT,
    DEFAULT_PUBLIC_PORT,
    MCPProcessSupervisor,
)
from .dbproxy import parse_relay_targets
from .store import ReceiptStore
from .task_context import TaskContextSpec
from .worker import WorkerProcessObserver


def _secret(value: str | None) -> str:
    secret = value or os.environ.get("MAREFORMA_HMAC_SECRET", "")
    if not secret:
        raise click.ClickException("set --secret or MAREFORMA_HMAC_SECRET")
    return secret


def _bind_pairs(values: Iterable[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for value in values:
        if ":" not in value:
            raise click.BadParameter(f"expected HOST:SANDBOX, got {value!r}")
        host, sandbox = value.split(":", 1)
        if not host or not sandbox:
            raise click.BadParameter(f"expected HOST:SANDBOX, got {value!r}")
        out[host] = sandbox
    return out


@click.group()
def cli() -> None:
    """Rootless, no-sudo observation helpers for Mareforma."""


@cli.command()
@click.option("--json", "as_json", is_flag=True)
def doctor(as_json: bool) -> None:
    """Report whether the no-sudo primitives are usable on this host."""
    checks: list[dict[str, object]] = []

    def add(name: str, ok: bool, detail: str, *, required: bool = True) -> None:
        checks.append({"name": name, "ok": ok, "detail": detail, "required": required})

    strace = shutil.which("strace")
    bwrap = shutil.which("bwrap")
    fusermount = shutil.which("fusermount3") or shutil.which("fusermount")
    ptrace_scope = None
    try:
        ptrace_scope = Path("/proc/sys/kernel/yama/ptrace_scope").read_text().strip()
    except OSError:
        pass
    add("strace", bool(strace), strace or "not installed")
    add("bwrap", bool(bwrap), bwrap or "not installed")
    # These describe the optional P2 FUSE route and host policy. A missing
    # /dev/fuse must not fail a P1 host: the default path never uses it.
    add(
        "ptrace_scope",
        ptrace_scope in (None, "0", "1", "2"),
        ptrace_scope or "not exposed",
        required=False,
    )
    add("fuse_device", Path("/dev/fuse").exists(), str(Path("/dev/fuse")), required=False)
    add("fusermount3", bool(fusermount), fusermount or "not installed", required=False)
    if strace:
        try:
            probe = subprocess.run(
                [strace, "--seccomp-bpf", "-qq", "-f", "-e", "trace=none", "--", "/bin/true"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            detail = (probe.stderr or probe.stdout or "no output").strip()[:160]
            add("seccomp_bpf", probe.returncode == 0, detail)
        except (OSError, subprocess.TimeoutExpired) as exc:
            add("seccomp_bpf", False, str(exc))
    report = {
        "ok": all(bool(c["ok"]) for c in checks if c["required"]),
        "checks": checks,
    }
    if as_json:
        click.echo(json.dumps(report, indent=2, sort_keys=True))
    else:
        for check in checks:
            label = "OK" if check["ok"] else ("WARN" if check["required"] else "OPTIONAL")
            click.echo(f"[{label}] {check['name']}: {check['detail']}")
    if not report["ok"]:
        raise click.exceptions.Exit(1)


@cli.command(context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.argument("command", nargs=-1, type=click.UNPROCESSED, required=True)
@click.option("--secret", default=None, help="HMAC secret; prefer MAREFORMA_HMAC_SECRET.")
@click.option("--cite", "cites", multiple=True, help="Cited source path/URL.")
@click.option("--ro-bind", "ro_binds", multiple=True, help="HOST:SANDBOX read-only bind.")
@click.option("--rw-bind", "rw_binds", multiple=True, help="HOST:SANDBOX read-write bind.")
@click.option("--tmpfs", "tmpfs_mounts", multiple=True, default=("/tmp",), show_default=True)
@click.option("--timeout", default=60.0, show_default=True, type=float)
@click.option("--keep-log", is_flag=True)
@click.option(
    "--source-requirement",
    type=click.Choice(sorted(SOURCE_REQUIREMENTS)),
    default="required",
    show_default=True,
)
@click.option("--json", "as_json", is_flag=True)
def run(
    command: tuple[str, ...],
    secret: str | None,
    cites: tuple[str, ...],
    ro_binds: tuple[str, ...],
    rw_binds: tuple[str, ...],
    tmpfs_mounts: tuple[str, ...],
    timeout: float,
    keep_log: bool,
    source_requirement: str,
    as_json: bool,
) -> None:
    """Run a command under bwrap+strace and emit a rootless receipt."""
    if not command:
        raise click.UsageError("a command is required after --")
    try:
        secret_value = _secret(secret)
        collector = RootlessCollector(secret_value)
        runner = RootlessBwrapRunner(collector)
        result = runner.run_in_bwrap(
            command,
            ro_binds=_bind_pairs(ro_binds),
            rw_binds=_bind_pairs(rw_binds),
            tmpfs_mounts=tmpfs_mounts,
            timeout_sec=timeout,
            keep_log=keep_log,
            source_requirement=source_requirement,
        )
        verdict = verify_and_verdict(
            result.evidence.to_receipt_dict(),
            secret=secret_value,
            cites=cites,
        )
    except (MareformaProError, OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    payload = {
        "returncode": result.process.returncode,
        "receipt": result.evidence.to_receipt_dict(),
        "grounding": verdict.to_signed_dict(),
    }
    if as_json:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        click.echo(f"returncode: {result.process.returncode}")
        click.echo(f"grounding: {verdict.grounding.value}")
        click.echo(f"observed_files: {list(result.evidence.observed_files)}")
        click.echo(f"opened_only: {list(result.evidence.opened_only)}")
        click.echo(f"opaque_reasons: {list(verdict.opaque_reasons)}")


@cli.command(
    name="supervise",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.argument("command", nargs=-1, type=click.UNPROCESSED, required=True)
@click.option("--secret", default=None, help="HMAC secret; prefer MAREFORMA_HMAC_SECRET.")
@click.option(
    "--port",
    default=DEFAULT_PUBLIC_PORT,
    show_default=True,
    type=int,
    help="Public Supervisor port (the client connects here).",
)
@click.option("--host", default="127.0.0.1", show_default=True, help="Public bind host.")
@click.option(
    "--internal-port",
    default=DEFAULT_INTERNAL_PORT,
    show_default=True,
    type=int,
    help="First internal MCP port (the unchanged server listens here).",
)
@click.option("--workers", default=1, show_default=True, type=int, help="Number of internal processes.")
@click.option("--egress-proxy", is_flag=True, help="Inject a local HTTP/HTTPS proxy into the server.")
@click.option(
    "--db-hook",
    is_flag=True,
    help="Prepend the opt-in Python sitecustomize DB/URL hooks to PYTHONPATH.",
)
@click.option(
    "--db-relay",
    "db_relays",
    multiple=True,
    metavar="HOST:PORT",
    help="Expose a local DB TCP relay and rewrite matching DATABASE_URL/PGHOST-style environment variables.",
)
@click.option("--no-strace", is_flag=True, help="Disable the strace FIFO (diagnostic only).")
@click.option(
    "--bind-rewrite-port",
    default=None,
    type=int,
    help="Redirect a fixed Python server bind() port to the internal host and port.",
)
@click.option("--ready-timeout", default=30.0, show_default=True, type=float)
@click.option("--drain-timeout", default=2.0, show_default=True, type=float)
@click.option("--session-idle-timeout", default=300.0, show_default=True, type=float)
@click.option(
    "--receipt-log",
    default="~/.mareforma/mcp-receipts.jsonl",
    show_default=True,
    type=click.Path(dir_okay=False, path_type=str),
    help="Append-only Call/Session receipt journal.",
)
@click.option("--trace-dir", default=None, type=click.Path(file_okay=False, path_type=str))
@click.option(
    "--otel-jsonl",
    default=None,
    type=click.Path(dir_okay=False, path_type=str),
    help="Optional non-authoritative OTel JSONL span output for Call/Session receipts.",
)
def supervise(
    command: tuple[str, ...],
    secret: str | None,
    port: int,
    host: str,
    internal_port: int,
    workers: int,
    egress_proxy: bool,
    db_hook: bool,
    db_relays: tuple[str, ...],
    no_strace: bool,
    bind_rewrite_port: int | None,
    ready_timeout: float,
    drain_timeout: float,
    session_idle_timeout: float,
    receipt_log: str,
    trace_dir: str | None,
    otel_jsonl: str | None,
) -> None:
    """Supervise an unchanged long-running HTTP MCP server.

    The original command is started on an internal loopback port. Requests
    arrive on the public port and are serialized per internal worker. The
    supervisor signs one CallReceipt after each request and a SessionReceipt
    when a session goes idle or the supervisor exits.

    Use ``{internal_port}`` or ``{external_port}`` in the command if its port
    argument is not the common ``--port <public-port>`` form. For a server that
    hard-codes its internal port, leave the server command unchanged and pass
    ``--bind-rewrite-port`` for a Python server, or configure the server to use
    ``{internal_port}``. The supervisor also sets PORT, MCP_PORT, UVICORN_PORT
    and MCP_SERVER_PORT for environment-driven servers.
    """
    if not command:
        raise click.UsageError("a command is required after --")
    try:
        secret_value = _secret(secret)
        span_exporter = AsyncJsonlSpanExporter(otel_jsonl) if otel_jsonl else None
        supervisor = MCPProcessSupervisor(
            command,
            secret=secret_value,
            host=host,
            port=port,
            internal_port=internal_port,
            workers=workers,
            egress_proxy=egress_proxy,
            db_hook=db_hook,
            db_relays=parse_relay_targets(db_relays),
            use_strace=not no_strace,
            bind_rewrite_port=bind_rewrite_port,
            ready_timeout=ready_timeout,
            drain_timeout=drain_timeout,
            session_idle_timeout=session_idle_timeout,
            trace_dir=trace_dir,
            receipt_log=Path(receipt_log).expanduser(),
            span_exporter=span_exporter,
        )
        supervisor.start()
    except (MareformaProError, OSError, RuntimeError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"supervisor listening: http://{host}:{port}")
    click.echo(f"internal endpoints: {[worker.endpoint for worker in supervisor.workers]}")
    if egress_proxy:
        click.echo("egress proxy: enabled (HTTPS path remains opaque without MITM CA)")
    if db_hook:
        click.echo("db hook: enabled (Python sitecustomize)")
    if bind_rewrite_port is not None:
        click.echo(
            f"bind rewrite: {bind_rewrite_port} -> "
            f"{supervisor.internal_host}:{supervisor.internal_port}"
        )
    if db_relays:
        click.echo(f"db relays: {list(db_relays)}")
    click.echo(f"receipt journal: {Path(receipt_log).expanduser()}")
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        supervisor.stop()
        if otel_jsonl:
            span_exporter.close()  # type: ignore[possibly-undefined]
        click.echo("supervisor stopped")


@cli.command(name="run-fuse", context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.argument("command", nargs=-1, type=click.UNPROCESSED, required=True)
@click.option("--secret", default=None, help="HMAC secret; prefer MAREFORMA_HMAC_SECRET.")
@click.option(
    "--source",
    "source_root",
    required=True,
    type=click.Path(exists=True, file_okay=False, path_type=str),
    help="Host directory exposed through the read-only FUSE view.",
)
@click.option(
    "--sandbox-path",
    default="/tmp/mareforma-data",
    show_default=True,
    help="Where the FUSE view is mounted inside bwrap.",
)
@click.option(
    "--keep-source-visible",
    is_flag=True,
    help="Do not hide the original host source path inside bwrap (debug only).",
)
@click.option("--cite", "cites", multiple=True, help="Cited host source path/URL.")
@click.option("--tmpfs", "tmpfs_mounts", multiple=True, default=("/tmp",), show_default=True)
@click.option("--timeout", default=60.0, show_default=True, type=float)
@click.option(
    "--source-requirement",
    type=click.Choice(sorted(SOURCE_REQUIREMENTS)),
    default="required",
    show_default=True,
)
@click.option("--json", "as_json", is_flag=True)
def run_fuse(
    command: tuple[str, ...],
    secret: str | None,
    source_root: str,
    sandbox_path: str,
    keep_source_visible: bool,
    cites: tuple[str, ...],
    tmpfs_mounts: tuple[str, ...],
    timeout: float,
    source_requirement: str,
    as_json: bool,
) -> None:
    """Run a command under a rootless read-only FUSE view (no ptrace)."""
    if not command:
        raise click.UsageError("a command is required after --")
    try:
        secret_value = _secret(secret)
        collector = RootlessCollector(secret_value)
        runner = RootlessFuseRunner(collector)
        result = runner.run_in_bwrap(
            command,
            source_root=source_root,
            sandbox_path=sandbox_path,
            hide_source_root=not keep_source_visible,
            tmpfs_mounts=tmpfs_mounts,
            timeout_sec=timeout,
            source_requirement=source_requirement,
        )
        verdict = verify_and_verdict(
            result.evidence.to_receipt_dict(),
            secret=secret_value,
            cites=cites,
        )
    except (MareformaProError, OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    payload = {
        "returncode": result.process.returncode,
        "receipt": result.evidence.to_receipt_dict(),
        "grounding": verdict.to_signed_dict(),
    }
    if as_json:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        click.echo(f"returncode: {result.process.returncode}")
        click.echo(f"collector_mode: {result.evidence.collector_mode}")
        click.echo(f"grounding: {verdict.grounding.value}")
        click.echo(f"observed_files: {list(result.evidence.observed_files)}")
        click.echo(f"opened_only: {list(result.evidence.opened_only)}")
        click.echo(f"opaque_reasons: {list(verdict.opaque_reasons)}")


@cli.group()
def worker() -> None:
    """Observe one long-running worker process without modifying it."""


@worker.command(
    name="supervise",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.argument("command", nargs=-1, type=click.UNPROCESSED, required=True)
@click.option("--secret", default=None, help="HMAC secret; prefer MAREFORMA_HMAC_SECRET.")
@click.option("--worker-id", default="0", show_default=True)
@click.option("--collector-id", default=None)
@click.option(
    "--receipt-log",
    default="~/.mareforma/worker-receipts.jsonl",
    show_default=True,
    type=click.Path(dir_okay=False, path_type=str),
    help="Append-only per-task receipt journal.",
)
@click.option("--trace-dir", default=None, type=click.Path(file_okay=False, path_type=str))
@click.option("--event-socket", default=None, type=click.Path(dir_okay=False, path_type=str))
@click.option(
    "--coverage-root",
    "coverage_roots",
    multiple=True,
    help="Host path the worker is expected to read; repeat for each root.",
)
@click.option(
    "--source-requirement",
    type=click.Choice(sorted(SOURCE_REQUIREMENTS)),
    default="required",
    show_default=True,
)
@click.option("--drain-timeout", default=2.0, show_default=True, type=float)
@click.option("--receipt-ttl", default=300.0, show_default=True, type=float)
@click.option("--strace-binary", default=None, help="Override the system strace path.")
@click.option("--no-strace", is_flag=True, help="Disable the kernel trace (diagnostic only).")
@click.option(
    "--db-query-text/--no-db-query-text",
    default=True,
    show_default=True,
    help="Record up to 4096 characters of SQL/Redis command text.",
)
@click.option(
    "--http-query-text",
    is_flag=True,
    help="Record URL query values as well as their digest and key names.",
)
@click.option(
    "--task-id-env",
    default="MAREFORMA_TASK_ID",
    show_default=True,
    help="Environment variable whose transitions delimit tasks.",
)
@click.option(
    "--execution-id-env",
    default="MAREFORMA_EXECUTION_ID",
    show_default=True,
    help="Optional environment variable carrying an execution id.",
)
@click.option(
    "--attempt-env",
    default="MAREFORMA_ATTEMPT",
    show_default=True,
    help="Optional environment variable carrying an attempt label.",
)
@click.option(
    "--attempt-dir-env",
    default="MAREFORMA_ATTEMPT_DIR",
    show_default=True,
    help="Optional environment variable whose basename is the attempt label.",
)
@click.option(
    "--execution-epoch-env",
    default="MAREFORMA_EXECUTION_EPOCH",
    show_default=True,
    help="Optional environment variable carrying an execution epoch.",
)
@click.option(
    "--parent-scope-id-env",
    default="MAREFORMA_PARENT_SCOPE_ID",
    show_default=True,
    help="Optional environment variable carrying a parent scope id.",
)
@click.option(
    "--traceparent-env",
    default="MAREFORMA_TRACEPARENT",
    show_default=True,
    help="Optional environment variable carrying a W3C traceparent.",
)
def worker_supervise(
    command: tuple[str, ...],
    secret: str | None,
    worker_id: str,
    collector_id: str | None,
    receipt_log: str,
    trace_dir: str | None,
    event_socket: str | None,
    coverage_roots: tuple[str, ...],
    source_requirement: str,
    drain_timeout: float,
    receipt_ttl: float,
    strace_binary: str | None,
    no_strace: bool,
    db_query_text: bool,
    http_query_text: bool,
    task_id_env: str,
    execution_id_env: str,
    attempt_env: str,
    attempt_dir_env: str,
    execution_epoch_env: str,
    parent_scope_id_env: str,
    traceparent_env: str,
) -> None:
    """Run an unchanged worker under a per-task observation scope.

    Task boundaries come from transitions of the configured task-id
    environment variable in the worker's Python runtime. The names are
    application-neutral; pass aliases when an unchanged worker already uses
    its own task variables. Each task receives its own HMAC-signed receipt.
    The child never receives the HMAC secret. The observer must start the
    worker itself; it cannot attach to an already-running systemd unit.
    """
    if not command:
        raise click.UsageError("a command is required after --")
    try:
        secret_value = _secret(secret)
        task_context = TaskContextSpec(
            task_id_env=task_id_env,
            execution_id_env=execution_id_env,
            attempt_env=attempt_env,
            attempt_dir_env=attempt_dir_env,
            execution_epoch_env=execution_epoch_env,
            parent_scope_id_env=parent_scope_id_env,
            traceparent_env=traceparent_env,
        )
        observer = WorkerProcessObserver(
            command,
            secret=secret_value,
            worker_id=worker_id,
            collector_id=collector_id,
            use_strace=not no_strace,
            strace_binary=strace_binary,
            drain_timeout=drain_timeout,
            receipt_ttl=receipt_ttl,
            receipt_log=Path(receipt_log).expanduser(),
            trace_dir=trace_dir,
            event_socket=event_socket,
            coverage_roots=coverage_roots,
            source_requirement=source_requirement,
            record_query_text=db_query_text,
            record_http_query_text=http_query_text,
            task_context=task_context,
        )
        click.echo(f"worker observer: worker_id={worker_id}")
        click.echo(f"task id environment: {task_id_env}")
        click.echo(f"worker command: {list(command)}")
        click.echo(f"receipt journal: {Path(receipt_log).expanduser()}")
        if no_strace:
            click.echo("kernel trace: disabled (every receipt is trace_incomplete)")
        else:
            click.echo("kernel trace: strace --seccomp-bpf -f -yy")
        returncode = observer.run_forever()
    except (MareformaProError, OSError, RuntimeError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"worker stopped: returncode={returncode}")
    if returncode:
        raise click.exceptions.Exit(returncode)


@cli.command()
@click.option("--socket", "socket_path", default="/tmp/mareforma-collector.sock", show_default=True)
@click.option("--secret", default=None)
@click.option("--token", default=None, help="Optional client token for the local socket.")
@click.option("--db", "db_path", default=None, help="SQLite receipt store.")
@click.option(
    "--otel-jsonl",
    "otel_jsonl",
    default=None,
    help="Write non-authoritative scope/process spans as JSONL.",
)
@click.option("--collector-id", default="rootless", show_default=True)
def serve(
    socket_path: str,
    secret: str | None,
    token: str | None,
    db_path: str | None,
    otel_jsonl: str | None,
    collector_id: str,
) -> None:
    """Serve the local rootless collector over a Unix socket."""
    store = ReceiptStore(db_path) if db_path else None
    secret_value = _secret(secret)
    span_exporter = AsyncJsonlSpanExporter(otel_jsonl) if otel_jsonl else None
    collector = RootlessCollector(
        secret_value,
        collector_id=collector_id,
        store=store,
        span_exporter=span_exporter,
    )
    server = CollectorServer(socket_path, collector, auth_token=token)
    click.echo(f"mareforma-collector listening on {socket_path}")
    try:
        server.serve_in_thread()
        while True:
            import time

            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        if span_exporter is not None:
            span_exporter.close()
        if store is not None:
            store.close()


@cli.command()
@click.option("--secret", default=None)
def demo(secret: str | None) -> None:
    """Run the four local sanity checks without a privileged host."""
    secret_value = _secret(secret)
    with tempfile.TemporaryDirectory(prefix="mareforma-pro-demo-") as tmp:
        root = Path(tmp)
        data = root / "results.csv"
        data.write_text("metric,value\naccuracy,0.942\n", encoding="utf-8")
        collector = RootlessCollector(secret_value)
        runner = RootlessBwrapRunner(collector)
        result = runner.run_in_bwrap(
            ["/bin/sh", "-c", "cd /tmp/work && /bin/cat results.csv >/dev/null"],
            ro_binds={str(root): "/tmp/work"},
        )
        verdict = verify_and_verdict(
            result.evidence.to_receipt_dict(), secret=secret_value, cites=[str(data)]
        )
        click.echo(f"read verdict: {verdict.grounding.value}")
        write_only = runner.run_in_bwrap(
            ["/bin/sh", "-c", "echo 1 > /tmp/work/out.csv"],
            rw_binds={str(root): "/tmp/work"},
        )
        verdict2 = verify_and_verdict(
            write_only.evidence.to_receipt_dict(), secret=secret_value, cites=[str(root / "out.csv")]
        )
        click.echo(f"write-only verdict: {verdict2.grounding.value}")
        click.echo(f"opaque reasons: {list(verdict2.opaque_reasons)}")


if __name__ == "__main__":
    cli()
