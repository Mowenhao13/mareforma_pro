"""Command line interface for the rootless observation extension."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Iterable

import click

from .collector import RootlessCollector
from .errors import MareformaProError
from .observe import verify_and_verdict
from .otel import AsyncJsonlSpanExporter
from .runner import RootlessBwrapRunner, RootlessFuseRunner
from .server import CollectorServer
from .store import ReceiptStore


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
