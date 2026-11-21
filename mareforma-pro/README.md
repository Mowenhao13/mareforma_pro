# mareforma-pro

`mareforma-pro` is the independently released, no-`sudo` observation extension
for [Mareforma](https://github.com/mareforma/mareforma). It installs the import
package `mareforma_pro` and the `mareforma-pro` command.

```bash
uv add mareforma-pro
```

The distribution depends on the core `mareforma` package. Use it when the host
does not grant `sudo`, CAP_BPF, or a writable cgroup subtree.

Releases use the independent tag namespace `mareforma-pro-vX.Y.Z` and publish
only this project. Core `mareforma` releases keep the `vX.Y.Z` tag namespace.

## Transports

- `strace + bwrap` (default): `strace --seccomp-bpf -f -y`, no privileged
  daemon.
- `FUSE + bwrap` (alternate): a scope-specific read-only `/dev/fuse` view that
  needs no ptrace. It uses the system `fusermount3` helper only for the
  unprivileged mount and requires no extra Python package.

```bash
# P1: ptrace-based read/open evidence
mareforma-pro run \
  --secret "$MAREFORMA_HMAC_SECRET" \
  --cite /data/exp42/results.csv \
  --ro-bind /data/exp42:/tmp/work \
  -- /bin/cat /tmp/work/results.csv

# P2: ptrace-free FUSE read evidence
mareforma-pro run-fuse \
  --secret "$MAREFORMA_HMAC_SECRET" \
  --source /data/exp42 \
  --cite /data/exp42/results.csv \
  -- /bin/cat /tmp/mareforma-data/results.csv
```

Both transports sign a `mareforma_pro.rootless_receipt/v1` receipt. The SDK
parent verifies the HMAC and converts it into a normal Mareforma grounding
verdict. A citation outside a FUSE receipt's signed `coverage_roots` is
`OPAQUE(unmapped_sandbox_path)`, never a confident `UNGROUNDED`.

## Python

```python
from mareforma_pro import RootlessCollector, RootlessFuseRunner, verify_and_verdict

collector = RootlessCollector(secret)
run = RootlessFuseRunner(collector).run_in_bwrap(
    ["/bin/cat", "/tmp/mareforma-data/results.csv"],
    source_root="/data/exp42",
)
verdict = verify_and_verdict(
    run.evidence.to_receipt_dict(),
    secret=secret,
    cites="/data/exp42/results.csv",
)
```

HMAC authenticates a receipt across the local process boundary. It is not a
defense against code that can read the parent's secret. Keep the secret out of
the target environment; the runners use `bwrap --clearenv` by default.

The optional OTLP adapter is available as `mareforma-pro[otel]`; the JSONL
exporter and span projection use only the standard library.
