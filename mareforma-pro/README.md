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

## Grounding scope, not a truth score

`mareforma-pro` reports what the selected backend could observe. It never
turns an application declaration into kernel evidence. Three OPAQUE cases are
kept distinct so an operator can see whether a missing source is expected:

- `no_cited_source`: the scope was expected to read an external source, but the
  finding named none;
- `computed_no_external_source`: the caller explicitly declared a pure
  computation with `source_requirement="not_applicable"`;
- `static_binary_untraced`, `trace_incomplete`, `socket_event_unbound`, and
  `unmapped_sandbox_path`: a native module, child process, thread, socket, or
  bounded view may have read data outside the backend's visibility.

The pure-computation path still produces a signed execution claim and remains
`OPAQUE`; it is a clearer diagnosis, not a claim that a computation is
grounded in external data.

If the installed core wheel predates the three diagnostic fields, Pro folds
`opaque_reasons`, `read_semantics`, and `evidence_level` into the verdict reason
and reconstructs `RootlessObservation.opaque_reasons` from its seams. The
verdict stays fail-closed; no blind spot is silently dropped.

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

## Application hooks and native blind spots

`JupyterScopeHook`, `audit_scope`, and `MCPApplicationMiddleware` are
application-level observers. The Python audit hook now records the following
boundaries instead of silently treating them as complete:

- native extension imports (`*.so`, `*.pyd`, `*.dylib`, `*.dll`);
- `ctypes.dlopen` / `ctypes.dlsym`;
- process creation (`subprocess.Popen`, `os.system`, fork/exec/spawn);
- thread creation and `socket.connect`.

Native and process boundaries are reported as `static_binary_untraced`; thread
and socket boundaries are reported as `trace_incomplete` and
`socket_event_unbound`. These are OPAQUE markers. A direct, matching Python
read can still ground a file because that positive event exists, but the
receipt never claims that the native code's internal reads were observed.

To make a pure-computation scope explicit:

```python
from mareforma_pro import SOURCE_NOT_APPLICABLE

collector.open_scope(
    "compute-only",
    evidence_level="APPLICATION_PYTHON_AUDIT",
    read_semantics="COMPUTED_ONLY",
    source_requirement=SOURCE_NOT_APPLICABLE,
)
```

Set this only from the orchestrator's task classification. It is an application
declaration that changes the diagnostic name; it never changes the state from
OPAQUE to GROUNDED and must not be exposed as a model-controlled escape hatch.

## URL reads are explicit application evidence

A Python audit hook can see a socket connection but not the HTTP request URL or
the response bytes that arrived. After an application adapter has completed a
successful read, it can report both explicitly:

```python
from mareforma_pro import record_url_read

digest = record_url_read(
    collector,
    scope_id,
    "https://api.example.org/v1/protein?id=TP53&token=secret",
    response,
)
```

The helper removes userinfo, query strings, and fragments before signing the
URL identity, and writes a SHA-256 over the response body. This is application
evidence, not kernel network proof. A URL citation in a generic Python or MCP
scope with no such manifest is `OPAQUE(trace_incomplete)`; a dedicated
`application_http` / `URL_READ` scope with no observed URL can be
`UNGROUNDED`. External MCP responses still remain `OPAQUE(external_mcp)`.

The optional OTLP adapter is available as `mareforma-pro[otel]`; the JSONL
exporter and span projection use only the standard library.

## What stays in the application

`mareforma-pro` can expose a boundary, but it cannot know a product's task
semantics or tool protocol. The integration still owns these pieces:

- choosing `source_requirement="not_applicable"` for a genuinely computational
  task, and never letting the model set it for data work;
- calling `record_url_read()` (or forwarding `observed_urls` over the collector
  protocol) after PubMed, UniProt, PDB, URL extraction, or another HTTP call
  succeeds, including query-specific accession/search evidence;
- binding the final answer claim to the execution receipt and enforcing a
  citation policy for data-dependent answers;
- retaining signed receipts for failed executions and choosing FUSE/strace or
  a signed remote receipt when a native or remote read must be closed.
