![Mareforma Pro](https://raw.githubusercontent.com/Mowenhao13/mareforma_pro/main/assets/mareforma-pro-wordmark.svg)

# mareforma-pro

`mareforma-pro` is an independent, open-source Python library and the upgraded
observation stack for [Mareforma](https://github.com/mareforma/mareforma). It
has its own distribution, its own `mareforma_pro` import package, its own
`mareforma-pro` command, and its own version and release line. Install it on
its own: packaging brings the Mareforma epistemic graph along as its engine, so
one command gives you the full stack.

```bash
uv add mareforma-pro
```

Compared with core `mareforma`, `mareforma-pro` upgrades observation from a
single Python process to the host and to the boundaries a Python audit hook
cannot see: unprivileged `strace + bwrap` and FUSE read evidence, a long-running
HTTP MCP supervisor, task-scoped worker receipts, egress and database probes,
and OTel export. It needs no `sudo`, CAP_BPF, or writable cgroup subtree.
`mareforma-pro` is MIT-licensed.

`mareforma-pro` is versioned and released independently: releases use the
`mareforma-pro-vX.Y.Z` tag namespace and publish only this project. Core
`mareforma` releases keep the `vX.Y.Z` tag namespace.

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

## Long-running MCP supervisor (0.4.0+)

The `supervise` command adds a long-running, no-sudo observation path for an
HTTP MCP server. The supervisor listens on public port `18100`; the unchanged
server keeps listening on its fixed internal port `18000`. Requests are
serialized per internal process so process events can be attributed to one
call. Point MCP clients at the supervisor port, not directly at `18000`.

```bash
MAREFORMA_HMAC_SECRET='replace-with-a-private-secret' \
mareforma-pro supervise \
  --port 18100 --internal-port 18000 --workers 1 \
  --egress-proxy --db-hook \
  -- /path/to/server-venv/bin/python /path/to/mcp_server.py
```

Use `--workers 1` when the server hard-codes `18000`: only one process can own
that port. For a server that accepts a port argument, pass
`--port '{internal_port}'` or change `--internal-port` to a free base port and
allow additional workers.

The supervisor also injects loopback `HOST` / `MCP_HOST` / `UVICORN_HOST` /
`MCP_SERVER_HOST` values together with the internal port environment variables.
If the server reads its bind host from a fixed config file, change that config
to `127.0.0.1`; otherwise port `18000` may remain directly reachable and bypass
the receipt boundary.

### Keep the remote endpoint on port 18000

Linux permits the same port on different local addresses. To leave remote MCP
clients unchanged, bind the original server to loopback and the Supervisor to
the concrete local address those clients already use:

```bash
mareforma-pro supervise \
  --host 10.12.112.230 --port 18000 \
  --internal-port 18000 \
  --workers 1 --egress-proxy --db-hook \
  -- /path/to/server-venv/bin/python /path/to/mcp_server.py
```

Remote clients continue using `http://10.12.112.230:18000`. The child must be
loopback-only at `127.0.0.1:18000`; `--host 0.0.0.0` is rejected in this mode
because a wildcard bind would conflict with the loopback listener. Local
clients that explicitly connect to `127.0.0.1:18000` still reach the child and
bypass the Supervisor, so local clients should use the external address too.

### Preserve a wildcard 0.0.0.0 listener

If the Python server hard-codes `0.0.0.0:18000` and that endpoint must remain
unchanged, let the Supervisor own the wildcard socket and redirect the child's
fixed `bind()` at runtime:

```bash
mareforma-pro supervise \
  --host 0.0.0.0 --port 18000 \
  --internal-port 18100 \
  --bind-rewrite-port 18000 \
  --workers 1 --egress-proxy --db-hook \
  -- /path/to/server-venv/bin/python /path/to/mcp_server.py
```

The autohook rewrites only an IPv4 `bind()` whose port is exactly `18000`, to
`127.0.0.1:18100`. All inbound clients keep using port `18000`, including the
loopback target of an SSH reverse tunnel. A non-Python server, a server started
with Python `-S`, or a server whose bind bypasses Python's socket module still
requires a configurable port or a separate network boundary.

Large MCP servers may spend a minute or more importing their tool catalog. Pass
`--ready-timeout 240` or higher for those servers; the default 30 seconds is
the time allowed before the supervisor declares the worker failed.

The supervisor writes HMAC-signed `CallReceipt` records to
`~/.mareforma/mcp-receipts.jsonl` by default and emits a `SessionReceipt` when
the MCP session goes idle or the supervisor stops. The optional
`--otel-jsonl` path exports non-authoritative `mareforma.mcp.call` and
`mareforma.mcp.session` spans.

Concurrent clients are safe by design: an idle worker is reserved atomically,
a session stays pinned to its worker, and other clients queue for an available
worker instead of sharing one. A regression test covers 8 concurrent plain
clients; each receives `tools/list` with the expected catalog and no client
needs the `mareforma_pro` package installed.

The official MCP Python SDK opens a long-lived `GET /mcp` SSE stream after
`notifications/initialized`. `GET` and `DELETE` are forwarded as transport and
session operations without taking the serialized call slot; otherwise the only
worker would stay reserved until the client closed that stream and the next
`tools/list` would return 503. A POST that overlaps a live GET is marked
`OPAQUE(concurrent_call_overlap)`, because process events are not attributable
to one request while both are in flight. SSE bytes are forwarded as they
arrive rather than buffered until a full read.

What the new transport adds:

- a FIFO-fed `strace --seccomp-bpf -f -yy` stream with a quiet drain barrier;
- `openat`/read evidence and `internal_temp_files` for files written and then
  read by the same call/session;
- `connect()` endpoint baselines and an optional local egress proxy;
- a Python `sitecustomize.py` autohook for HTTP response digests and DB
  commands (SQLite, psycopg/psycopg2, and Redis) when `--db-hook` is enabled;
- explicit `concurrent_call_overlap`, `egress_proxy_bypassed`,
  `egress_uninspected`, `db_uninspected`, and `https_path_opaque` diagnostics.

This remains a user-space observation boundary. HTTPS proxy mode reports only
the CONNECT authority and marks `https_path_opaque` unless a trusted local
MITM CA is later supplied. The Python autohook currently covers SQLite and
the patched `urllib`/`requests`/`httpx` surfaces; other DB drivers and native
children require the generic proxy/strace path or a separate adapter. A
shared long-running server process that is not started under this supervisor
cannot be ptraced by a no-sudo user after the fact.

## Task-scoped worker supervisor (0.5.0+)

A second long-running path covers the worker process that executes queued tool
tasks. It starts the unchanged worker as a child of `strace`, injects the
Python autohook through `PYTHONPATH`, and signs one
`mareforma_pro.rootless_receipt/v1` per task:

```bash
MAREFORMA_HMAC_SECRET='replace-with-a-private-secret' \
mareforma-pro worker supervise \
  --worker-id 1 \
  --receipt-log ~/.mareforma/worker-1-receipts.jsonl \
  --coverage-root /srv/tasks \
  -- /path/to/worker-venv/bin/python /path/to/worker.py --worker-id 1
```

The observer must own the process launch; it cannot attach to an
already-running systemd unit. Replace the unit's `ExecStart` with the command
above. The child environment never receives `MAREFORMA_HMAC_SECRET`,
`MAREFORMA_PRO_SECRET`, or `MAREFORMA_SECRET`; only the parent signs receipts.

Task boundaries come from transitions of the configured task-id environment
variable. The defaults are generic: `MAREFORMA_TASK_ID`,
`MAREFORMA_EXECUTION_ID`, `MAREFORMA_ATTEMPT`, and
`MAREFORMA_ATTEMPT_DIR`. An unchanged worker that already uses its own names is
mapped explicitly, for example:

```bash
mareforma-pro worker supervise \
  --task-id-env MY_TASK_ID \
  --execution-id-env MY_EXECUTION_ID \
  --attempt-dir-env MY_ATTEMPT_DIR \
  -- /path/to/worker-venv/bin/python /path/to/worker.py
```

The names are application configuration, not built-in Mareforma semantics.
`strace -ttt` timestamps are checked against those boundaries, so a FIFO line
that arrives late is charged to the task active when the syscall completed, not
to whichever task is active when the parser wakes up. A child Python process
inherits the current task id and its application events remain in that task,
but it cannot open or close a second task scope. No worker source change is
required when the worker already exposes a task-id variable.

Each receipt adds optional `task_id`, `worker_id`, `execution_id`, `attempt`,
and `read_bytes` fields. It also carries:

- `observed_files`, `opened_only`, `internal_temp_files`, and
  `unmapped_paths` from the kernel-level `strace` stream;
- `observed_http` rows containing a credential-free URL, method, status,
  response-body byte count, response SHA-256, query digest, and query key
  names for `urllib`, `requests`, and `httpx` calls observed before TLS;
- `observed_db_queries` from `sqlite3`, `psycopg`, `psycopg2`, and `redis`,
  including SQL text by default (disable with `--no-db-query-text`);
- `observed_urls`, `observed_egress_urls`, `payload_digests`, and the normal
  OPAQUE diagnostics.

An unconsumed streaming response or a body that cannot be observed adds
`OPAQUE(http_body_unobserved)`. Query values are omitted by default because
presigned URLs commonly carry credentials; `--http-query-text` opts into the
plaintext query and is not recommended for signed receipts. `--no-strace` is a
diagnostic mode and always adds `OPAQUE(trace_incomplete)`.

### Two-link MCP-to-worker parent binding (0.6.0+)

The supervisor and worker now sign the two halves of a parent link. For a
successful MCP `tools/call`, the supervisor extracts one `task_id` from
`result.task_id`, `result.structuredContent.task_id`, or a JSON object in
`result.content[*].text`, then signs it into
`CallReceipt.dispatched_task_ids`. The worker signs `task_id` and the parent
scope it received through its configured parent-scope environment variable.

```python
from mareforma_pro import verify_task_chain

verdict = verify_task_chain(call_receipt, worker_receipt, secret)
if verdict.linked:
    # WorkerReceipt.parent_scope_id == CallReceipt.scope_id
    # and WorkerReceipt.task_id is in CallReceipt.dispatched_task_ids.
    parent_scope = verdict.call_scope_id
```

`verify_task_chain()` verifies both HMACs before comparing either id. Pass
`worker_secret=` when the worker collector uses a different secret. Matching
does not use `started_at`, `closed_at`, or any time window. The application
still has to propagate the MCP request's `scope_id` into the worker as
`MAREFORMA_PARENT_SCOPE_ID` (or the configured `--parent-scope-id-env`); without
that signed parent field, the result remains an explicit non-link. A response
with zero or multiple distinct task ids also contributes no id. Treat every
status other than `LINKED` as `OPAQUE`; never upgrade a missing half from
`task_id`/`request_id`/`execution_id` correlation alone.

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
