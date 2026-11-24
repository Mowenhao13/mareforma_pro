<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/mareforma/mareforma/main/assets/mareforma-wordmark-dark.svg">
    <img alt="Mareforma" src="https://raw.githubusercontent.com/mareforma/mareforma/main/assets/mareforma-wordmark.svg" width="420">
  </picture>
</p>

<p align="center">
  <strong>Where AI discovery becomes science</strong>
  <br>
  <sub>trust earned, not declared · uses real data · effectively independent · publicly verifiable · local-first</sub>
</p>

<p align="center">
  <a href="https://docs.mareforma.com/introduction/quickstart">Quickstart</a> &nbsp;·&nbsp;
  <a href="https://docs.mareforma.com">Docs</a> &nbsp;·&nbsp;
  <a href="https://github.com/mareforma/mareforma/tree/main/examples/">Examples</a>
</p>

<p align="center">
  <a href="https://pypi.org/project/mareforma/"><img src="https://img.shields.io/pypi/v/mareforma" alt="PyPI"></a>
  <a href="https://pypi.org/project/mareforma-pro/"><img src="https://img.shields.io/pypi/v/mareforma-pro" alt="mareforma-pro PyPI"></a>
  <a href="https://pypi.org/project/mareforma/"><img src="https://img.shields.io/pypi/pyversions/mareforma" alt="Python"></a>
  <a href="https://github.com/mareforma/mareforma/actions/workflows/tests.yml"><img src="https://github.com/mareforma/mareforma/actions/workflows/tests.yml/badge.svg" alt="Tests"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
</p>

<hr>

Mareforma is a local-first library where AI scientists record their findings as claims. Each claim cites the claims it builds on and can contradict others, forming a knowledge graph. Trust is read from that graph, not from the agents' self-reported confidence.

## The silent failure it catches

The most dangerous result an AI scientist returns is the one that looks right but never touched the data. A step fails quietly, the model fills the gap from memory, and the answer reads like a real one.

Catch one yourself. You need `uv`, a local model, and a minute. Nothing to install: `uvx` fetches mareforma, runs it, and throws it away.

```bash
# a small model (0.5 GB), runs locally
ollama pull qwen3:0.6b

# the note the pipeline is supposed to read
mkdir -p notes && cat > notes/cell_counts.md <<'EOF'
# Note: cellular composition of the human brain

Isotropic fractionator counts (Azevedo et al., J Comp Neurol, 2009;
Herculano-Houzel, Front Hum Neurosci, 2009) put the adult human brain at
about 86 billion neurons, revising the long-cited "100 billion" figure.
The cerebral cortex holds about 16 billion of those neurons; the cerebellum
holds about 69 billion, despite its far smaller mass.
EOF

# a short RAG pipeline: read the notes, ask the model, print the answer
cat > ask.py <<'EOF'
import glob
import httpx

docs = [open(p).read() for p in sorted(glob.glob("notes/*.md"))]
context = "\n\n".join(docs)
question = "How many neurons are in the human brain?"

reply = httpx.post(
    "http://localhost:11434/api/chat",
    json={
        "model": "qwen3:0.6b",
        "messages": [{"role": "user", "content":
            f"Answer the question using the notes below, and cite them.\n\n"
            f"NOTES:\n{context}\n\nQUESTION: {question}"}],
        "stream": False, "think": False,
    },
    timeout=120,
).json()
print("FINDING:", reply["message"]["content"].strip())
EOF
```

Run it under the observer. `diagnose` runs your program and records every file it opens and every network call it makes; `--cites` names the file the answer should come from:

```bash
uvx mareforma diagnose --cites notes/cell_counts.md -- python ask.py
```

Mareforma prints your pipeline's answer, then its own report below it:

<pre>
FINDING: The human brain has about 86 billion neurons, as stated in the notes. [...]

  reads: 1
    [file] notes/cell_counts.md
  Grounding: GROUNDED
</pre>

It watched the process open the note and read from it, so the finding is `GROUNDED`.

Now rename the folder, which simulates the corpus not having synced, and run the exact same command as before:

```bash
mv notes notes.not-synced
uvx mareforma diagnose --cites notes/cell_counts.md -- python ask.py
```

<pre>
FINDING: The human brain contains approximately 86 billion neurons. [...] (Cite:
Russell, George P. "Neuroscience: An Introduction to the Study of the Brain," 1983)

  reads: 0
  Grounding: UNGROUNDED
</pre>

The script found no files, so it sent the model an empty blob of notes. The model answered from memory, invented a citation, and got the number right. Mareforma marks it `UNGROUNDED`.

Same command, same confident answer, both times correct. The only visible difference is `reads: 1` against `reads: 0`. Nothing else in your stack catches it: no exception, no differing log line, and re-running reproduces it. Ask the model and it says it read the notes. The verdict does not move, because it is not a guess about the text. It records what the process did at the I/O boundary.

The observer sits at the `requests`, `httpx`, `aiohttp`, `io.open`, `pandas`, and `polars` seams. The model call shows up as a socket, which buys the finding no credit: a socket cannot deliver a local file read, so absence stays trustworthy. Where it cannot see, such as duckdb running its own I/O, it returns `OPAQUE` instead of guessing.

That verdict is meant to travel with the finding. Sync the notes again, then record the claim with its computed grounding, not a label you chose:

```bash
mv notes.not-synced notes
cat > record.py <<'EOF'
import glob, httpx, mareforma
from mareforma.observe import observe

with observe(cites="notes/cell_counts.md") as obs:
    context = "\n\n".join(open(p).read() for p in sorted(glob.glob("notes/*.md")))
    reply = httpx.post("http://localhost:11434/api/chat", json={
        "model": "qwen3:0.6b", "stream": False, "think": False,
        "messages": [{"role": "user", "content":
            f"Using these notes, how many neurons are in the human brain?\n\n{context}"}],
    }, timeout=120).json()
    finding = reply["message"]["content"].strip()

claim = mareforma.open().assert_claim(
    finding,
    generated_by="agent/lab-a",
    source_name="notes/cell_counts.md",
    observed_grounding=obs.verdict.to_signed_dict(),  # computed, not declared
)
print(f"recorded claim {claim}")
print(f"grounding: {obs.verdict.grounding.value}")
EOF
uv run --with mareforma record.py
```

<pre>
recorded claim 75e4cbe5-f77a-45c0-9c00-57c065d83c90
grounding: GROUNDED
</pre>

The claim now carries `GROUNDED` as a computed fact, not a self-reported label. The same run records which model authored the finding, computed from the request that was actually sent; a local model is identified by the sha256 digest of the weights that served it, not by the name it reports. [Example 02](https://github.com/mareforma/mareforma/tree/main/examples/02_compounding_agents/) runs this catch end to end.

## Install

```bash
uv add mareforma        # core epistemic graph
uv add mareforma-pro    # upgraded observation library (brings the graph with it)
mareforma bootstrap     # optional: sign your claims and enable the public log
```

## `mareforma-pro`: the upgraded observation library

[`mareforma-pro`](https://pypi.org/project/mareforma-pro/) is an independent,
open-source Python library, with its own distribution, its own `mareforma_pro`
import package, its own `mareforma-pro` command, and its own
`mareforma-pro-vX.Y.Z` release line. Install it on its own — packaging brings
the Mareforma epistemic graph along as its engine — so one
`uv add mareforma-pro` gives you the full stack.

It is the upgrade over core `mareforma` for observation. Where the core library
observes one Python process, `mareforma-pro` extends coverage to the host and
to the process boundaries a Python audit hook cannot see: unprivileged
`strace + bwrap` and FUSE read evidence, a long-running HTTP MCP supervisor,
task-scoped worker receipts, egress and database probes, and OTel export. It
needs no `sudo`, CAP_BPF, or writable cgroup subtree, and no eBPF or Tetragon.
Build, release, and verification details are in
[Package distributions](https://docs.mareforma.com/reference/distributions).

```bash
uv add mareforma-pro
```

The published wheel filename is normalized to `mareforma_pro-*.whl`; the
distribution metadata is still `Name: mareforma-pro`, and the import is
`mareforma_pro`.

Its default route wraps a non-setuid `bwrap` command in
`strace --seccomp-bpf -f -y`, parses the syscall stream deterministically, and
signs a domain-separated HMAC receipt. It does not need eBPF or Tetragon.

```bash
python -m mareforma_pro run \
  --secret "$MAREFORMA_HMAC_SECRET" \
  --cite /data/exp42/results.csv \
  --ro-bind /data/exp42:/tmp/work \
  -- /bin/cat /tmp/work/results.csv
```

An optional FUSE route covers hosts where ptrace is unavailable (`ptrace_scope=2`
or a tool with its own conflicting seccomp policy). It uses the ordinary
`fusermount3` helper to mount a scope-specific read-only view, then binds that
view into `bwrap`. No `sudo`, ptrace, eBPF, or extra Python package is needed:

```bash
mareforma-pro run-fuse \
  --secret "$MAREFORMA_HMAC_SECRET" \
  --source /data/exp42 \
  --cite /data/exp42/results.csv \
  -- /bin/cat /tmp/mareforma-data/results.csv
```

The FUSE callback records a path in `opened_only` on open and in
`observed_files` only after a non-empty read. The original host source path is
shadowed by a tmpfs inside bwrap by default, so the mounted view is the only
route to the data. The receipt carries `coverage_roots`; a citation outside the
source root is `OPAQUE(unmapped_sandbox_path)`, not a confident `UNGROUNDED`.

The result is a `mareforma_pro.rootless_receipt/v1` receipt. The SDK verifies
the HMAC in the parent process and converts it into a normal Mareforma grounding
record:

```python
from mareforma_pro import (
    RootlessFuseRunner,
    RootlessBwrapRunner,
    RootlessCollector,
    assert_claim_from_receipt,
)

collector = RootlessCollector(secret)
result = RootlessBwrapRunner(collector).run_in_bwrap(
    ["/bin/cat", "/tmp/work/results.csv"],
    ro_binds={"/data/exp42": "/tmp/work"},
)

claim_id = assert_claim_from_receipt(
    graph,
    "The analysis read the cited results file",
    receipt=result.evidence.to_receipt_dict(),
    secret=secret,
    cites="/data/exp42/results.csv",
)
```

The FUSE runner has the same receipt bridge:

```python
fuse_run = RootlessFuseRunner(collector).run_in_bwrap(
    ["/bin/cat", "/tmp/mareforma-data/results.csv"],
    source_root="/data/exp42",
)
claim_id = assert_claim_from_receipt(
    graph,
    "The analysis read the cited results file through the FUSE view",
    receipt=fuse_run.evidence.to_receipt_dict(),
    secret=secret,
    cites="/data/exp42/results.csv",
)
```

If the graph is opened with a trusted `ReceiptVerifier`, core `assert_claim`
also accepts the full external receipt directly:

```python
from mareforma_pro import ReceiptVerifier

verifier = ReceiptVerifier(collector, cites="/data/exp42/results.csv")
with mareforma.open(project, external_grounding_verifier=verifier) as graph:
    graph.assert_claim(
        "The analysis read the cited results file",
        observed_grounding=result.evidence.to_receipt_dict(),
    )
```

The application hooks also expose the blind spots a Python audit hook cannot
close. Native extension loads, `ctypes` calls, child processes, threads, and
sockets are reported as explicit OPAQUE reasons instead of being treated as
complete observation. A pure computation can be labelled with
`source_requirement="not_applicable"` to name
`computed_no_external_source`; it remains OPAQUE and does not invent a data
source. HTTP tools can report an explicit URL read manifest with
`record_url_read(collector, scope_id, url, response)`, which strips query
credentials and signs a response digest. That is application evidence, not
kernel network proof, and external MCP responses still remain
`OPAQUE(external_mcp)`. Query-specific binding (for example the exact UniProt
accession) remains the tool adapter's responsibility; the URL identity in the
receipt deliberately omits the query so presigned secrets cannot leak.

The parser distinguishes a successful `read` from an open that was never read.
`opened_only` and `unmapped_tmpfs` are fail-closed diagnostics, not a claim that
the bytes were consumed. A complete trace with a cited read is `GROUNDED`; a
cited file opened but not read is `OPAQUE(open_only)`; an unmapped temporary
mount is `OPAQUE(unmapped_tmpfs)`; a citation outside a FUSE receipt's
`coverage_roots` is `OPAQUE(unmapped_sandbox_path)`; a tampered or unsigned
receipt is `OPAQUE(unsigned_declared)`. A graph opened without a trusted
`external_grounding_verifier` also stores a raw external receipt as
`DECLARED` / `OPAQUE(unsigned_declared)` rather than trusting its contents.

The HMAC authenticates a receipt across the process boundary; it is not a
defense against code that can read the collector secret in the parent. Keep the
secret out of the target process and launch it with `bwrap --clearenv` (the
runner's default).

A collector can emit non-authoritative scope and process spans on every
`close_scope` by passing `span_exporter=AsyncJsonlSpanExporter(...)`; the CLI
exposes the same path as `mareforma-pro serve --otel-jsonl ...`. Export failure
never changes a receipt.

Jupyter and MCP hooks use application-level Python audit events and are labelled
`APPLICATION_PYTHON_AUDIT` / `APPLICATION_MCP`. They never become eBPF evidence;
a third-party MCP response is additionally marked `external_mcp`. OTel export is
non-authoritative and cannot change a verdict.

The rootless path is not a replacement for kernel evidence when the claim needs
it: `strace` is ptrace-based, can be detected or restricted by the target, and
does not cover every read channel (for example mmap or io_uring). Use it when
the threat model accepts that boundary. A deployment that needs stronger
coverage must add a separate kernel-tracing sidecar; this package does not
silently claim that coverage.

The FUSE route has its own explicit boundary: it observes reads through the
mounted view of one source directory, not unrelated host filesystem activity.
It is not a proof that a process never read another path; it is a proof that a
cited read crossed this scope's controlled view. Keep the source root narrow
and use a stronger kernel observer when the threat model requires host-wide
coverage.

For a long-running HTTP MCP server, `mareforma-pro supervise` (0.4.0+) listens
on its own public port (default `18100`) and starts the unchanged server on
the internal loopback port (default `18000`). It streams `strace` through a
FIFO and signs per-call and per-session receipts. It adds optional
`--egress-proxy` and `--db-hook` probes without changing the server source.
Long-lived `GET /mcp` SSE and session `DELETE` requests are forwarded without
taking the serial call slot, so the official MCP SDK's notification stream
does not starve later `tools/list` requests. A POST overlapping that stream is
marked `OPAQUE(concurrent_call_overlap)`. The same limits apply: HTTPS without
a trusted MITM CA is authority level only, a pre-existing process cannot be
attached without ptrace permission, and every unobserved channel remains
`OPAQUE`.

For a long-running task worker behind such a server,
`mareforma-pro worker supervise` starts the unchanged process under the same rootless `strace` +
Python-autohook stack and signs one task-scoped receipt at each configured
task-id transition. The default task context is application-neutral:
`MAREFORMA_TASK_ID`, `MAREFORMA_EXECUTION_ID`, `MAREFORMA_ATTEMPT`, and
`MAREFORMA_ATTEMPT_DIR`. A worker that already uses other variable names is
wrapped by mapping them with `TaskContextSpec` or the `--task-id-env` CLI
options; Biomni-style names are not built into Mareforma. The receipt binds
the task/execution/attempt ids and adds `observed_http` rows (method, status,
response bytes and SHA-256, credential-free URL, query digest), DB commands
for SQLite/psycopg/Redis, and the file/temp-file read evidence. Task
receipts can now form a cryptographic two-link chain with the MCP request:
the supervisor signs the `tools/call` response's unique `task_id` into
`CallReceipt.dispatched_task_ids`, and `verify_task_chain()` checks that id
and the worker's signed `parent_scope_id` against the gateway receipt. No time
window is used. The application must still pass the request scope into the
worker; a missing parent scope, missing gateway task id, conflicting task ids,
or either bad HMAC remains `OPAQUE`, not an inferred link.

## Capabilities

| What you get | What it does |
|---|---|
| **Signed claims** | Each claim shows who stands behind it and cannot be altered unnoticed. |
| **Grounding check** | Computes whether a finding's step actually accessed the data it cites, or leaned on the model's memory, by observing the run. |
| **Trust map** | `mareforma map <claim>` shows every trust property (grounding, independence, contestation, witnessing) with how far it can be trusted, and says plainly what it cannot check. |
| **Verify** | `mareforma verify <claim>` re-checks the signatures, that the signer is enrolled, and that the grounding verdict matches the data the finding cites, with stable exit codes for CI (0 verified, 1 tampered, 2 unverifiable). |
| **Diagnose a run** | `mareforma diagnose -- python run.py` runs a target under the observer and reports what data actually flowed, and where a silent fallback hid. |
| **Audit a pipeline** | `mareforma audit --findings map.json -- python run.py` runs a pipeline that never imports mareforma and signs one grounding receipt per finding, from the observer alone. |
| **Serve a project to an agent** | `mareforma mcp serve` serves one project over the Model Context Protocol, read and verify only. Six tools to query, inspect and verify; no write path. |
| **Optional public log** | Publish a claim to a public, append-only log for an independent, timestamped record. |
| **Local-first** | Runs on local SQLite. Network only for the optional log. |

## Reading trust from the graph

Trust comes from a claim's place in the graph, never from a self-reported score. The lead signal is **effective independence**: how many checks behind a finding differ in model, data, and signer. Two agents on the same model are one line of evidence, not two, so the count holds until a check on a distinct model, or a human check, raises it. `mareforma map <claim>` reports the number and marks it `UNVERIFIABLE` when it cannot tell the models apart. When every signer traces back to one operator who could have made all the keys, it names that single trust root on the count: the number then rests on distinct model or human lines within one trust domain, not independence across operators.

Every claim carrying signed material is re-checked against its signatures on every read, so a tampered claim in a shared graph is caught when you query, not served.

Classification stays a secondary label the agent declares: `INFERRED` (model reasoning), `ANALYTICAL` (analysis run against real data), `DERIVED` (built on higher-trust claims). It is a declaration, kept honest by the computed grounding verdict above, never the trust signal on its own.

## Examples

| | Example | What it shows |
|---|---|---|
| 01 | [API Walkthrough](https://github.com/mareforma/mareforma/tree/main/examples/01_api_walkthrough/) | The full API in one runnable script |
| 02 | [Compounding Agents](https://github.com/mareforma/mareforma/tree/main/examples/02_compounding_agents/) | The absence catch and computed independence, run end to end |
| 03 | [Documented Contestation](https://github.com/mareforma/mareforma/tree/main/examples/03_documented_contestation/) | An agent challenges established consensus |
| 04 | [Private Data, Public Findings](https://github.com/mareforma/mareforma/tree/main/examples/04_private_data_public_findings/) | Two labs share how they reached a finding without sharing the data |
| 05 | [Drug Target Provenance](https://github.com/mareforma/mareforma/tree/main/examples/05_drug_target_provenance/) | A real research agent that labels which findings come from real data and which from the model's guess |
| 06 | [Verify in CI](https://github.com/mareforma/mareforma/tree/main/examples/06_ci_verify/) | `mareforma verify` as a GitHub Actions gate, keyed on exit codes |
| 07 | [Silent Failure Catch](https://github.com/mareforma/mareforma/tree/main/examples/07_silent_failure_catch/) | Two pipelines print the same number; one read the data. `pip install` plus one command, no model |

<hr>

[`AGENTS.md`](https://github.com/mareforma/mareforma/blob/main/AGENTS.md): execution contract and adapters &nbsp;·&nbsp;
[`ARCHITECTURE.md`](https://github.com/mareforma/mareforma/blob/main/ARCHITECTURE.md): system design &nbsp;·&nbsp;
[`SECURITY.md`](https://github.com/mareforma/mareforma/blob/main/SECURITY.md): threat model &nbsp;·&nbsp;
[`CONTRIBUTING.md`](https://github.com/mareforma/mareforma/blob/main/CONTRIBUTING.md): dev workflow &nbsp;·&nbsp;
[`CHANGELOG.md`](https://github.com/mareforma/mareforma/blob/main/CHANGELOG.md): releases
