# AIScientist × mareforma-pro 接入修改清单

日期：2026-11-22

适用范围：

- AIScientist：`/data/user/mowh/AIScientist/OmniScientist/OmniScientist-chat`
- Mareforma Pro：`mareforma-pro >= 0.2.0`
- 目标缺口报告：`/data/user/mowh/AIScientist/OmniScientist/OmniScientist-chat/docs/mareforma-observe-gaps-20261122.md`

本文只列 **AIScientist 侧需要修改的内容**。`mareforma-pro` 侧的
`source_requirement`、`record_url_read()`、`observed_urls`、native/进程/线程/
socket 边界检测已经实现；AIScientist 不需要再次实现这些底层能力。

## 1. 先升级并收敛兼容桥

### 1.1 升级 Pro

AIScientist 应使用：

```text
mareforma-pro >= 0.2.0
```

Pro 0.2.0 对已发布的 core 0.4.0 wheel 仍保持兼容：当 core 的
`GroundingVerdict` 没有 `opaque_reasons`、`read_semantics`、`evidence_level`
三个字段时，Pro 会把诊断折叠进 verdict reason，并从 seams 恢复
`RootlessObservation.opaque_reasons`。因此 AIScientist 不再需要维护一份
过时的 `_mint_external_verdict` 副本来适配旧 core。

### 1.2 删除复制出来的 verdict 判定逻辑

当前文件：

`/data/user/mowh/AIScientist/OmniScientist/OmniScientist-chat/src/local_deep_research/provenance/mareforma_pro_adapter.py`

当前 `_mint_external_verdict()`（约 568 行）复制了 Pro 的判定逻辑，但只处理
`observed_files`，不处理 `observed_urls`、`source_requirement`、URL 引用和
external MCP 的硬边界。继续保留会再次产生两套逐渐漂移的判定规则。

建议改为直接调用 Pro 的公开函数：

```python
from mareforma_pro.observe import verdict_from_evidence


def _verified_verdict(verified, cites):
    return verdict_from_evidence(verified, cites=cites)
```

然后让 `verify_external_receipt()` 使用这个结果：

```python
def verify_external_receipt(receipt, *, secret, cites):
    verified = _verified_receipt(receipt, secret)
    return verdict_from_evidence(verified, cites=cites)
```

这样可以自动获得：

- `observed_urls` 与 URL 引用匹配；
- `source_requirement` / `computed_no_external_source`；
- native、进程、线程、socket 诊断；
- external MCP 不得被本地 URL manifest 升级为 `GROUNDED`；
- core 0.4.0 与当前 core checkout 的兼容行为。

如果短期内不想删除副本，至少必须把副本中的以下逻辑补齐：

1. `observed = observed_files + observed_urls`；
2. URL 引用在泛 application scope 中没有 manifest 时加
   `OPAQUE(trace_incomplete)`；
3. `source_requirement="not_applicable"` 时产生
   `OPAQUE(computed_no_external_source)`；
4. `external_mcp` 永远不能返回 `GROUNDED`；
5. `coverage_roots` 只检查本地路径，不检查 URL。

## 2. `_BufferedEvents` 必须保存 URL manifest

当前代码：

`/data/user/mowh/AIScientist/OmniScientist/OmniScientist-chat/src/local_deep_research/provenance/mareforma_pro_adapter.py`

`_BufferedEvents.ingest_events()` 当前通过 `**_kwargs` 静默忽略
`observed_urls`，位置约 318–357 行。

需要修改：

```python
@dataclass
class _BufferedEvents:
    observed_files: list[str] = field(default_factory=list)
    observed_urls: list[str] = field(default_factory=list)
    observed_dirs: list[str] = field(default_factory=list)
    opened_only: list[str] = field(default_factory=list)
    payload_digests: list[str] = field(default_factory=list)
    opaque_reasons: list[str] = field(default_factory=list)

    def ingest_events(
        self,
        _scope_id: str | None = None,
        *,
        observed_files: Iterable[str] = (),
        observed_urls: Iterable[str] = (),
        observed_dirs: Iterable[str] = (),
        opened_only: Iterable[str] = (),
        payload_digests: Iterable[str] = (),
        opaque_reasons: Iterable[str] = (),
        **_kwargs: Any,
    ) -> None:
        with self._lock:
            self.observed_files.extend(str(v) for v in observed_files if v)
            self.observed_urls.extend(str(v) for v in observed_urls if v)
            self.observed_dirs.extend(str(v) for v in observed_dirs if v)
            self.opened_only.extend(str(v) for v in opened_only if v)
            self.payload_digests.extend(str(v) for v in payload_digests if v)
            self.opaque_reasons.extend(str(v) for v in opaque_reasons if v)

    def payload(self) -> dict[str, list[str]]:
        with self._lock:
            return {
                "observed_files": list(dict.fromkeys(self.observed_files)),
                "observed_urls": list(dict.fromkeys(self.observed_urls)),
                "observed_dirs": list(dict.fromkeys(self.observed_dirs)),
                "opened_only": list(dict.fromkeys(self.opened_only)),
                "payload_digests": list(dict.fromkeys(self.payload_digests)),
                "opaque_reasons": list(dict.fromkeys(self.opaque_reasons)),
            }
```

验收标准：

- `_BufferedEvents.ingest_events(observed_urls=[...])` 后，
  `payload()["observed_urls"]` 存在；
- URL 经过父进程 `ingest_events` 后进入签名 receipt；
- query、userinfo、fragment 在 receipt 中被移除；
- URL 空响应进入 `opened_only`，不得变成 `GROUNDED`；
- 父进程在构造中间 `GroundingReceipt` 时，`grounded_sources` 应取
  `observed_files + observed_urls`，不能只取文件列表；如果 UI 需要展示 URL
  明细，应为 `GroundingReceipt` 增加 `observed_urls` 字段，或直接从
  `external_receipt` 读取。

## 3. 修正 URL cite 的无条件 OPAQUE

当前 `_event_reasons()` 大约在 404–422 行：

```python
if any("://" in str(cite) for cite in spec.cites):
    reasons.append(_OPAQUE_TRACE_INCOMPLETE)
```

这会把已经由 `record_url_read()` 明确举证的 URL 重新压成
`OPAQUE(trace_incomplete)`，导致本次 Pro 扩展失效。

应改为：

```python
def _event_reasons(
    spec: GroundingSpec,
    *,
    observed_urls: Iterable[str] = (),
) -> list[str]:
    reasons: list[str] = []

    # 只有在没有任何 URL manifest 时，URL 才是不可闭合的网络盲区。
    # 有 manifest 时，匹配结果由 Pro 的 verdict 逻辑决定。
    if (
        any("://" in str(cite) for cite in spec.cites)
        and not tuple(observed_urls)
    ):
        reasons.append(_OPAQUE_TRACE_INCOMPLETE)

    language = str(
        (spec.metadata or {}).get("language") or ""
    ).strip().lower()
    if language and language != "python":
        reasons.append(_OPAQUE_TRACE_INCOMPLETE)

    return list(dict.fromkeys(reasons))
```

调用处位于 `observe_with_collector()` 的 `finally` 分支，当前是：

```python
payload = buffer.payload()
payload["opaque_reasons"] = list(
    dict.fromkeys(
        (*payload["opaque_reasons"], *_event_reasons(spec))
    )
)
```

应改成：

```python
payload = buffer.payload()
payload["opaque_reasons"] = list(
    dict.fromkeys(
        (
            *payload["opaque_reasons"],
            *_event_reasons(
                spec,
                observed_urls=payload.get("observed_urls", ()),
            ),
        )
    )
)
```

最终语义必须是：

| 情况 | 期望 |
| --- | --- |
| URL cite，无 URL manifest，泛 Python/MCP/FUSE scope | `OPAQUE(trace_incomplete)` |
| URL cite，有匹配 URL manifest | `GROUNDED`，但保留 `socket_event_unbound` 等 seam 披露 |
| URL cite，有 manifest 但 URL 不匹配，专用 `application_http` / `URL_READ` scope | `UNGROUNDED` |
| 纯计算，无 cite，orchestrator 声明 `source_requirement=not_applicable` | `OPAQUE(computed_no_external_source)` |
| 外部 MCP，无论本地是否有 URL manifest | `OPAQUE(external_mcp)` |

## 4. 把 `source_requirement` 加到 GroundingSpec

`source_requirement` 不能由模型在文本中自行决定，必须由 AIScientist 的任务
分类/编排层设置。建议在：

`/data/user/mowh/AIScientist/OmniScientist/OmniScientist-chat/src/local_deep_research/provenance/mareforma_adapter.py`

为 `GroundingSpec` 增加字段：

```python
@dataclass(frozen=True, slots=True)
class GroundingSpec:
    ...
    claim_without_cites: bool = False
    source_requirement: str = "required"
    ...
```

并同步：

- `to_dict()`；
- `from_dict()`；
- `GroundingSpec.from_dict()` 的默认值校验；
- Provider 构造 `GroundingSpec` 的所有调用点。

建议校验值：

```python
if self.source_requirement not in {"required", "not_applicable"}:
    raise ValueError("invalid source_requirement")
```

然后在 `observe_with_collector()` 的 registration 中传入：

```python
registration = {
    "op": "open_scope",
    "scope_id": scope_id,
    "root_passthrough": True,
    "traceparent": traceparent,
    "parent_scope_id": spec.parent_scope_id or None,
    "evidence_level": "APPLICATION_PYTHON_AUDIT",
    "read_semantics": "COMPUTED_ONLY" if spec.source_requirement == "not_applicable"
                       else "OPEN_INTENT",
    "collector_mode": "application_python_audit",
    "source_requirement": spec.source_requirement,
}
```

当前 registration 位于约 454–467 行，尚未传这个字段。

只在确认是纯计算任务时设置 `not_applicable`，例如：

- 只做数学计算、拟合、派生指标、格式化；
- 没有查询外部数据库、URL、实验数据或文件；
- 计算输入来自本次任务文本或已绑定 claim，而不是新的外部数据读取。

不能因为“没有派生 cite”就自动设置 `not_applicable`。数据依赖任务没有 cite
仍然应是 `OPAQUE(no_cited_source)`。

## 5. 外部工具必须产生 URL manifest

### 5.1 推荐的总入口

AIScientist 当前在 worker/child 中通过 `observe_with_collector()` 使用
`_BufferedEvents` 作为 `audit_scope` 的 collector。工具代码在同一个 Python
进程内执行，因此工具适配层可以在 HTTP 成功后写入同一个 buffer。

建议在 `mareforma_pro_adapter.py` 增加一个 context-local 的 scope 句柄：

```python
from contextvars import ContextVar

_ACTIVE_PRO_SCOPE: ContextVar[tuple[Any, str] | None] = ContextVar(
    "omniscientist_pro_scope",
    default=None,
)
```

在 `observe_with_collector()` 的 `with audit_scope(...)` 内设置和恢复：

```python
token = _ACTIVE_PRO_SCOPE.set((buffer, scope_id))
try:
    with audit_scope(buffer, scope_id):
        output = fn()
finally:
    _ACTIVE_PRO_SCOPE.reset(token)
```

再提供：

```python
def record_current_url_read(url: str, response: Any) -> str | None:
    active = _ACTIVE_PRO_SCOPE.get()
    if active is None:
        return None
    collector, scope_id = active
    try:
        from mareforma_pro import record_url_read
        return record_url_read(collector, scope_id, url, response)
    except Exception:
        # provenance 不能替换科学工具结果；由外层保留 trace_incomplete
        return None
```

工具适配层在收到成功响应后调用：

```python
from local_deep_research.provenance.mareforma_pro_adapter import (
    record_current_url_read,
)

digest = record_current_url_read(final_url, response)
```

注意：

- 只在 HTTP 请求成功并且已经拿到响应后调用；
- 不要把失败请求记成 URL 读取；
- 不要把流式 response 的 `.read()` 消费掉；必要时传已计算的
  `digest=`，并明确 `nonempty=`；
- `record_url_read()` 会移除 userinfo、query、fragment；
- 需要区分 accession/search term 时，把结构化查询信息写入
  `GroundingSpec.metadata` 或 claim evidence，不要放回 URL 的 query 中。

### 5.2 必须接入的工具清单

至少覆盖缺口报告中的以下工具：

- `biomedical.tool.literature.query_pubmed`
- `biomedical.tool.literature.extract_url_content`
- `biomedical.tool.database.query_uniprot`
- `biomedical.tool.database.query_pdb`
- `biomedical.tool.database.query_pdb_identifiers`
- `biomedical.tool.database.query_pdb_target_ligand_structures`

另外需要检查所有通过 `httpx`、`requests`、`urllib` 或 MCP 客户端发起的读取
路径。AIScientist 现有的 UniProt recovery 路径
`execution/biomni/uniprot_read_recovery.py` 已经直接使用 `httpx`，它是优先
接入点之一。

### 5.3 查询语义的绑定

`record_url_read()` 签名的 URL identity 会故意去掉 query。因此以下信息不能
只依赖 URL：

- UniProt accession；
- PDB ID / ligand ID；
- PubMed PMID 或检索式；
- 页面标题或 API 查询参数。

建议在 claim evidence 中保存经过白名单筛选的结构化字段，例如：

```python
metadata = {
    "source_query": {
        "accession": "P04637",
        "endpoint": "uniprot",
    }
}
```

禁止把 token、Cookie、Authorization、预签名 query 写入 claim evidence。

## 6. 父进程验证与失败执行

`finalize_collector_receipt()` 应该保留 raw receipt，并用 Pro 0.2.0 的直接
`verdict_from_evidence()` 生成 verdict。重点检查：

1. URL manifest 已进入 `GroundingReceipt.grounded_sources`；
2. 失败执行仍把 child 写入的 `mareforma_receipt` 交给父进程；
3. `status="failed"` 不会被去掉执行 claim；
4. `raw_receipt` 中已有 `opaque_reasons` 时，不能再无条件追加 URL
   `trace_incomplete`；
5. `external_receipt` 校验失败时仍写入 `OPAQUE(unsigned_declared)`，不得
   回退为 `GROUNDED`。

当前 `observe_with_collector()` 的失败路径已经会把
`body_error.mareforma_receipt` 返回给上层；需要确认所有调用
`run_observed()` / worker 的 catch 分支都持久化这个 receipt，而不是只保存
错误字符串。

中间 receipt 中目前有一处只写文件来源：

```python
grounded_sources=tuple(raw_receipt.get("observed_files") or ())
```

应改为至少等价于：

```python
grounded_sources=tuple(
    dict.fromkeys(
        (*raw_receipt.get("observed_files", ()),
         *raw_receipt.get("observed_urls", ()))
    )
)
```

## 7. Shell / R / native 与残留盲区

这些不是 `mareforma-pro` Python audit hook 能单独闭合的：

- shell / Bash / R / 外部解释器；
- 已经预先加载的 native extension 内部读取；
- native 二进制内部的 `openat`；
- raw socket 里的协议内容；
- 外部不可控 MCP server 内部读取。

AIScientist 侧需要选择：

1. 将 shell/R/code-run 接入 `RootlessBwrapRunner` 或 FUSE runner；
2. 让 native 工具返回输入文件、输出文件和 digest，由父进程生成 read
   manifest；
3. 对不可控远端接受 `OPAQUE`，并要求远端提供签名 receipt；
4. 不能把 `static_binary_untraced`、`socket_event_unbound` 或
   `external_mcp` 显示成已验证。

## 8. Answer claim 强制绑定

Case 06 / Case 26 的问题不在 execution claim，而在最终答案没有 answer
claim。需要在答案生成/发布层增加：

- 数据依赖型答案至少携带一个 citation；
- citation 能解析到 execution claim；
- execution claim 的 `grounding`、`opaque_reasons` 和 `receipt_digest` 一并
  保留；
- answer claim 使用 `classification="DERIVED"`，并支持对应
  execution claim；
- citation 无法绑定时显示 `not_observed`，不能把具体数值、ID、数据库字段
  当成已验证事实直接发布。

当前实现入口：

- `/data/user/mowh/AIScientist/OmniScientist/OmniScientist-chat/src/local_deep_research/provenance/answer_claims.py`
- `/data/user/mowh/AIScientist/OmniScientist/OmniScientist-chat/src/local_deep_research/products/chat_lifecycle.py`

建议把 answer claim 状态写入最终 delivery summary，而不只是写入内部 durable
state。Case 06 和 Case 26 应增加回归测试。

## 9. AIScientist 侧测试清单

至少增加以下测试：

1. `_BufferedEvents` 的 `observed_urls` round-trip；
2. 有 URL manifest 时不再无条件添加 `trace_incomplete`；
3. URL manifest 的 query/userinfo 不出现在 receipt；
4. 纯计算任务的 `source_requirement="not_applicable"`；
5. 数据任务默认 `required`，无 cite 时仍是 `no_cited_source`；
6. external MCP 即使带本地 URL manifest 也保持 `external_mcp`；
7. 失败执行保留签名 receipt；
8. answer claim 对 Case 06 / Case 26 的绑定行为；
9. shell/R 路径保持 `trace_incomplete`，除非改为 runner；
10. 预先加载 native 或 raw socket 场景仍然 OPAQUE。

建议同时保留现有测试：

```bash
cd /data/user/mowh/AIScientist/OmniScientist/OmniScientist-chat
.venv/bin/python -m pytest tests/provenance/test_mareforma_pro_adapter.py
```

## 10. 完成定义

AIScientist 侧修改可以认为完成，当且仅当：

- `mareforma-pro>=0.2.0` 是实际运行版本；
- URL 工具成功响应后有 `observed_urls`；
- URL cite 与 manifest 能匹配，且 query 信息单独进入 claim evidence；
- 纯计算和数据依赖型任务使用不同的 `source_requirement`；
- 无 manifest 的 URL 仍然 OPAQUE，而不是 UNGROUNDED；
- external MCP 保持 OPAQUE；
- 失败执行保留 receipt；
- 数据依赖型最终答案有 answer claim；
- shell/R、native、raw socket 的残留盲区在 UI/报告中明确展示。

## 11. 参考文件

AIScientist：

- `/data/user/mowh/AIScientist/OmniScientist/OmniScientist-chat/src/local_deep_research/provenance/mareforma_pro_adapter.py`
- `/data/user/mowh/AIScientist/OmniScientist/OmniScientist-chat/src/local_deep_research/provenance/mareforma_adapter.py`
- `/data/user/mowh/AIScientist/OmniScientist/OmniScientist-chat/src/local_deep_research/provenance/answer_claims.py`
- `/data/user/mowh/AIScientist/OmniScientist/OmniScientist-chat/src/local_deep_research/execution/biomni/tool_child.py`
- `/data/user/mowh/AIScientist/OmniScientist/OmniScientist-chat/src/local_deep_research/execution/biomni/uniprot_read_recovery.py`
- `/data/user/mowh/AIScientist/OmniScientist/OmniScientist-chat/src/local_deep_research/execution/code/mareforma_runner.py`

Mareforma Pro：

- `/data/user/mowh/mareforma/mareforma-pro/src/mareforma_pro/http.py`
- `/data/user/mowh/mareforma/mareforma-pro/src/mareforma_pro/jupyter.py`
- `/data/user/mowh/mareforma/mareforma-pro/src/mareforma_pro/observe.py`
- `/data/user/mowh/mareforma/mareforma-pro/src/mareforma_pro/evidence.py`

缺口报告：

- `/data/user/mowh/AIScientist/OmniScientist/OmniScientist-chat/docs/mareforma-observe-gaps-20261122.md`
