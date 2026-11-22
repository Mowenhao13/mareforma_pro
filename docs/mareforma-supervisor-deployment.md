# Mareforma Supervisor 生产部署记录（2026-11-23）

## 目标拓扑

```text
远端 / 普通 MCP 客户端
        |
        | 0.0.0.0:18000
        v
mareforma-pro supervise（公开门面，签 CallReceipt）
        |
        | 127.0.0.1:18100
        v
原 Biomni MCP Server（源码未修改）
```

约束：

- 不修改 MCP Server 源码；
- 不需要 `sudo`、eBPF、cgroup 或内核模块；
- 普通用户、远端用户、未安装 `mareforma_pro` 的客户端继续访问
  `0.0.0.0:18000`；
- SSH 反向隧道 `...:18000 -> 127.0.0.1:18000` 保持不变。

## 当前验证状态

在 `omni-base@gpu3` 上已验证：

```text
biomni-mcp.service         active (running)
0.0.0.0:18000              mareforma-pro supervise
127.0.0.1:18100            mcp_server.py
initialize (127.0.0.1)     200
initialize (10.12.112.230) 200
tools/list                  10 个工具
latest_call_receipt         collector_mode=mcp_process_supervisor
8 并发普通客户端            8/8 成功，全部返回 10 个工具
官方 MCP Python SDK         initialize -> GET SSE -> tools/list -> DELETE
GET 长连接不占用 worker     tools/list 不等待 GET 关闭
```

`mareforma-pro` 从 0.4.1 起单独修复了官方 MCP SDK 的 GET SSE 长连接
兼容性；0.4.0 的普通并发修复不能替代该版本。

## 并发客户端 502 修复

切换后发现一个 Supervisor 自身的并发缺陷：

- 8 个普通客户端同时 `initialize` 时，部分请求返回
  `502 {"error": "worker already has an active call"}`；
- 根因是旧的 `WorkerPool` 使用 `queue.Queue` 管理空闲 worker，同时用
  `_reserved` 标记占用。affinity 路径取得 worker 后，worker 仍留在空闲队列里；
- 一个匿名请求随后从队列中取出同一个 worker，两个请求同时进入
  `begin_call()`，第二个请求触发 502；
- 修复后，空闲状态与 session affinity 由同一个 `Condition` 原子保护；
  worker 只有在 `_reserved=False` 时才可被任何路径取得；
- 错误处理增加 `call_started` 守卫：`begin_call()` 都没成功时，不再错误地
  `finish_call()` 另一个请求的 active call。

验证：

```text
mareforma-pro tests        91 passed
staging 8 并发客户端       8/8 成功
production 8 并发客户端    8/8 成功
所有 tools/list            200，10 个工具
```

这项修复保证普通用户和远端用户只通过 `0.0.0.0:18000` 访问时，不需要安装
`mareforma_pro`，也不会因为 Supervisor 的 worker 竞争得到 502。

## 故障根因

本次故障不是 MCP Server 源码问题，而是部署时的两个版本/时序问题。

### 1. 同版本 wheel 没有真正重装

Supervisor venv 中已存在 `mareforma-pro 0.4.0`，但它是加入
`--bind-rewrite-port` 之前的构建。安装脚本用：

```bash
pip install --upgrade mareforma_pro-0.4.0-py3-none-any.whl
```

pip 看到版本号仍是 `0.4.0`，没有覆盖已安装文件。结果：

- `supervise --help` 中没有 `--bind-rewrite-port`；
- Click 的 `ignore_unknown_options` 把该选项当成目标命令的一部分；
- `strace` 收到 `--bind-rewrite-port`，报：

```text
/usr/bin/strace: Can't stat '--bind-rewrite-port': No such file or directory
```

正确做法是强制重装并验证 CLI：

```bash
VENV=.../.state/mareforma-supervisor-venv
"$VENV/bin/python" -m pip install \
  --upgrade --force-reinstall --no-deps \
  /tmp/mareforma-pro-dist-0.4.0/mareforma_pro-0.4.0-py3-none-any.whl
"$VENV/bin/mareforma-pro" supervise --help | grep -q -- '--bind-rewrite-port'
```

更稳妥的方式是直接提升 patch 版本。当前生产使用 `mareforma-pro 0.4.1`，
wheel 路径应写为：

```text
/tmp/mareforma-pro-dist-0.4.1-final/mareforma_pro-0.4.1-py3-none-any.whl
```

### 2. 默认 ready timeout 小于 Biomni 冷启动时间

Biomni MCP Server 会扫描 `biomni.tool.*` 模块并构建 209 个函数的目录。
2026-11-23 的实测：

- 冷启动（旧进程刚退出）：约 83 秒；
- 热启动（页缓存已热）：约 31 秒。

Supervisor 默认 `--ready-timeout 30`，不足以覆盖冷启动。部署时必须显式
传入：

```text
--ready-timeout 240
```

systemd drop-in 中的验证/等待时间也应至少为 300 秒。

### 3. 恢复脚本等待时间过短

一次正常恢复中，MCP Server 在约 83 秒后才绑定 `0.0.0.0:18000`。
只看 40 秒会误判为恢复失败。恢复脚本现在应等待 300 秒再判定。

### 4. 官方 MCP SDK 的 GET SSE 长连接占用唯一 worker

0.4.0 解决了并发 `initialize` 的 worker 竞争，但官方 MCP Python SDK 在
`notifications/initialized` 之后会打开：

```text
GET /mcp
Accept: text/event-stream
```

并保持该响应打开，用于接收 server-initiated messages。0.4.0 将所有方法
都当作普通调用，GET 一直占用唯一 worker，后续同 session 的
`tools/list` 只能等待 acquire timeout，最终返回 503。

0.4.1 的处理：

- `POST /mcp`：保留串行 worker 和 `CallReceipt` 证据管线；
- `GET /mcp`：作为 SSE transport 直接转发，不占 worker 调用槽位；
- `DELETE /mcp`：作为 session termination 直接转发，并结束会话汇总；
- 使用 `HTTPResponse.read1()` 逐段转发 SSE，避免等待 64 KiB 缓冲区；
- 与 live GET 并发的 POST 标记
  `OPAQUE(concurrent_call_overlap)`，不虚构独占归因。

这不是只针对 Biomni 的补丁；标准 MCP Streamable HTTP 客户端都走同一路径。

## 生产命令

### 查看状态

```bash
systemctl --user status biomni-mcp.service --no-pager
ss -ltnp '( sport = :18000 or sport = :18100 )'
```

### 手工探针

```bash
curl -sS -i --max-time 20 \
  -X POST http://127.0.0.1:18000/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}'
```

远端地址探针：

```bash
curl -sS -i --max-time 20 \
  -X POST http://10.12.112.230:18000/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}'
```

### 官方 MCP Python SDK 探针

使用目标机 Biomni 环境已有的 `mcp` 包。探针必须跑完整生命周期，不能只测
`initialize`，因为 GET SSE 和 DELETE 发生在 initialize 之后：

```bash
/data/user/omni-base/anaconda3/envs/biomni_e1/bin/python - <<'PY'
import asyncio
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async def main():
    async with streamablehttp_client(
        "http://10.12.112.230:18000/mcp"
    ) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            print("tools", len(tools.tools))

asyncio.run(main())
PY
```

成功标志：无 503，且输出工具数量。该探针结束时 SDK 会发送
`DELETE /mcp`；Supervisor 不应因此阻塞或重置 worker。

### 安全切换

部署脚本必须：

1. 先验证原 MCP 在 `18000` 可 initialize；
2. 安装 0.4.1 wheel，并验证 `mareforma_pro.__version__ == "0.4.1"`；
3. 验证 `supervise --help` 包含 `--bind-rewrite-port`；
4. 使用 `--ready-timeout 240`；
5. 切换后同时等待 `0.0.0.0:18000` 和 `127.0.0.1:18100`，最长 300 秒；
6. 探针失败时自动移除 Supervisor drop-in、重启原服务并再次探针；
7. 不允许失败后留在 systemd 重启循环。

日常重启和恢复脚本已放在生产状态目录：

```text
/data/user/omni-base/projects/omniscientist-chat/.state/mareforma/restart-mcp-supervised.sh
/data/user/omni-base/projects/omniscientist-chat/.state/mareforma/restore-mcp-server.sh
/data/user/omni-base/projects/omniscientist-chat/.state/mareforma/cutover-mareforma-supervisor-safe.sh
```

日常重启：

```bash
/data/user/omni-base/projects/omniscientist-chat/.state/mareforma/restart-mcp-supervised.sh
```

只恢复原服务（禁用 Supervisor）：

```bash
/data/user/omni-base/projects/omniscientist-chat/.state/mareforma/restore-mcp-server.sh
```

### 回滚

```bash
UNIT=biomni-mcp.service
DROPIN="$HOME/.config/systemd/user/$UNIT.d/zzzzzzzzzzz-mareforma-supervisor.conf"
systemctl --user stop "$UNIT"
mv "$DROPIN" "$DROPIN.disabled.$(date +%Y%m%d%H%M%S)"
systemctl --user daemon-reload
systemctl --user reset-failed "$UNIT" || true
systemctl --user restart "$UNIT"
# 原服务冷启动可能需要 90 秒
```

## 观测边界

- `--bind-rewrite-port` 是 Python `socket.bind` 运行时重定向；
- 仅覆盖 IPv4、同一进程、未使用 `-S` 的 Python 服务；
- 非 Python 原生二进制、嵌套 subprocess、外部 MCP Server 仍应诚实标为
  `OPAQUE` / `not_observed`；
- `--no-strace` 只用于诊断，会留下 `OPAQUE(trace_incomplete)`；
- 当前生产已开启 `--egress-proxy` 与 `--db-hook`，并通过 `strace` 采集
  `openat` / `connect` / `write` 等事件。

## 凭据安全

`docs/omni-base登陆.md` 含明文登录密码，只用于本地操作，**不得提交**。
本机已将该文件加入 `.git/info/exclude`。不要把该文件复制进仓库、镜像、
日志或发布包。
