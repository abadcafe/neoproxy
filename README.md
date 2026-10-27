# neoproxy

一个高性能转发代理服务器，支持 HTTP/1.1、HTTPS、HTTP/3 (QUIC) 和 SOCKS5 协议。

## 功能概览

| 组件 | 类型 | 名称 | 说明 |
|------|------|------|------|
| Listener | `http` | HTTP/1.1 监听器，支持 CONNECT 方法和 Host 头路由 |
| Listener | `https` | HTTPS (HTTP/1.1 over TLS) 监听器，支持 SNI 证书选择和客户端证书认证 |
| Listener | `http3` | HTTP/3 (QUIC) 监听器 |
| Listener | `socks5` | SOCKS5 监听器，支持用户名/密码认证 |
| Service | `http_upstream.upstream` | 统一代理服务，支持直连模式（连接目标）和链式模式（通过上游代理） |
| Service | `echo` | 回显服务（测试用） |
| Layer | `auth.basic_auth` | HTTP Basic 代理认证层 |
| Layer | `access_log.file` | 访问日志层，支持多 writer、缓冲写入、文件轮转 |

## 快速开始

### 环境要求

- Rust 1.88 或更高版本（Rust 2024 edition，使用 let chains）

### 编译

```bash
cargo build --release
```

### 运行

```bash
./target/release/neoproxy --config conf/example.yaml
```

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-c, --config <FILE>` | 配置文件路径 | `conf/server.yaml` |
| `-v, --version` | 显示版本号 | - |

## 配置文件结构

```yaml
# 工作线程数（默认: 4）
server_threads: 4

# 全局插件配置
plugins:
  <plugin_name>:
    # 插件特定参数

# 监听器定义（全局，被 servers 引用）
listeners:
  - name: <监听器名称>
    kind: <监听器类型>     # http / https / http3 / socks5
    addresses: ["host:port"]
    args:
      # 监听器特定参数

# 服务定义
services:
  - name: <服务名称>
    kind: <插件名>.<服务名>
    args:
      # 服务特定参数
    layers:                  # 可选中间件层
      - kind: <插件名>.<层名>
        args:
          # 层特定参数

# 服务器定义（关联服务和监听器）
servers:
  - name: <服务器名称>
    hostnames: []            # 可选虚拟主机名
    tls:                     # 可选 TLS 配置
      certificates:
        - cert_path: <路径>
          key_path: <路径>
      client_ca_certs: []    # 默认空列表，不要求客户端证书；非空启用 mTLS
    listeners:
      - <引用监听器名称>
    service: <引用的服务名称>
```

> neoproxy 在启动时验证配置文件，检测地址冲突、证书等配置错误，并在日志中详细报告。

---

## 全局插件配置

### 1. access_log 插件

访问日志插件，支持多 writer、缓冲写入、文本/JSON 格式、文件大小和日期轮转。

```yaml
plugins:
  access_log:
    writers:
      - path_prefix: "logs/access.log"   # 文件路径前缀
        buffer_capacity: "32KiB"         # 触发刷新的缓冲区大小（默认: 32KiB）
        max_buffer_size: "128KiB"        # 最大缓冲区，满时丢弃（默认: 128KiB）
        flush_interval: "1s"             # 最大刷新间隔（默认: 1s）
        max_file_size: "200MiB"          # 文件大小轮转阈值（默认: 200MiB）
        rotate_daily: true               # 按进程本地日期轮转（默认: true）
        format: "text"                   # 日志格式: text / json（默认: text）
```

轮转在有缓冲日志需要 flush 时检查：开启 `rotate_daily` 后，跨进程本地日期或已有文件达到 `max_file_size`，任一条件满足即切换文件。本地日期遵循运行环境时区及夏令时规则；大小是轮转阈值，一次缓冲写入可以超过阈值，下次 flush 再归档。编号在 writer 内递增缓存，重启或切换日期后重新寻找未占用的编号，已有归档不会被覆盖。

`flush_interval` 由日志接收线程统一计时。缓冲区达到大小阈值提前刷新后，下一次定时刷新仍按期执行；持续收到日志也不会重置这个时限。空缓冲区的定时刷新不执行文件写入。

### 2. http_upstream 插件

统一代理插件，定义上游代理池和直连配置。支持三级继承配置：**Plugin → Upstream → Address**。
低层级覆盖高层级同名参数。`upstream_request_timeout` 按插件、upstream、address 三级继承；链式请求使用调度选中地址的超时。链式地址通过 `address_protocol: http`、`address_protocol: https` 或 `address_protocol: http3` 选择单一协议；`address_protocol` 支持三级继承，默认 `https`。TCP keepalive 的三个字段均已生效，省略时保持系统默认；配置任一项即启用 TCP keepalive。

**直连模式**：upstream 不配置 `addresses`，代理直接连接目标服务器。
**链式模式**：upstream 配置 `addresses`，代理通过上游代理服务器转发。

```yaml
plugins:
  http_upstream:
    certificates:                          # TLS 配置（链式模式需要）
      server_ca_path: conf/certs/server-ca.crt
      client_cert_path: conf/certs/client.crt
      client_key_path: conf/certs/client.key
    dns_servers: null                 # 仅插件级；未配置时读取系统 DNS 服务器
    dns_resolve_timeout: 5s            # 仅插件级
    dns_refresh_retry_interval: 30s    # 仅插件级；刷新失败后重试间隔
    address_protocol: https           # 三级继承；direct 普通请求由 URL scheme 决定
    address_max_fails: 1               # 三级继承；0 禁用被动失败摘除
    address_fail_timeout: 10s          # 三级继承；失败统计及摘除时长
    tcp_keep_alive_time: null          # 三级继承；开始探测前的空闲时间
    tcp_keep_alive_interval: null      # 三级继承；探测间隔
    tcp_keep_alive_retries: null       # 三级继承；探测重试次数
    upstream_request_timeout: 30s      # 每次上游尝试收到响应头/完成 CONNECT 的时限
    tunnel_idle_timeout: 60s           # 插件级默认配置
    tcp_connect_timeout: 10s
    tls_handshake_timeout: 5s
    quic_connection_connect_timeout: 10s
    quic_connection_keep_alive_interval: "3s"
    upstreams:
      # 直连模式（无 addresses）
      - name: direct
        tunnel_idle_timeout: 60s
        tcp_connect_timeout: 10s
        pool:
          max_idle_per_host: 32            # 连接池最大空闲连接数（默认: 32）
          idle_timeout: 90s                # 连接池空闲超时（默认: 90s）

      # 链式模式（有 addresses）
      - name: remote_relay
        tunnel_idle_timeout: 60s
        quic_connection_keep_alive_interval: "5s"
        addresses:
          - address: "host:port"           # 上游代理地址
            hostname: "sni.example.com"    # 连接上游时使用的 SNI（需匹配上游证书 SAN）
            weight: 1                      # 负载均衡权重
            address_protocol: http                 # http、https 或 http3
```

---

## Listener 详解

HTTP、HTTPS、HTTP/3 使用 `args.header_read_timeout` 限制请求头读取时间（默认 `30s`，必须为正且可表示的时长）。HTTP/3 超时只取消对应请求流，其他流继续处理。

HTTP、HTTPS、SOCKS5 共用 TCP accept 恢复策略：连接中止、信号中断及待接收连接的网络错误立即继续，不做定时退避；文件描述符或内存资源耗尽时记 ERROR 日志，并按 `args.accept_retry_delay` 退避后重试（默认 `1s`）。监听描述符无效、不是 socket 或已不处于监听状态时，返回原始错误，由监督层停止服务并以非零状态退出。其他未知 I/O 错误记 ERROR 并退避，避免忙循环；所有等待均可被 shutdown 打断。

### 1. http (HTTP/1.1)

HTTP/1.1 监听器，支持 CONNECT 方法和基于 Host 头的虚拟主机路由。

#### 请求校验

收到请求后按以下顺序校验：

1. 支持 HTTP/1.0 和 HTTP/1.1；HTTP/1.1 必须恰好有一个合法 Host 字段。
2. 绝对 URI 和 CONNECT 使用目标 authority 路由；普通 origin-form 请求使用 Host。HTTP/1 绝对 URI 中的 authority 优先于 Host，转发时重新生成 Host。
3. 重复 Host、非法 authority 返回 `400 Bad Request`；没有可确定 authority 的请求也返回 400。
4. `args.header_read_timeout` 默认为 `30s`，限制请求头读取时间。

#### 配置参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `addresses` | `[String]` | 是 | 监听地址列表，格式 `host:port` |
| `header_read_timeout` | `Duration` | 否 | HTTP/1 请求头读取超时，默认 `30s` |
| `accept_retry_delay` | `Duration` | 否 | accept 资源耗尽或未知 I/O 错误后的重试退避，默认 `1s`；必须大于零且能安全计时 |

#### 配置示例

```yaml
listeners:
  - name: http_main
    kind: http
    addresses:
      - "0.0.0.0:8080"
    args:
      accept_retry_delay: "1s"
```

#### 使用方式

```bash
curl --proxy http://127.0.0.1:8080 https://example.com
```

---

### 2. https (HTTPS)

HTTPS (HTTP/1.1 over TLS) 监听器，支持 SNI 证书选择和客户端证书认证。

#### 请求校验

收到请求后按以下顺序校验：

1. HTTP 路由和 Host 校验遵循上述 HTTP 规则。
2. TLS 握手并发进行，不阻塞其他客户端连接。
3. SNI 在当前 listener 的关联 Server 中按 `hostnames` 选择 Server，再选择该 Server 的证书；无 SNI 或未匹配时使用唯一的 `hostnames: []` 默认 Server，没有默认 Server 或选中 Server 没有兼容证书则握手失败。客户端 CA 仍由关联 Server 向 listener 汇总：提交的客户端证书在 TLS 握手中使用 CA 并集验证，不可信则握手失败；允许匿名握手。请求阶段按目标 authority/Host 在同一 listener 内另行选择 Server；其 `client_ca_certs` 非空但连接未提供证书时，由 listener 直接返回 `403 Forbidden`。Service 不重验证书，不要求请求目标等于 SNI。
4. `args.header_read_timeout` 默认为 `30s`，独立于 TLS 握手超时。

#### 配置参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `addresses` | `[String]` | 是 | - | 监听地址列表 |
| `tls_handshake_timeout` | `Duration` | 否 | `5s` | TLS 握手超时，防止慢客户端占用连接 |
| `header_read_timeout` | `Duration` | 否 | `30s` | HTTP/1 请求头读取超时 |
| `accept_retry_delay` | `Duration` | 否 | `1s` | accept 资源耗尽或未知 I/O 错误后的重试退避，必须大于零且能安全计时 |

TLS 证书在服务器（Server）级别配置，多个服务器可以共享同一监听器地址，通过 SNI 区分证书。

#### 配置示例

```yaml
listeners:
  - name: https_main
    kind: https
    addresses: ["0.0.0.0:8443"]
    args:
      tls_handshake_timeout: "5s"
      accept_retry_delay: "1s"

servers:
  - name: my_server
    tls:
      certificates:
        - cert_path: /path/to/cert.pem
          key_path: /path/to/key.pem
      client_ca_certs:         # 可选，用于 mTLS
        - /path/to/client-ca.crt
    listeners:
      - https_main
    service: tunnel
```

#### 使用方式

```bash
curl --proxy https://proxy.example.com:8443 \
     --proxy-cacert /path/to/ca.crt \
     --proxy-cert /path/to/client.crt \
     --proxy-key /path/to/client.key \
     https://httpbin.org/ip
```

---

### 3. http3 (HTTP/3)

HTTP/3 (QUIC) 监听器，提供更快的连接建立和更好的弱网表现。

每个 worker 独立持有 UDP socket 和 QUIC Endpoint，通过 `SO_REUSEPORT` 绑定同一监听地址；收包和连接驱动运行在所属 worker 上。禁用连接迁移，客户端地址或端口变化后不保证原连接继续可用，与 TCP 一样需要重新建连。

#### 请求校验

收到请求后按以下顺序校验：

1. **authority 检查** — 普通请求允许通过 `:authority` 或 Host 提供 authority；CONNECT 必须提供目标 host:port
2. **Host 一致性** — 若 Host 头存在，必须与 `:authority` 一致，不一致返回 `400 Bad Request`
3. **路由** — 根据 `:authority` 的 host 部分匹配服务器
4. **认证** — 通过 Service 的中间件层处理（如 `auth.basic_auth`）

#### 配置参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `addresses` | `[String]` | 是 | 监听地址列表 |
| `quic` | `Object` | 否 | QUIC 协议参数 |

#### QUIC 参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `max_concurrent_bidi_streams` | `u64` | 100 | 最大并发双向流 (1-10000) |
| `max_idle_timeout` | `Duration` | `5s` | 最大空闲超时 |
| `initial_mtu` | `u16` | 1200 | 初始 MTU (1200-9000) |
| `send_window` | `Byte` | `10MiB` | 发送窗口大小 |
| `receive_window` | `Byte` | `10MiB` | 接收窗口大小 |

#### 配置示例

```yaml
listeners:
  - name: http3_main
    kind: http3
    addresses: ["0.0.0.0:443"]
    args:
      quic:
        max_concurrent_bidi_streams: 100
        max_idle_timeout: "5s"
        initial_mtu: 1200
        send_window: "10MiB"
        receive_window: "10MiB"
```

TLS 证书通过服务器级别的 `tls` 配置（同 https 监听器），http3 依赖相同机制。

---

### 4. socks5 (SOCKS5)

SOCKS5 监听器，兼容 RFC 1928 和 RFC 1929。

#### 配置参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `addresses` | `[String]` | 是 | - | 监听地址列表 |
| `handshake_timeout` | `Duration` | 否 | `3s` | 协议握手、后续命令读取各自的超时 |
| `accept_retry_delay` | `Duration` | 否 | `1s` | accept 资源耗尽或未知 I/O 错误后的重试退避，必须大于零且能安全计时 |

认证策略由所关联服务的 `auth.basic_auth` 层声明，监听器不接受独立的 `users` 参数。服务组合时显式合并认证要求，并通过传输无关的只读接口提供给 SOCKS5 握手。未配置认证时只接受无认证方法（`0x00`），配置认证后只接受用户名/密码方法（`0x02`）；客户端同时提供两种方法时也按此策略选择，与客户端排列顺序无关。客户端未提供所需方法时返回 `0xFF` 并关闭连接。凭据必须满足所有认证层，才发送 RFC 1929 成功应答。凭据错误时先发送认证失败应答并关闭连接，不读取 CONNECT 目标。成功后再将 SOCKS5 CONNECT 转成 HTTP CONNECT，执行服务中间件和访问日志；凭据通过类型化扩展传递，保留用户名中的冒号。

服务层 `users` 条目格式：

| 参数 | 类型 | 说明 |
|------|------|------|
| `username` | `String` | 用户名 |
| `password` | `String` | 密码（明文） |

#### 配置示例

**无认证模式：**

```yaml
listeners:
  - name: socks5_main
    kind: socks5
    addresses: ["0.0.0.0:1080"]
```

**密码认证：**

```yaml
listeners:
  - name: socks5_main
    kind: socks5
    addresses: ["0.0.0.0:1080"]
    args:
      handshake_timeout: "15s"
      accept_retry_delay: "1s"

plugins:
  auth: {}
  http_upstream:
    upstreams:
      - name: direct
services:
  - name: proxy
    kind: http_upstream.upstream
    args:
      upstream: direct
    layers:
      - kind: auth.basic_auth
        args:
          users:
            - username: admin
              password: secret123
servers:
  - name: socks_proxy
    listeners: [socks5_main]
    service: proxy
```

#### 使用方式

```bash
# 无认证
curl --socks5 127.0.0.1:1080 https://example.com

# 用户名/密码认证
curl --socks5 127.0.0.1:1080 --proxy-user admin:secret123 https://example.com
```

---

## Service 详解

### 1. http_upstream.upstream

统一代理服务，支持两种模式：
- **直连模式**：upstream 无 addresses，代理直接连接目标服务器
- **链式模式**：upstream 有 addresses，代理通过上游代理服务器转发

支持 HTTP CONNECT、SOCKS5 CONNECT、HTTP/3 CONNECT 和 HTTP 正向代理。

Service 按方法处理请求：`CONNECT host:port` 建立透明隧道；其他方法统一转发完整的 HTTP 请求，目标 URL 支持 `http://` 和 `https://`。直连时，HTTP 目标使用 TCP，HTTPS 目标使用 TLS 并校验证书和目标主机名；链式模式将目标 scheme、authority、path、方法和消息体交给下一跳，不在中继节点建立目标 TLS。到 proxy 的连接地址、TLS 主机名与请求目标独立。GET/POST 的响应保留 HTTP 消息语义，CONNECT 成功后才转入双向字节传输。

末端直连客户端只使用 HTTP/1.1：HTTP 目标走 TCP，HTTPS 目标走 TLS，ALPN 仅提供 `http/1.1`，并保留证书和主机名校验。连接池按目标 scheme、host、port 隔离，由 `pool.max_idle_per_host` 和 `pool.idle_timeout` 控制。直连不使用 HTTP/2、HTTP/3，不解析或缓存 Alt-Svc，也不查询 DNS HTTPS 记录。

direct 从请求目标构造一个权重为 1 的 address，链式模式使用配置的全部 addresses；各域名先解析为所有 A/AAAA 地址，再对全部 IP 节点做平滑加权轮询。每个 IP 继承所属 address 的完整权重、协议、认证及超时配置。同一 IP 属于不同 address 时保持不同身份。连接池按选中节点及目标身份隔离，复用连接也先经过节点调度，不再做 IP 并发竞速。所有 TCP 监听和上游连接均启用 `TCP_NODELAY`；`quic_connection_*` 只作用于 HTTP/3 链式上游。

节点健康状态按 worker、upstream 和目标分别维护。`address_max_fails` 默认 1，`address_fail_timeout` 默认 10s，采用 Nginx 风格的被动失败计数、有效权重恢复和到期重试；只有一个 IP 节点时不因失败摘除，`address_max_fails: 0` 禁用摘除。失败只统计建连（含 TLS/QUIC 握手）、发送请求、等待响应头阶段的传输错误或超时，不按 HTTP 4xx/5xx 状态摘除，不统计非法响应头、客户端请求体错误、响应 body 或已建立隧道的后续错误。未提交请求的建连失败可尝试同组其他节点；已经提交的普通请求不自动重放。主动健康探测不启用。

链式 H3 上游同样遵守 `pool`：`max_idle_per_host: 0` 禁用跨请求连接复用，非零值允许复用一个多路复用会话，`idle_timeout` 从最后一个活跃响应或隧道释放后计算。池销毁会立即取消自己的维护任务；池索引不会因一个响应持续时间较长而淘汰仍活跃的 H3 会话。日志 writer 的活动文件和轮转归档必须拥有互不重叠的路径命名空间。

普通转发响应移除 `Alt-Svc`，中继同样不保留该响应头；响应 trailers 也会移除该字段。CONNECT 保持字节透传，不解析隧道内的 TLS 或 HTTP。

链式 CONNECT 在建立隧道前保留请求与成功响应的端到端头，并追加 `Via`；连接专属字段、上一跳代理凭据和成功 CONNECT 的 HTTP 内容长度不会转发。H3 上游提前给出最终响应并用 `H3_NO_ERROR` 停止上传时，上传方向结束，响应继续传输；其他传输错误仍会终止对应交换。

转为 HTTP/1 时，长度未知的 GET/HEAD 内容使用显式分块定界，保持流式上传。合法的 `Trailer` 声明会保留；初始 `Connection` 点名的逐跳字段及不允许延后的字段会同时从后续 trailer 帧中移除。带 trailer 的 HTTP/1 输出使用分块定界，包括正文长度已知的消息。

#### 配置参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `upstream` | `String` | 是 | 上游名称，引用 `plugins.http_upstream.upstreams[].name` |

直连模式的超时和连接池配置在 upstream 定义中设置：`tcp_connect_timeout` 用于 TCP 建连；`tls_handshake_timeout` 用于 TCP 上的 TLS 握手；`upstream_request_timeout` 限制响应头或隧道建立的等待时间。普通转发的连接池按 scheme、目标主机和端口区分，配置项为 `pool`；隧道使用 `tunnel_idle_timeout`。HTTPS 目标使用系统信任库，并可通过 `plugins.http_upstream.certificates.server_ca_path` 添加 CA，客户端证书沿用该配置中的 `client_cert_path` 和 `client_key_path`。

显式 CA 文件必须包含有效证书；空文件、只有私钥或无证书内容会导致配置失败，系统信任库不会掩盖该错误。

`dns_servers`、`dns_resolve_timeout` 和 `dns_refresh_retry_interval` 仅可在插件级配置。`dns_servers` 例如 `["127.0.0.1:5353", "[::1]:5353"]`；未配置时读取系统 DNS 服务器，由同一解析器服务 direct、CONNECT 和链式上游。遵守 DNS TTL，到期由后续请求触发刷新，同域名并发查询合并。刷新失败（包括无可用地址）保留上次成功结果，默认 30s 后允许再次刷新，不强制废弃旧结果；首次失败且无缓存则返回 DNS 错误。DNS 更新保留未变化 IP 的健康状态，移除节点停止接收新请求，已有响应与隧道继续完成。

`tunnel_idle_timeout` 按整个隧道的双向字节进展计时，任一方向成功读取或接受写入新字节都会刷新期限；EOF、空读写和反复轮询不算活动。一个独立计时器覆盖整个传输过程，包括双方读到 EOF 后仍在等待的 H3 `flush`/`finish`。单向半关闭会继续传输另一方向的数据，直到正常完成、空闲超时或服务关闭。H3 适配器每次最多缓冲 64 KiB，接受数据后立即确认本次字节数，`flush`/`shutdown` 推进发送并传播错误。

#### 直连模式示例

```yaml
plugins:
  http_upstream:
    upstreams:
      - name: direct
        tunnel_idle_timeout: "60s"
        tcp_connect_timeout: "10s"
        tls_handshake_timeout: "5s"

services:
  - name: tunnel
    kind: http_upstream.upstream
    args:
      upstream: direct

servers:
  - name: proxy
    listeners:
      - http_main
    service: tunnel
```

#### 链式模式示例

代理链架构：

```
客户端 --HTTP/1.1 CONNECT--> neoproxy(本地) --HTTP/3 QUIC--> neoproxy(上游) --> 目标服务器
```

**本地节点**（监听 HTTP 请求，转发到上游 H3 代理）：

```yaml
plugins:
  http_upstream:
    certificates:
      server_ca_path: conf/certs/server-ca.crt
    upstreams:
      - name: remote_relay
        addresses:
          - address: upstream.example.com:443
            hostname: "proxy.example.com"
            weight: 1
            address_protocol: http3

listeners:
  - name: http_main
    kind: http
    addresses: ["0.0.0.0:8080"]

services:
  - name: chain
    kind: http_upstream.upstream
    args:
      upstream: remote_relay

servers:
  - name: local_proxy
    listeners:
      - http_main
    service: chain
```

**上游节点**（监听 H3 连接，转发 TCP）：

```yaml
plugins:
  http_upstream:
    upstreams:
      - name: direct

listeners:
  - name: http3_main
    kind: http3
    addresses: ["0.0.0.0:443"]

services:
  - name: tunnel
    kind: http_upstream.upstream
    args:
      upstream: direct

servers:
  - name: remote_proxy
    tls:
      certificates:
        - cert_path: /etc/neoproxy/cert.pem
          key_path: /etc/neoproxy/key.pem
    listeners:
      - http3_main
    service: tunnel
```

#### 支持的协议

- HTTP CONNECT（通过 `http` 或 `https` 监听器）
- SOCKS5 CONNECT（通过 `socks5` 监听器）
- HTTP/3 CONNECT（通过 `http3` 监听器）
- HTTP 正向代理（absolute-form URI）

---

### 2. echo

回显服务，返回请求内容。用于测试和调试。

#### 配置示例

```yaml
services:
  - name: echo_service
    kind: echo.echo

servers:
  - name: echo_server
    listeners:
      - http_main
    service: echo_service
```

#### 使用方式

```bash
curl -X POST -d "Hello World" http://127.0.0.1:8080
# 返回: Hello World
```

---

## 中间件层 (Layers)

Service 支持通过 `layers` 配置中间件链，按声明顺序依次处理请求。

### 1. auth.basic_auth

HTTP Basic 代理认证层，验证 `Proxy-Authorization` 请求头。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `users` | `[Object]` | 是 | 用户列表（username + password） |

```yaml
services:
  - name: tunnel
    kind: http_upstream.upstream
    args:
      upstream: direct
    layers:
      - kind: auth.basic_auth
        args:
          users:
            - username: "admin"
              password: "secret"
```

### 2. access_log.file

访问日志层，将请求记录到指定 writer。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `writer` | `String` | 是 | writer 路径前缀（匹配 `plugins.access_log.writers[].path_prefix`） |
| `context_fields` | `[String]` | 否 | 要记录的请求上下文字段；省略时为 `["request.id"]`，显式列表按所列字段输出 |

```yaml
services:
  - name: tunnel
    kind: http_upstream.upstream
    args:
      upstream: direct
    layers:
      - kind: access_log.file
        args:
          writer: "logs/access.log"
          context_fields:
            - "request.id"
            - "basic_auth.user"
            - "upstream.connect_ms"
```

请求入口从 `X-Request-ID` 读取已有值；缺失时使用 worker 本地随机密钥和递增计数器，
通过两次 SipHash-2-4 生成 128 位、32 字符小写十六进制 request ID。
已有值作为不透明标识原样沿用。入口只把 ID 保存到 request context，保持入站请求头原样。
向上游发送普通请求或 CONNECT 时，在逐跳头清理后从 context 写入 `X-Request-ID`；
响应出口也从同一 context 写入该头，覆盖上游同名值。路由拒绝、认证拒绝和本地错误响应
同样携带 ID。SOCKS5 在转换成内部 CONNECT 请求时建立 ID。

context 使用受类型约束的字段键保存原生值，耗时保存为 `Duration`、计数保存为整数、
复用标志保存为布尔值，地址和解析结果保存为地址类型。只有选中的日志字段才会被提取和
格式化；JSON 扩展字段保留数字、布尔和数组类型，文本格式在输出时转换并转义。

| 可选 context 字段 | 输出含义 |
|------|------|
| `upstream.dns.host`、`upstream.dns.addresses` | 本次解析主机与地址数组 |
| `upstream.dns.duration_ms`、`upstream.dns.timeout_ms` | 解析耗时与期限，毫秒整数 |
| `upstream.connection.peer`、`upstream.connection.local` | 实际连接端点（可用时） |
| `upstream.connection.reused` | 连接复用布尔值 |
| `upstream.tcp.connect_ms`、`upstream.tls.handshake_ms` | 本次连接建立阶段耗时；H3 的后者包含 QUIC/TLS 握手 |
| `upstream.protocol` | 本次选择的上游协议：`http`、`https` 或 `http3`；direct CONNECT 没有目标 scheme，字段留空 |
| `upstream.forward_ms`、`upstream.forward_status` | 等待上游响应头的耗时与状态码 |
| `upstream.error.phase`、`upstream.error.kind`、`upstream.error.message` | 请求失败阶段、分类和完整错误信息 |

连接池保存连接观测信息，不保存请求 context。每次选择上游节点时记录其协议；direct 普通请求使用目标 URL 的 scheme，重试时记录最后选中的协议。复用连接会记录实际地址与所选协议，
本次未发生的解析、TCP 建连和 TLS 握手耗时留空。
access log 继续在 service 返回响应头时生成；完整正文或 tunnel 的最终传输统计不会
事后回写这条记录。tunnel 结束后另有一条带相同 `request_id` 的 `tunnel_finished`
业务日志，记录目标、端点、持续时间、双向字节数和结束原因；取消时也保留部分进度。
字节数按 I/O 层成功接受的写入统计，不计入尚未写出的预读数据。

---

## Server 级别配置

### 虚拟主机路由

服务器通过 `hostnames` 配置虚拟主机名，TLS 的 SNI 和 HTTP 的目标 authority/Host 分别使用它选 Server。精确匹配优先；通配符 `*.example.com` 只匹配一个非空标签，不匹配裸域或多层子域。本项目对齐 Nginx 的选 Server/证书流程，继续使用自身原有的单层通配语义。
多个服务器必须引用同一个 listener 对象来共享地址，再按目标 authority 路由。不同 listener 对象不能重复绑定同一 socket，也不能配置相互覆盖的通配监听地址。空 hostnames 表示默认/兜底服务器。同一 listener 的各 worker 使用 `SO_REUSEPORT` 独立绑定，QUIC Endpoint 不跨 worker 共享。

```yaml
servers:
  - name: api
    hostnames: ["api.example.com"]
    tls:
      certificates:
        - cert_path: conf/certs/api.crt
          key_path: conf/certs/api.key
    listeners:
      - https_main
    service: api_service

  - name: app
    hostnames: ["*.app.example.com"]
    tls:
      certificates:
        - cert_path: conf/certs/app.crt
          key_path: conf/certs/app.key
    listeners:
      - https_main
    service: app_service
```

### TLS 配置

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `certificates` | `[Object]` | 是 | 证书列表（cert_path + key_path 对） |
| `client_ca_certs` | `[String]` | 否 | 默认为 `[]`；非空时要求客户端证书，并向 listener 的共享信任库贡献 CA |

每个显式指定的客户端 CA 文件必须包含至少一个可加入信任库的证书。空文件、只有空白或普通文本、只有私钥的文件均导致启动失败，即使其他文件或关联 Server 提供了有效 CA。文件可以包含注释、多张证书及其他 PEM 项；读取、解析或证书错误会带上 TLS Server 的局部索引、服务名、CA 列表索引及文件路径。

监听器在 TLS 握手阶段根据客户端 SNI 选择对应服务器的证书，而非在 HTTP 请求处理阶段使用 SNI。

配置解析和校验后、任何 worker 或 listener 启动前，编译所有 TLS 凭据：加载证书链和私钥、检查配对、解析叶证书 SAN，并加载客户端 CA。`hostnames` 非空时，每张候选证书都必须覆盖全部配置名称或单层通配范围，否则以 Server 名称、证书路径和未覆盖名称报错。默认 Server 的空名称列表不做域名覆盖检查。额外 SAN 允许存在，但不会自动生成路由；中间证书不贡献服务名称。编译结果由配置克隆共享，worker 和握手不再读取证书/CA 文件。

每个 Server 的 `certificates` 按优先级排列。握手使用 rustls 提供的客户端兼容签名算法筛选，选择首个兼容候选；相同算法的多张证书也遵循此顺序。没有兼容候选则拒绝握手，不使用另一个 Server 的证书，也不按 SAN 重新挑选。每个条目包含叶证书、私钥及配套证书链。

---

## 完整配置示例

### 示例 1：HTTP 代理服务器（带认证和访问日志）

```yaml
server_threads: 4

plugins:
  access_log:
    writers:
      - path_prefix: "logs/access.log"
  http_upstream:
    upstreams:
      - name: direct
        tcp_connect_timeout: "10s"
        tunnel_idle_timeout: "60s"

listeners:
  - name: http_main
    kind: http
    addresses: ["0.0.0.0:8080"]

services:
  - name: tunnel
    kind: http_upstream.upstream
    args:
      upstream: direct
    layers:
      - kind: auth.basic_auth
        args:
          users:
            - username: admin
              password: secret123
      - kind: access_log.file
        args:
          writer: "logs/access.log"
          context_fields:
            - "basic_auth.user"

servers:
  - name: http_proxy
    listeners:
      - http_main
    service: tunnel
```

### 示例 2：SOCKS5 代理服务器（无认证）

```yaml
server_threads: 4

plugins:
  http_upstream:
    upstreams:
      - name: direct

listeners:
  - name: socks5_main
    kind: socks5
    addresses: ["0.0.0.0:1080"]

services:
  - name: tunnel
    kind: http_upstream.upstream
    args:
      upstream: direct

servers:
  - name: socks5_proxy
    listeners:
      - socks5_main
    service: tunnel
```

### 示例 3：HTTPS/HTTP3 代理服务器（带 TLS）

```yaml
server_threads: 4

plugins:
  http_upstream:
    upstreams:
      - name: direct

listeners:
  - name: https_main
    kind: https
    addresses: ["0.0.0.0:443"]
    args:
      tls_handshake_timeout: "5s"
  - name: http3_main
    kind: http3
    addresses: ["0.0.0.0:443"]

services:
  - name: tunnel
    kind: http_upstream.upstream
    args:
      upstream: direct
    layers:
      - kind: auth.basic_auth
        args:
          users:
            - username: admin
              password: secret123

servers:
  - name: secure_proxy
    tls:
      certificates:
        - cert_path: /etc/neoproxy/cert.pem
          key_path: /etc/neoproxy/key.pem
      client_ca_certs:
        - /etc/neoproxy/client-ca.crt
    listeners:
      - https_main
      - http3_main
    service: tunnel
```

### 示例 4：HTTP/3 代理链

**本地节点配置：**

```yaml
server_threads: 4

plugins:
  http_upstream:
    certificates:
      server_ca_path: /etc/neoproxy/ca.pem
    upstreams:
      - name: remote
        addresses:
          - address: remote.example.com:443
            hostname: "proxy.example.com"
            weight: 1
            address_protocol: http3

listeners:
  - name: http_main
    kind: http
    addresses: ["0.0.0.0:8080"]

services:
  - name: chain
    kind: http_upstream.upstream
    args:
      upstream: remote

servers:
  - name: local_proxy
    listeners:
      - http_main
    service: chain
```

**远程节点配置：**

```yaml
server_threads: 4

plugins:
  http_upstream:
    upstreams:
      - name: direct

listeners:
  - name: http3_main
    kind: http3
    addresses: ["0.0.0.0:443"]

services:
  - name: tunnel
    kind: http_upstream.upstream
    args:
      upstream: direct

servers:
  - name: remote_proxy
    tls:
      certificates:
        - cert_path: /etc/neoproxy/cert.pem
          key_path: /etc/neoproxy/key.pem
    listeners:
      - http3_main
    service: tunnel
```

---

## 日志

主日志按日期滚动，存储在 `logs/` 目录。日志级别通过环境变量 `NEOPROXY_LOG` 控制：

```bash
export NEOPROXY_LOG=debug
./neoproxy --config conf/server.yaml
```

支持的日志级别：`trace`, `debug`, `info`, `warn`, `error`

默认日志输出包含：时间戳、日志级别、文件名、行号、线程名。
启用 debug/trace 后还会记录已启用 span 的结束事件及忙碌、等待耗时。
业务 DNS、TCP/TLS 摘要进入 request context，经配置选择后写入 access log，
不再单独输出这些阶段的业务运行日志或 span。
H3 内容块 TRACE 保留发送前后事件、字节数和请求 ID，用于按需观察传输进展。

代理链集测每次运行都会保留诊断目录，默认位于
`tmp/test-artifacts/proxy-chain/chain-*/`，可通过 `NEOPROXY_TEST_ARTIFACTS` 指定根目录。
目录包含用例与进程清单、配置、两级代理运行日志、access log 与标准输出、带时间戳的 curl trace、
响应头和完整或部分响应体、curl JSON 计时与收发统计，以及每 250 ms 按代理 PID
过滤的 TCP/UDP 内核状态。采集失败会写明原因；测试失败时显示诊断目录。
原有公网和受控源站用例的目标、断言、连接及总超时不变，诊断不会重试请求。
这些产物在测试临时目录清理后仍保留，成功运行的产物也保留，按需清理。

启动日志及配置对象的 `Debug` 保留完整字段，按黑名单将密码、token 的值显示为一个 `*`，字段名仍保留。原始插件参数递归处理嵌套映射、列表和 YAML 标签；字段名不区分大小写，匹配 `password`、`token` 及以 `_password`、`-password`、`_token`、`-token` 结尾的字段，例如 `access_token`。其他字段保持正常输出，用户名、地址、文件路径和 `token_count` 等均不隐藏。认证器的用户表保留用户名，每个密码显示为 `*`；格式化不改写实际配置或凭据。访问日志的文本/JSON 转义仅维护日志格式，不属于脱敏。

访问日志通过 `access_log` 插件配置，支持文本和 JSON 格式、文件大小和日期轮转。

---

## 信号处理

neoproxy 支持优雅关闭：

- `SIGINT` (Ctrl+C)：触发优雅关闭
- `SIGTERM`：触发优雅关闭

优雅关闭流程：
1. 停止接收新连接
2. 通知 HTTP 协议连接优雅关闭：HTTP/1 和 HTTP/2 关闭空闲连接、停止连接复用；H3 发送 GOAWAY，并在解析请求头之前拒绝新请求流。允许正在进行的普通请求及其 body、trailers、CONNECT 建立和升级收尾。等待这些请求任务最多 3 秒；超时取消后，再等待回收最多 2 秒。H3 对未完成的请求流发送取消重置
3. 卸载上游插件，通知已升级的隧道立即停止转发并关闭上游连接池；同时收尾 H3 连接驱动。H3 驱动继续处理控制帧和拒绝新请求，保留排队中的 GOAWAY、响应及流结束帧，等待对端关闭；不主动关闭连接的客户端由此阶段的时限终止。两类清理并行进行，共用第二阶段最多 3 秒、取消回收最多 2 秒的预算。这不是让隧道继续传输的宽限期
4. 所有 worker 完成前两阶段后，再释放各自的 QUIC Endpoint 和 UDP socket。已完成清理的 worker 保持运行时和 socket 存活，避免 reuseport 组提前缩小影响其他 worker 的收包
5. 访问日志 writer 线程刷新缓冲区
6. 退出程序

同一工作线程内，前两段任务等待预算均为 `3 + 2` 秒，合计 10 秒；H3 驱动与上游插件并行收尾，没有第三段独立等待预算。第二阶段的 3 秒常量由插件和 H3 驱动共用。worker 之间的释放协调等待其他 worker 已有的收尾流程；日志刷新及其他退出步骤不包含在这 10 秒中，目前没有进程级全局硬超时。

worker 退出时先销毁本地异步任务，再关闭运行时。无法取消的系统 DNS 阻塞调用可以在后台结束，并持续占用已有的 DNS 并发许可；它们不会延长 worker 的运行时析构等待。

### 退出码

| 退出码 | 含义 |
|--------|------|
| 0 | 正常退出 |
| 1 | 工作线程崩溃（panic） |
| 2 | 工作线程错误退出 |

---

## 安全建议

1. **配置文件权限：** 密码以明文存储，建议设置配置文件权限为 600
   ```bash
   chmod 600 conf/server.yaml
   ```

2. **日志目录权限：** 限制日志目录访问权限
   ```bash
   chmod 700 logs/
   ```

3. **证书文件权限：** TLS 私钥文件应设置严格权限
   ```bash
   chmod 600 /path/to/key.pem
   ```

4. **认证安全性：** 密码字节使用恒定时间比较，认证失败返回统一的 "invalid credentials" 错误。该保证不表示整个用户名查找流程具有恒定时间。

---

## 开发

### 运行单元测试

```bash
cargo test --workspace --no-fail-fast
```

### 运行集成测试

```bash
cargo build
uv run pytest
```

默认使用 pytest-xdist 的 [worksteal 调度](https://pytest-xdist.readthedocs.io/en/latest/distribution.html)，
worker 数量按可用 CPU 选择，最多 4 个。标记为 `slow` 的用例优先开始，让真实期限等待
与其他测试重叠；默认仍执行全部测试。需要串行诊断或查看耗时分布时：

```bash
uv run pytest -n 0 --durations=20
uv run pytest --durations=20 --junitxml=tmp/pytest-timings.xml
```

测试进程通过 `tmp/test-port-counter` 的文件锁协调端口，端口仍需通过 IPv4/IPv6、
TCP/UDP 可用性探测。启动就绪改为专用通知：`start_proxy()` 返回拥有通知通道的
`ProxyProcess`，调用 `wait_ready(timeout=...)` 等待结果。全部 worker 的所有 listener
完成绑定后，NeoProxy 向 `NOTIFY_SOCKET` 指定的 Unix datagram socket 发送一次
`READY=1`。任何 worker 初始化失败或启动期间退出，都不会发出成功通知。

父进程通过内核事件同时等待就绪消息和子进程退出：Linux 使用 pidfd，macOS 使用
kqueue 的 `EVFILT_PROC/NOTE_EXIT`。两者共用通知协议和截止时间处理；超时可以再次
等待，成功或退出后释放通知资源。Mac 的通知路径使用 `/tmp` 下的短目录，避免 Unix
socket 路径长度问题；普通文件路径形式的通知不依赖 systemd。Linux 额外支持标准
`NOTIFY_SOCKET` 的 `@` 抽象地址形式。旧 TCP/UDP 启动就绪轮询接口已删除。

证书设施保留至多 64 组已验证的 CA 对象，按证书和私钥的实际 PEM 内容识别；文件替换后
会重新识别，外部 CA 首次加载仍完整验证。客户端 CA 配置矩阵共享只读证书材料，
每个用例保留独立的配置文件、错误输入和代理进程。

2026-10-27 在同一台机器、debug 构建上的完整验证：

| 阶段 | 用例数 | 耗时 |
|------|------:|------:|
| 优化前，串行基线 | 661 | 538.63 秒 |
| 证书、就绪检测、失败启动及并行执行优化后 | 667 | 129.75 秒 |
| 加上慢用例优先及 worker 结束通知 | 668 | 111.87 秒 |
| 全量启动就绪改为通知机制 | 670 | 102.65 秒 |

最终耗时减少约 80.9%，约提速 5.2 倍。早期版本 `b162408` 收集到 301 个测试，
当前基线已增至 661 个；新增的两个默认请求头期限用例合计约 61 秒，原有期限继续验证。
首轮性能优化新增 7 个回归用例；通知升级将已删除的端口探测接口单测替换为事件语义
测试，继续全量执行协议场景，无跳过测试。

六项优化分别处理以下根因：

1. 就绪检测以固定 100ms 粒度等待，快速启动也要等待一个完整间隔；最终改为进程
   主动通知，父进程等待消息或退出事件，统一验证所有 worker 和 listener 的就绪状态。
2. 证书签发把刚生成的 CA 私钥写入文件后立即重复解析、验证。20 次签发的初始
   profile 中，仅私钥加载就占 4.33 秒；现在复用已验证对象。客户端 CA 配置矩阵
   的只读证书材料也改为模块作用域，原 28 个用例累计从 22.17 秒降到 1.97 秒。
3. 失败启动用例没有把进程句柄传给就绪等待，子进程退出后仍等满 5 秒；现在观察
   进程状态并校验退出码，该用例从 5.04 秒降到最终并行运行的 0.023 秒。
4. 全部用例串行执行，时间等待与密码学初始化累计；通过最多 4 个 worker 并行运行。
   同时修复进程内端口计数器的隔离缺陷，跨进程回归验证 48 次分配互不重复。
5. 默认 30 秒期限用例排在后面，其他 worker 结束后仍有拖尾；通过公开的 `slow`
   标记优先开始，不以修改协议期限缩短测试。
6. 主进程每 100ms 轮询 worker 是否结束，给大量进程启动失败和退出增加延迟。
   `process::Workers` 统一拥有线程创建、结束通知和 join，worker 返回或展开时主动
   唤醒监督器；退出码优先级、借用数据生命周期及异常清理均由黑盒单测验证。

串行诊断使用 `cProfile` 和 JUnit 分项耗时；含 profiler 的中间阶段完整运行也为
668 项通过。上述速度比较使用普通运行结果，profile 耗时不作为最终默认命令耗时。

通知升级验证：Rust 默认及全特性单测各 813 项通过，Linux 进程集测 670 项通过。
全项目 `All` 类型检查，以及 Linux/macOS 后端各自的平台类型检查均通过；macOS 实机
运行尚未在此 Linux 环境中执行。测试覆盖无 sleep 等待、提前退出、超时重试、资源清理，
以及 TCP/UDP 后续 listener 绑定失败时不得通知成功的 1/4 worker 场景。

### 代码检查

```bash
cargo +nightly fmt --all
cargo +nightly fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build
cargo test --workspace --no-fail-fast
uv run ruff format
uv run ruff format --check
uv run ruff check
uv run basedpyright
uv run pytest
```

当前 h3 0.0.8 的经典 CONNECT 编码会额外发送 `:scheme` 和 `:path`，严格上游可能拒绝。此第三方限制不在项目内打补丁；[失败场景测试](tests/integration/test_dependency_h3.py) 记录了实际报文和拒绝结果。普通 H3 转发不受此限制。审查根因和架构判断见 [REVIEW.txt](REVIEW.txt)。
