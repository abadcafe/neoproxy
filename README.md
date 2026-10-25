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
低层级覆盖高层级同名参数。

**直连模式**：upstream 不配置 `addresses`，代理直接连接目标服务器。
**链式模式**：upstream 配置 `addresses`，代理通过上游代理服务器转发。

```yaml
plugins:
  http_upstream:
    certificates:                          # TLS 配置（链式模式需要）
      server_ca_path: conf/certs/server-ca.crt
      client_cert_path: conf/certs/client.crt
      client_key_path: conf/certs/client.key
    request_timeout: 30s                # 到收到响应头/完成 CONNECT 的总时限，可在 upstream 覆盖
    tunnel_idle_timeout: 60s            # 插件级默认配置
    http:
      connect_timeout: 10s
    https:
      connect_timeout: 10s
      tls_handshake_timeout: 5s
    http3:
      quic:
        keep_alive_interval: "3s"
    upstreams:
      # 直连模式（无 addresses）
      - name: direct
        tunnel_idle_timeout: 60s
        http:
          connect_timeout: 10s
        pool:
          max_idle_per_host: 32            # 连接池最大空闲连接数（默认: 32）
          idle_timeout: 90s                # 连接池空闲超时（默认: 90s）

      # 链式模式（有 addresses）
      - name: remote_relay
        tunnel_idle_timeout: 60s
        http3:
          quic:
            keep_alive_interval: "5s"
        addresses:
          - address: "host:port"           # 上游代理地址
            hostname: "sni.example.com"    # 连接上游时使用的 SNI（需匹配上游证书 SAN）
            weight: 1                      # 负载均衡权重
            http: {}                       # 可在此处覆盖协议配置
```

---

## Listener 详解

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

认证由所关联服务的 `auth.basic_auth` 层处理，监听器不接受 `users` 参数，也不提取服务认证策略。SOCKS5 客户端先等待认证子协商回复，随后才发送 CONNECT 目标；HTTP Service 则需要目标与凭据齐备的一次完整请求。因此，转换器先完成子协商并保存凭据，再将 SOCKS5 CONNECT 转成 HTTP CONNECT，按配置的中间件顺序统一处理认证和访问日志。错误或缺失的凭据由认证层返回 HTTP `407`，转换为 SOCKS5 CONNECT 的 `REP=0x02` 并关闭该连接，不建立隧道。这与 RFC 1929 §2“验证凭据后才报告认证成功”的阶段语义存在明确差异；握手阶段的成功回复不能代表凭据已通过服务校验。配置用户名列表必须非空且不重复。凭据通过类型化请求扩展传递，保留 SOCKS5 用户名中允许的冒号，不转成可能丢失边界的 Basic 字符串。

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
curl --socks5 127.0.0.1:1080 --proxy-user user1:pass1 https://example.com
```

---

## Service 详解

### 1. http_upstream.upstream

统一代理服务，支持两种模式：
- **直连模式**：upstream 无 addresses，代理直接连接目标服务器
- **链式模式**：upstream 有 addresses，代理通过上游代理服务器转发

支持 HTTP CONNECT、SOCKS5 CONNECT、HTTP/3 CONNECT 和 HTTP 正向代理。

#### 配置参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `upstream` | `String` | 是 | 上游名称，引用 `plugins.http_upstream.upstreams[].name` |

直连模式的超时和连接池配置在 upstream 定义中设置（`http.connect_timeout`、`tunnel_idle_timeout`、`pool`）。

`tunnel_idle_timeout` 按整个隧道的双向字节进展计时，任一方向成功读取或接受写入新字节都会刷新期限；EOF、空读写和反复轮询不算活动。一个独立计时器覆盖整个传输过程，包括双方读到 EOF 后仍在等待的 H3 `flush`/`finish`。单向半关闭会继续传输另一方向的数据，直到正常完成、空闲超时或服务关闭。H3 适配器每次最多缓冲 64 KiB，接受数据后立即确认本次字节数，`flush`/`shutdown` 推进发送并传播错误。

#### 直连模式示例

```yaml
plugins:
  http_upstream:
    upstreams:
      - name: direct
        tunnel_idle_timeout: "60s"
        http:
          connect_timeout: "10s"

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
            http3: {}

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
| `context_fields` | `[String]` | 否 | 要记录的请求上下文字段 |

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
            - "basic_auth.user"
            - "upstream.connect_ms"
```

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
        http:
          connect_timeout: "10s"
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
            http3: {}

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
