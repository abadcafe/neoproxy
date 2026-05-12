# neoproxy

一个高性能代理服务器，支持 HTTP/1.1、HTTPS、HTTP/3 (QUIC) 和 SOCKS5 协议。

## 功能概览

| 组件 | 类型 | 名称 | 说明 |
|------|------|------|------|
| Listener | `http` | HTTP/1.1 监听器，支持 CONNECT 方法和主机路由 |
| Listener | `https` | HTTPS (HTTP/1.1 over TLS) 监听器，支持 SNI 证书选择和客户端证书认证 |
| Listener | `http3` | HTTP/3 (QUIC) 监听器，支持密码认证和 TLS 客户端证书认证 |
| Listener | `socks5` | SOCKS5 监听器，支持用户名/密码认证 |
| Service | `connect_tcp` | TCP 隧道服务，连接目标服务器 |
| Service | `http3_chain` | HTTP/3 代理链服务，通过 HTTP/3 连接上游代理 |
| Service | `echo` | 回显服务（测试用） |
| Plugin | `auth` | 认证插件，提供 HTTP Basic Auth 中间件层 |
| Plugin | `access_log` | 访问日志插件，支持多 writer、缓冲写入、文件轮转 |

## 快速开始

### 环境要求

- Rust 1.85.0 或更高版本（使用 Rust 2024 edition）

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
# 服务线程数（默认: 4）
server_threads: 2

# 全局插件配置
plugins:
  <plugin_name>:
    # 插件特定参数

# 监听器定义（全局，被 servers 引用）
listeners:
  - name: <监听器名称>
    kind: <监听器类型>
    addresses: ["host:port"]
    args:
      # 监听器特定参数

# 服务定义
services:
  - name: <服务名称>
    kind: <插件名>.<服务名>
    args:
      # 服务特定参数
    layers:        # 可选中间件层
      - kind: <插件名>.<层名>
        args:
          # 层特定参数

# 服务器定义（关联服务和监听器）
servers:
  - name: <服务器名称>
    hostnames: []  # 可选虚拟主机名
    tls:           # 可选 TLS 配置
      certificates:
        - cert_path: <路径>
          key_path: <路径>
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
        rotate_daily: true               # 按日期轮转（默认: true）
        format: "text"                   # 日志格式: text / json（默认: text）
```

---

## Listener 详解

### 1. http (HTTP/1.1)

HTTP/1.1 监听器，支持 CONNECT 方法和基于 Host 头的虚拟主机路由。

#### 配置参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `addresses` | `[String]` | 是 | 监听地址列表，格式 `host:port` |

#### 配置示例

```yaml
listeners:
  - name: http_main
    kind: http
    addresses:
      - "0.0.0.0:8080"
```

#### 使用方式

```bash
curl --proxy http://127.0.0.1:8080 https://example.com
```

---

### 2. https (HTTPS)

HTTPS (HTTP/1.1 over TLS) 监听器，支持 SNI 证书选择和客户端证书认证。

#### 配置参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `addresses` | `[String]` | 是 | - | 监听地址列表 |
| `tls_handshake_timeout` | `Duration` | 否 | `5s` | TLS 握手超时，防止慢客户端占用连接 |

TLS 证书在服务器（Server）级别配置，多个服务器可以共享同一监听器地址，通过 SNI 区分。

#### 配置示例

```yaml
listeners:
  - name: https_main
    kind: https
    addresses: ["0.0.0.0:8443"]
    args:
      tls_handshake_timeout: "5s"

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

#### 认证配置

http3 的密码认证和 TLS 客户端证书认证通过上层 Service 的 `auth.basic_auth` layer 和服务器级别的 `client_ca_certs` 配置实现。

---

### 4. socks5 (SOCKS5)

SOCKS5 监听器，兼容 RFC 1928 和 RFC 1929。

#### 配置参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `addresses` | `[String]` | 是 | - | 监听地址列表 |
| `handshake_timeout` | `Duration` | 否 | `3s` | 握手超时 |
| `users` | `[Object]` | 否 | - | 用户名/密码认证，省略则为无认证模式 |

`users` 条目格式：

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
      users:
        - username: admin
          password: secret123
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

### 1. connect_tcp

TCP 隧道服务，连接目标服务器并转发数据。通常与 Listener 配合使用。

#### 配置参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `connect_timeout` | `Duration` | 否 | `10s` | TCP 连接目标超时 |
| `idle_timeout` | `Duration` | 否 | `60s` | 隧道数据传输空闲超时 |

#### 配置示例

```yaml
services:
  - name: tunnel
    kind: connect_tcp.connect_tcp
    args:
      connect_timeout: "10s"
      idle_timeout: "60s"

servers:
  - name: proxy
    listeners:
      - http_main
    service: tunnel
```

#### 支持的协议

- HTTP CONNECT（通过 `http` 或 `https` 监听器）
- SOCKS5 CONNECT（通过 `socks5` 监听器）
- HTTP/3 CONNECT（通过 `http3` 监听器）

---

### 2. http3_chain

HTTP/3 代理链服务，通过 HTTP/3 协议连接到上游代理服务器。

**适用场景：** 利用 QUIC 的弱网能力，在不稳定网络环境下建立代理链。

#### 配置参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `proxy_group` | `[Object]` | 是 | 上游代理组 |
| `default_user` | `Object` | 否 | 默认用户名/密码凭证 |
| `default_tls` | `Object` | 否 | 默认 TLS 配置 |

proxy_group 条目格式：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `address` | `String` | 是 | 上游代理地址 `host:port` |
| `hostname` | `String` | 否 | SNI 主机名（需匹配服务器证书 SAN） |
| `weight` | `usize` | 是 | 权重（负载均衡用） |
| `user` | `Object` | 否 | 可选用户名/密码覆盖 |
| `tls` | `Object` | 否 | 可选 TLS 配置覆盖 |

#### 配置示例

```yaml
services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      default_user:
        username: "default_user"
        password: "default_pass"
      default_tls:
        server_ca_path: conf/certs/server-ca.crt
      proxy_group:
        - address: upstream1.example.com:443
          hostname: "http3.example.com"
          weight: 1
          user:
            username: "admin"
            password: "secret"
          tls:
            client_cert_path: conf/certs/client.crt
            client_key_path: conf/certs/client.key
            server_ca_path: conf/certs/server-ca.crt
```

#### 代理链架构

```
客户端 --HTTP/1.1 CONNECT--> neoproxy(本地) --HTTP/3 QUIC--> neoproxy(上游) --> 目标服务器
```

上游 neoproxy 配置：

```yaml
services:
  - name: tunnel
    kind: connect_tcp.connect_tcp

servers:
  - name: upstream
    tls:
      certificates:
        - cert_path: /path/to/cert.pem
          key_path: /path/to/key.pem
    listeners:
      - http3_main
    service: tunnel
```

---

### 3. echo

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
    kind: connect_tcp.connect_tcp
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
    kind: connect_tcp.connect_tcp
    layers:
      - kind: access_log.file
        args:
          writer: "logs/access.log"
          context_fields:
            - "basic_auth.user"
            - "connect_tcp.connect_ms"
```

---

## Server 级别配置

### 虚拟主机路由

服务器支持通过 `hostnames` 字段配置虚拟主机名，支持精确匹配和通配符匹配 (`*.example.com`)。
多个服务器可以共享同一监听器地址，通过 Host 头或 SNI 进行路由。空 hostnames 表示默认/兜底服务器。

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
| `client_ca_certs` | `[String]` | 否 | 客户端 CA 证书路径列表（用于 mTLS） |

---

## 完整配置示例

### 示例 1：HTTP 代理服务器（带认证和访问日志）

```yaml
server_threads: 2

plugins:
  access_log:
    writers:
      - path_prefix: "logs/access.log"

listeners:
  - name: http_main
    kind: http
    addresses: ["0.0.0.0:8080"]

services:
  - name: tunnel
    kind: connect_tcp.connect_tcp
    args:
      connect_timeout: "10s"
      idle_timeout: "60s"
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
server_threads: 2

listeners:
  - name: socks5_main
    kind: socks5
    addresses: ["0.0.0.0:1080"]

services:
  - name: tunnel
    kind: connect_tcp.connect_tcp

servers:
  - name: socks5_proxy
    listeners:
      - socks5_main
    service: tunnel
```

### 示例 3：HTTPS/HTTP3 代理服务器（带 TLS）

```yaml
server_threads: 2

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
    kind: connect_tcp.connect_tcp
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
server_threads: 2

listeners:
  - name: http_main
    kind: http
    addresses: ["0.0.0.0:8080"]

services:
  - name: chain
    kind: http3_chain.http3_chain
    args:
      default_tls:
        server_ca_path: /etc/neoproxy/ca.pem
      proxy_group:
        - address: remote.example.com:443
          hostname: "http3.example.com"
          weight: 1

servers:
  - name: local_proxy
    listeners:
      - http_main
    service: chain
```

**远程节点配置：**

```yaml
server_threads: 2

listeners:
  - name: http3_main
    kind: http3
    addresses: ["0.0.0.0:443"]

services:
  - name: tunnel
    kind: connect_tcp.connect_tcp

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

访问日志通过 `access_log` 插件配置，支持文本和 JSON 格式、文件大小和日期轮转。

---

## 信号处理

neoproxy 支持优雅关闭：

- `SIGINT` (Ctrl+C)：触发优雅关闭
- `SIGTERM`：触发优雅关闭

优雅关闭流程：
1. 停止接收新连接
2. 等待现有连接完成（Listener 层超时 3 秒）
3. 强制关闭剩余连接
4. 访问日志 writer 线程刷新缓冲区
5. 退出程序

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

4. **认证安全性：** 密码验证使用恒定时间比较，防止时序攻击。所有认证失败返回统一的 "invalid credentials" 错误，避免泄露用户名是否存在。

---

## 开发

### 运行单元测试

```bash
cargo test
```

### 运行集成测试

```bash
cargo build
cd tests/integration
python3 -m pytest -v
```

### 代码检查

```bash
cargo clippy
cargo fmt --check
```
