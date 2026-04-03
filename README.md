# neoproxy

一个高性能代理服务器，支持 HTTP/1.1、HTTP/3 和 SOCKS5 协议。

## 功能概览

| 组件 | 名称 | 说明 |
|------|------|------|
| Listener | `hyper.listener` | HTTP/1.1 监听器，支持 CONNECT 方法 |
| Listener | `http3.listener` | HTTP/3 (QUIC) 监听器，支持密码认证和 TLS 客户端证书认证 |
| Listener | `fast_socks5.listener` | SOCKS5 监听器，支持用户名/密码认证 |
| Service | `connect_tcp` | TCP 隧道服务，连接目标服务器 |
| Service | `http3_chain` | HTTP/3 代理链服务，通过 HTTP/3 连接上游代理 |
| Service | `echo` | 回显服务（测试用） |

## 快速开始

### 编译

```bash
cargo build --release
```

### 运行

```bash
./target/release/neoproxy --config conf/server.yaml
```

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-c, --config <FILE>` | 配置文件路径 | `conf/server.yaml` |
| `-v, --version` | 显示版本号 | - |

## 配置文件结构

```yaml
# 工作线程数（默认: 1）
worker_threads: 1

# 日志目录（默认: logs/）
log_directory: logs/

# 服务定义
services:
  - name: <服务名称>
    kind: <插件名>.<服务名>
    args:
      # 服务特定参数

# 服务器定义（关联服务和监听器）
servers:
  - name: <服务器名称>
    service: <引用的服务名称>
    listeners:
      - kind: <监听器名>
        args:
          # 监听器特定参数
```

---

## Listener 详解

### 1. hyper.listener (HTTP/1.1)

HTTP/1.1 监听器，接收 HTTP CONNECT 请求。

#### 配置参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `addresses` | `[String]` | 是 | 监听地址列表，格式 `host:port` |

#### 配置示例

```yaml
listeners:
  - kind: hyper.listener
    args:
      addresses:
        - "0.0.0.0:8080"
        - "0.0.0.0:8081"
```

#### 使用方式

```bash
# 通过代理访问目标服务器
curl --proxy 127.0.0.1:8080 https://example.com
```

---

### 2. http3.listener (HTTP/3)

HTTP/3 (QUIC) 监听器，提供更快的连接建立和更好的弱网表现。

#### 配置参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `address` | `String` | 是 | 监听地址，格式 `host:port` |
| `cert_path` | `String` | 是 | TLS 证书文件路径 (PEM) |
| `key_path` | `String` | 是 | TLS 私钥文件路径 (PEM) |
| `quic` | `Object` | 否 | QUIC 协议参数 |
| `auth` | `Object` | 否 | 认证配置 |

#### QUIC 参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `max_concurrent_bidi_streams` | `u64` | 100 | 最大并发双向流 (1-10000) |
| `max_idle_timeout_ms` | `u64` | 30000 | 最大空闲超时（毫秒） |
| `initial_mtu` | `u16` | 1200 | 初始 MTU (1200-9000) |
| `send_window` | `u64` | 10485760 | 发送窗口大小（字节） |
| `receive_window` | `u64` | 10485760 | 接收窗口大小（字节） |

#### 认证配置

**密码认证：**

```yaml
auth:
  type: password
  users:
    - username: user1
      password: secret123
    - username: user2
      password: secret456
```

**TLS 客户端证书认证：**

```yaml
auth:
  type: tls_client_cert
  client_ca_path: /path/to/client_ca.pem
```

> **安全警告：** 密码以明文形式存储在配置文件中。建议通过文件权限限制配置文件的访问权限（例如 `chmod 600 conf/server.yaml`）。

---

### 3. fast_socks5.listener (SOCKS5)

SOCKS5 监听器，完全兼容 RFC 1928 和 RFC 1929。

#### 配置参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `addresses` | `[String]` | 是 | - | 监听地址列表 |
| `handshake_timeout` | `u64` | 否 | 10 | 握手超时（秒） |
| `auth` | `Object` | 否 | - | 认证配置 |

#### 认证配置

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `type` | `String` | 是 | 认证类型：`password`（SOCKS5 仅支持密码认证） |
| `users` | `[Object]` | 是 | 用户列表 |

用户条目格式：

| 参数 | 类型 | 说明 |
|------|------|------|
| `username` | `String` | 用户名 |
| `password` | `String` | 密码（明文） |

> **注意：** SOCKS5 仅支持密码认证，不支持 TLS 客户端证书认证。

#### 配置示例

**无认证模式：**

```yaml
listeners:
  - kind: fast_socks5.listener
    args:
      addresses:
        - "0.0.0.0:1080"
```

**密码认证：**

```yaml
listeners:
  - kind: fast_socks5.listener
    args:
      addresses:
        - "0.0.0.0:1080"
      handshake_timeout: 15
      auth:
        type: password
        users:
          - username: admin
            password: secret123
```

#### 使用方式

```bash
# 无认证
curl --socks5 127.0.0.1:1080 https://example.com

# 用户名/密码认证
curl --socks5-basic --socks5-hostname 127.0.0.1:1080 \
     --proxy-user user1:pass1 https://example.com
```

---

## Service 详解

### 1. connect_tcp

TCP 隧道服务，连接目标服务器并转发数据。通常与 Listener 配合使用。

#### 配置示例

```yaml
services:
  - name: tunnel
    kind: connect_tcp.connect_tcp

servers:
  - service: tunnel
    listeners:
      - kind: hyper.listener
        args:
          addresses: ["0.0.0.0:8080"]
```

#### 支持的协议

- HTTP CONNECT（通过 `hyper.listener`）
- SOCKS5 CONNECT（通过 `fast_socks5.listener`）
- HTTP/3 CONNECT（通过 `http3.listener`）

---

### 2. http3_chain

HTTP/3 代理链服务，通过 HTTP/3 协议连接到上游代理服务器。

**适用场景：** 利用 QUIC 的弱网能力，在不稳定网络环境下建立代理链。

#### 配置参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `proxy_group` | `[Object]` | 是 | 上游代理组 |
| `ca_path` | `String` | 是 | CA 证书路径（用于验证上游代理） |

proxy_group 条目格式：

| 参数 | 类型 | 说明 |
|------|------|------|
| `address` | `String` | 上游代理地址 `host:port` |
| `weight` | `usize` | 权重（负载均衡用） |

#### 配置示例

```yaml
services:
  - name: proxy_chain
    kind: http3_chain.http3_chain
    args:
      proxy_group:
        - address: "upstream1.example.com:443"
          weight: 1
        - address: "upstream2.example.com:443"
          weight: 2
      ca_path: /path/to/ca.pem

servers:
  - service: proxy_chain
    listeners:
      - kind: hyper.listener
        args:
          addresses: ["0.0.0.0:8080"]
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
  - service: tunnel
    listeners:
      - kind: http3.listener
        args:
          address: "0.0.0.0:443"
          cert_path: /path/to/cert.pem
          key_path: /path/to/key.pem
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
  - service: echo_service
    listeners:
      - kind: hyper.listener
        args:
          addresses: ["0.0.0.0:8080"]
```

#### 使用方式

```bash
curl -X POST -d "Hello World" http://127.0.0.1:8080
# 返回: Hello World
```

---

## 完整配置示例

### 示例 1：HTTP 代理服务器

```yaml
worker_threads: 2
log_directory: logs/

services:
  - name: tunnel
    kind: connect_tcp.connect_tcp

servers:
  - name: http_proxy
    service: tunnel
    listeners:
      - kind: hyper.listener
        args:
          addresses:
            - "0.0.0.0:8080"
```

### 示例 2：SOCKS5 代理服务器（带认证）

```yaml
worker_threads: 2
log_directory: logs/

services:
  - name: tunnel
    kind: connect_tcp.connect_tcp

servers:
  - name: socks5_proxy
    service: tunnel
    listeners:
      - kind: fast_socks5.listener
        args:
          addresses:
            - "0.0.0.0:1080"
          auth:
            type: password
            users:
              - username: admin
                password: secret123
```

### 示例 3：HTTP/3 代理服务器（带认证）

```yaml
worker_threads: 2
log_directory: logs/

services:
  - name: tunnel
    kind: connect_tcp.connect_tcp

servers:
  - name: http3_proxy
    service: tunnel
    listeners:
      - kind: http3.listener
        args:
          address: "0.0.0.0:443"
          cert_path: /etc/neoproxy/cert.pem
          key_path: /etc/neoproxy/key.pem
          auth:
            type: password
            users:
              - username: admin
                password: secret123
```

### 示例 4：HTTP/3 代理链

**本地节点配置：**

```yaml
worker_threads: 2
log_directory: logs/

services:
  - name: chain
    kind: http3_chain.http3_chain
    args:
      proxy_group:
        - address: "remote.example.com:443"
          weight: 1
      ca_path: /etc/neoproxy/ca.pem

servers:
  - name: local_proxy
    service: chain
    listeners:
      - kind: hyper.listener
        args:
          addresses: ["0.0.0.0:8080"]
```

**远程节点配置：**

```yaml
worker_threads: 2
log_directory: logs/

services:
  - name: tunnel
    kind: connect_tcp.connect_tcp

servers:
  - name: remote_proxy
    service: tunnel
    listeners:
      - kind: http3.listener
        args:
          address: "0.0.0.0:443"
          cert_path: /etc/neoproxy/cert.pem
          key_path: /etc/neoproxy/key.pem
```

---

## 日志

日志文件按日期滚动，存储在 `log_directory` 配置的目录中。

日志级别通过环境变量 `NEOPROXY_LOG` 控制：

```bash
# 设置日志级别
export NEOPROXY_LOG=debug
./neoproxy --config conf/server.yaml
```

支持的日志级别：`trace`, `debug`, `info`, `warn`, `error`

---

## 信号处理

neoproxy 支持优雅关闭：

- `SIGINT` (Ctrl+C)：触发优雅关闭
- `SIGTERM`：触发优雅关闭

优雅关闭流程：
1. 停止接收新连接
2. 等待现有连接完成（超时 5 秒）
3. 强制关闭剩余连接
4. 退出程序

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