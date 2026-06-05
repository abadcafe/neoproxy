# NeoProxy

## 开发

```bash
cargo build
cargo test                    # 单元测试
cargo test --release          # 集成测试也需要先编译 release 二进制
uv run pytest -v tests/integration/  # 集成测试（295个）
```

**注意**: 集成测试（`tests/integration/`）是 Python 编写的，需要先编译 release 二进制再运行。

## 本地部署

**部署目录**: `~/services/neoproxy/`

**部署方式**: systemd --user，**禁止使用 nohup / 直接后台启动**。

```bash
# 构建
cargo build --release

# 部署
cp target/release/neoproxy ~/services/neoproxy/bin/

# 重启
systemctl --user daemon-reload
systemctl --user restart neoproxy.service

# 查看状态
systemctl --user --no-pager status neoproxy.service

# 查看日志
journalctl --user -u neoproxy.service -n 50 --no-pager
# 或直接看日志文件（日志文件轮转日期后缀）：
tail -f ~/services/neoproxy/logs/neoproxy.log.2026-06-05
tail -f ~/services/neoproxy/logs/access.log.2026-06-05
```

**Service 文件**: `~/.config/systemd/user/neoproxy.service`

```ini
[Unit]
Description=NeoProxy (local — p.fwcoding.tech relay)
After=network.target

[Service]
Type=simple
ExecStart=%h/services/neoproxy/bin/neoproxy -c conf/server.yaml
WorkingDirectory=%h/services/neoproxy
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

**配置**: `~/services/neoproxy/conf/server.yaml`

**验证**:
```bash
curl -x http://127.0.0.1:8080 http://www.google.com/ -s -o /dev/null -w "%{http_code}\n"
# 应返回 200
```

## 项目架构

- `src/main.rs` — 入口，信号处理，主循环
- `src/listener.rs` — `Listener`, `Listening`, `BuildListener`, `ListenerProps`, `TransportLayer` 等抽象
- `src/listeners/` — 具体 listener 实现 (http, https, http3, socks5) + 注册表 `ListenerManager`
- `src/plugins/http_upstream/` — 上游代理转发插件，支持 HTTP/HTTPS/H3 协议
- `src/config/` — 配置加载、验证（三态继承）
- `tests/integration/` — Python 集成测试（pytest）

