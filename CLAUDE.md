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

**部署方式 A**: systemd --user

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

**部署方式 B**: status.sh（nohup + 自动重启循环）

```bash
# 构建 & 部署
cargo build --release
cp target/release/neoproxy ~/services/neoproxy/bin/

# 启动 / 停止 / 重启 / 状态
~/services/neoproxy/bin/status.sh start
~/services/neoproxy/bin/status.sh stop
~/services/neoproxy/bin/status.sh restart
~/services/neoproxy/bin/status.sh status

# 查看日志
tail -f ~/services/neoproxy/logs/stdout.log
```

**`bin/status.sh` 文件**: `~/services/neoproxy/bin/status.sh`

```bash
#!/bin/bash

CMD="bin/neoproxy -c conf/server.yaml"
. "$(dirname "$0")/../../status.sh"
```

> **注意**: 两种方式的配置等都要维护（目录结构、配置文件互不冲突）。启停优先用 systemctl，systemctl 不可用时再用 status.sh。

**配置**: `~/services/neoproxy/conf/server.yaml`

**验证**:
```bash
curl -x http://127.0.0.1:8080 http://www.google.com/ -s -o /dev/null -w "%{http_code}\n"
# 应返回 200
```

