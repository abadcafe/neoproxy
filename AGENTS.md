# NeoProxy

## 开发铁律（不可违反）

- 所有语言都要像 Rust 一样强类型，编译期解决所有类型错误，禁止忽略和跳过
- 任何代码修改后都必须全量验证: 1. 格式化 2. 检查 3. 单测 4. 集测

### 1. Python：100% 类型注解，0 编译警告和错误

技术栈: uv, Python >= 3.14, Pydantic v2, Pytest, 使用pyproject.toml

强类型约束:
- **所有 Python 代码（包括 `*_tests.py`）必须有完整的类型注解**
- 必须像 Rust 一样强类型，编译期解决所有类型错误，禁止忽略和跳过
- 必须使用 `type` 类型别名语法和泛型函数语法
- 禁止使用 `# pyright: ignore` 和 `# type: ignore` 等方式掩盖错误
- 优先使用 `Pydantic` 而不是 `cast`

禁止抛异常:
- 所有业务错误必须用 Result/Optional 机制处理（如 `Ok[T] | Error`），像 Rust 一样
- **禁止捕获** `AssertionError`、`IndexError`、`KeyError`、`TypeError`、`RuntimeError` 等编程错误，就让它崩溃暴露 bug
- 第三方库抛出的异常如果是正常流程控制（例如网络错误处理等），则必须在调用点尽量窄地捕获并正确处理, **其他情况禁止捕获**，就让它崩溃暴露 bug
- 测试代码中用 `assert isinstance(result, Ok)` / `assert isinstance(result, Error)` 替代 `pytest.raises`

各种验证:
1. `uv run ruff format`         # 全量格式化
2. `uv run ruff format --check` # 0 警告和错误
3. `uv run ruff check`          # 0 警告和错误
4. `uv run basedpyright`        # 0 警告和错误
5. `uv run pytest`              # 测试全部通过, 禁止跳过

### 2. Rust：0 编译警告和错误

各种验证:
1. `cargo +nightly fmt --all`         # 全量格式化
2. `cargo +nightly fmt --all --check` # 0 警告和错误
3. `cargo clippy --workspace --all-targets -- -D warnings` # 0 警告和错误
4. `cargo build`                           # 0 警告和错误
5. `cargo test --workspace --no-fail-fast` # 单测全部通过, 禁止跳过
6. `uv run pytest`                         # 集测全部通过, 禁止跳过

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
