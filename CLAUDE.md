# CLAUDE.md

Coding agent guidelines for the neoproxy project.

## Project Overview

Neoproxy is a Rust-based proxy server using async Tokio runtime, Hyper HTTP server,
and Tower middleware. It features a plugin architecture where services and listeners
are built dynamically from YAML configuration.

Supported protocols: HTTP/1.1, HTTP/2, HTTP/3 (QUIC), SOCKS5.

## Build Commands

```bash
cargo build              # Build the project
cargo build --release    # Build in release mode
cargo run                # Run the server
cargo run -- --config path/to/config.yaml  # Run with custom config
cargo fmt                # Format code
cargo clippy             # Run linter
cargo test               # Run all tests
cargo test test_name     # Run a single test by name
cargo check              # Check for compilation errors
```

## Code Style

- Indentation: 2 spaces
- Max line width: 72 characters
- Always run `cargo fmt` before committing

### Import Order

1. Standard library (`use std::...`)
2. External crates (`use anyhow::...`, `use tokio::...`)
3. Local crate (`use crate::...`)

### Naming Conventions

- Types/Structs/Traits: PascalCase
- Functions/Methods: snake_case
- Constants: SCREAMING_SNAKE_CASE
- Module names: snake_case

### Error Handling

- Use `anyhow::Result` for fallible operations
- Use `.with_context()` to add context
- Propagate errors with `?` operator

### Async Patterns

- Use `tokio::task::LocalSet` for single-threaded async execution
- Use `Rc<RefCell<T>>` for shared mutable state within a thread
- Use `Arc<sync::Notify>` for cross-thread signaling

## Plugin Architecture

Plugins implement the `Plugin` trait and expose:
- `plugin_name() -> &'static str`: Plugin identifier
- `create_plugin() -> Box<dyn Plugin>`: Factory function

Service builders: `Fn(SerializedArgs) -> Result<Service>`

Listener builders: `Fn(SerializedArgs, Service) -> Result<Listener>`

## Type Aliases

```rust
pub type RequestBody = UnsyncBoxBody<Bytes, anyhow::Error>;
pub type ResponseBody = UnsyncBoxBody<Bytes, anyhow::Error>;
pub type Request = http::Request<RequestBody>;
pub type Response = http::Response<ResponseBody>;
pub type SerializedArgs = serde_yaml::Value;
```

## Available Plugins

**Services**
- `echo.echo` - Echo service for testing
- `connect_tcp.connect_tcp` - HTTP CONNECT TCP tunneling
- `http3_chain.http3_chain` - HTTP/3 proxy chain with WRR load balancing

**Listeners**
- `hyper.hyper` - HTTP/1.1 listener (only CONNECT method supported)
- `fast_socks5.listener` - SOCKS5 proxy listener with optional authentication
- `http3.listener` - HTTP/3 (QUIC) listener

## File Structure

```
src/
  main.rs         # Entry point
  config.rs       # Configuration parsing
  plugin.rs       # Plugin traits and Service/Listener types
  plugins.rs      # Plugin registry
  server.rs       # Server management
  shutdown.rs     # Graceful shutdown coordination
  plugins/
    echo.rs           # Echo service
    hyper.rs          # HTTP/1.1 listener
    connect_tcp.rs    # TCP proxy
    http3_chain.rs    # HTTP/3 chain proxy
    fast_socks5.rs    # SOCKS5 listener
    http3.rs    # HTTP/3 listener
    utils.rs          # Utilities (TransferingSet, etc.)
```

## Configuration

Config files are YAML. Default path: `conf/server.yaml`.

Services are referenced by `kind` as `plugin_name.service_name`.
Listeners are referenced by `kind` as `plugin_name.listener_name`.

## 代码导航策略

- 用 Grep/Glob 做发现（找文件、搜模式）
- 用 LSP 做理解（定义跳转、引用查找、类型信息）
- 找到文件后，优先用 LSP 导航，而不是读取整个文件
