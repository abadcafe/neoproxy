use std::sync::Arc;

use deno_core::{
  JsRuntime, ModuleCodeString, ModuleSpecifier, PollEventLoopOptions,
  RuntimeOptions, extension,
};
use deno_ext_fetch::FetchOptions;
use deno_ext_web::BlobStore;
use tracing::error;

use crate::plugins::js_sandbox::cpu_sandbox::CPUTimerScope;
use crate::plugins::js_sandbox::request::{
  IncomingRequest, OutgoingResponse, SandboxConfig,
};
use crate::plugins::js_sandbox::{inject_ops, mem_sandbox};

extension!(
  neoproxy_sandbox,
  ops = [
    inject_ops::op_sandbox_read_request,
    inject_ops::op_sandbox_write_response,
  ],
);

/// Combined script that loads Web API globals, then reads the request
/// from OpState, calls the user's fetch handler, and writes the response
/// back to OpState. deno_fetch/deno_web extensions use `lazy_loaded_js`
/// which are NOT auto-evaluated at startup — we must load them via
/// `Deno.core.loadExtScript()` and put the constructors on globalThis.
const BOOT_SCRIPT: &str = r#"
(async () => {
  var load = Deno.core.loadExtScript;

  // deno_fetch (cascades to load deno_web + deno_webidl deps)
  var h = load("ext:deno_fetch/20_headers.js");
  var fd = load("ext:deno_fetch/21_formdata.js");
  var req = load("ext:deno_fetch/23_request.js");
  var resp = load("ext:deno_fetch/23_response.js");
  var f = load("ext:deno_fetch/26_fetch.js");

  // deno_web (some already loaded as transitive deps above)
  var url = load("ext:deno_web/00_url.js");
  var domEx = load("ext:deno_web/01_dom_exception.js");
  var evt = load("ext:deno_web/02_event.js");
  var abort = load("ext:deno_web/03_abort_signal.js");
  var streams = load("ext:deno_web/06_streams.js");
  var blob = load("ext:deno_web/09_file.js");
  var mp = load("ext:deno_web/13_message_port.js");

  // Fetch API
  globalThis.Headers = h.Headers;
  globalThis.FormData = fd.FormData;
  globalThis.Request = req.Request;
  globalThis.Response = resp.Response;
  globalThis.fetch = f.fetch;

  // URL API
  globalThis.URL = url.URL;
  globalThis.URLSearchParams = url.URLSearchParams;

  // DOM / Events
  globalThis.DOMException = domEx.DOMException;
  globalThis.Event = evt.Event;
  globalThis.EventTarget = evt.EventTarget;
  globalThis.AbortController = abort.AbortController;
  globalThis.AbortSignal = abort.AbortSignal;

  // Streams
  globalThis.ReadableStream = streams.ReadableStream;
  globalThis.WritableStream = streams.WritableStream;
  globalThis.TransformStream = streams.TransformStream;

  // Blob / File
  globalThis.Blob = blob.Blob;
  globalThis.File = blob.File;

  // MessageChannel
  globalThis.MessageChannel = mp.MessageChannel;
  globalThis.MessagePort = mp.MessagePort;

  try {
    const reqData = Deno.core.ops.op_sandbox_read_request();
    // Request() requires a full URL; prepend a synthetic base for relative paths
    const reqUrl = reqData.url.startsWith("http") ? reqData.url
      : "http://sandbox.local" + (reqData.url.startsWith("/") ? "" : "/") + reqData.url;
    const req = new Request(reqUrl, {
      method: reqData.method,
      headers: new Headers(Object.fromEntries(reqData.headers)),
      body: reqData.method !== "GET" && reqData.method !== "HEAD" ? new Uint8Array(reqData.body) : undefined,
    });

    const mod = await import("sandbox://entry.js");
    const handler = mod.default;
    if (!handler || typeof handler.fetch !== "function") {
      throw new TypeError("module must export default { fetch(request) }");
    }

    const resp = await handler.fetch(req);

    const headers = [];
    resp.headers.forEach((v, k) => headers.push([k, v]));
    let body;
    if (resp.status === 204 || resp.status === 304) {
      body = new Uint8Array(0);
    } else {
      const ab = await resp.arrayBuffer();
      body = new Uint8Array(ab);
    }

    Deno.core.ops.op_sandbox_write_response(resp.status, headers, body);
  } catch (e) {
    Deno.core.ops.op_sandbox_write_response(502, [["x-sandbox-error", String(e)]], new Uint8Array(0));
  }
})();
"#;

/// A per-request V8 sandbox.
pub struct Sandbox {
  runtime: JsRuntime,
  config: SandboxConfig,
}

impl Sandbox {
  /// Create a new sandbox with the given configuration.
  pub fn new(config: SandboxConfig) -> anyhow::Result<Self> {
    // Ensure rustls CryptoProvider is installed (needed for outbound
    // fetch TLS)
    let _ = rustls::crypto::ring::default_provider().install_default();

    let heap_limit_bytes = config.heap_limit_bytes;
    let allocator =
      mem_sandbox::TrackingAllocator::new(heap_limit_bytes * 2);
    let v8_allocator = allocator.clone().get_allocator();

    let create_params = deno_core::v8::CreateParams::default()
      .heap_limits(heap_limit_bytes, heap_limit_bytes * 2)
      .array_buffer_allocator(v8_allocator);

    let blob_store = Arc::new(BlobStore::default());
    let fetch_options = FetchOptions::default();

    let mut runtime = JsRuntime::new(RuntimeOptions {
      extensions: vec![
        deno_ext_webidl::deno_webidl::init(),
        deno_ext_web::deno_web::init(Arc::clone(&blob_store), None),
        deno_tls::deno_tls::init(),
        deno_ext_fetch::deno_fetch::init(fetch_options),
        neoproxy_sandbox::init(),
      ],
      create_params: Some(create_params),
      ..Default::default()
    });

    mem_sandbox::install_heap_limit_callback(
      &mut runtime,
      heap_limit_bytes,
    );

    Ok(Self { runtime, config })
  }

  /// Execute the sandbox: inject request, run JS handler, extract
  /// response.
  pub fn execute(
    mut self,
    request: IncomingRequest,
  ) -> anyhow::Result<OutgoingResponse> {
    let request_id = self.config.sandbox_id.clone();
    let isolate_handle = self.runtime.v8_isolate().thread_safe_handle();
    let cpu_limit_us = self.config.cpu_limit_us;

    let _cpu_timer = CPUTimerScope::new(
      cpu_limit_us,
      request_id.clone(),
      isolate_handle,
    )?;

    // Put request into OpState so op_sandbox_read_request can retrieve
    // it
    {
      let state = self.runtime.op_state();
      state.borrow_mut().put(request);
    }

    // We need a tokio runtime to drive async operations
    let rt = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()?;

    rt.block_on(async {
      // Load the user ESM module
      let specifier = ModuleSpecifier::parse("sandbox://entry.js")
        .map_err(|e| {
          anyhow::anyhow!("invalid module specifier: {e}")
        })?;
      let code =
        ModuleCodeString::from(self.config.source_code.clone());

      let module_id = self
        .runtime
        .load_side_es_module_from_code(&specifier, code)
        .await?;

      let _ = self.runtime.mod_evaluate(module_id);
      self
        .runtime
        .run_event_loop(PollEventLoopOptions::default())
        .await?;

      // Run the bridge script that calls the user's fetch handler
      self.runtime.execute_script(
        "<neoproxy_bridge>",
        ModuleCodeString::from(BOOT_SCRIPT.to_string()),
      )?;

      // Drive the event loop until completion
      self
        .runtime
        .run_event_loop(PollEventLoopOptions::default())
        .await?;

      // Extract response from OpState
      let response = {
        let state = self.runtime.op_state();
        state.borrow_mut().try_take::<OutgoingResponse>()
      };

      match response {
        Some(resp) => Ok(resp),
        None => {
          error!(
            "No response extracted from sandbox for request {}",
            request_id
          );
          Err(anyhow::anyhow!("sandbox produced no response"))
        }
      }
    })
  }
}
