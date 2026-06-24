/// Per-request sandbox configuration, derived from HTTP request headers
/// and the plugin's default settings.
#[derive(Debug, Clone)]
pub(crate) struct SandboxConfig {
  pub(crate) sandbox_id: String,
  pub(crate) heap_limit_bytes: usize,
  pub(crate) cpu_limit_us: u32,
  pub(crate) source_code: String,
}

/// Incoming HTTP request data sent to the sandbox thread.
#[derive(Debug)]
pub(crate) struct IncomingRequest {
  pub(crate) method: String,
  pub(crate) url: String,
  pub(crate) headers: Vec<(String, String)>,
  pub(crate) body: Vec<u8>,
}

/// Outgoing HTTP response data returned from the sandbox thread.
#[derive(Debug)]
pub(crate) struct OutgoingResponse {
  pub(crate) status: u16,
  pub(crate) headers: Vec<(String, String)>,
  pub(crate) body: Vec<u8>,
}
