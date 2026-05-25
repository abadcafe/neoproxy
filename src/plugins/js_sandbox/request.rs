/// Per-request sandbox configuration, derived from HTTP request headers
/// and the plugin's default settings.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
  pub sandbox_id: String,
  pub heap_limit_bytes: usize,
  pub cpu_limit_us: u32,
  pub source_code: String,
}

/// Incoming HTTP request data sent to the sandbox thread.
#[derive(Debug)]
pub struct IncomingRequest {
  pub method: String,
  pub url: String,
  pub headers: Vec<(String, String)>,
  pub body: Vec<u8>,
}

/// Outgoing HTTP response data returned from the sandbox thread.
#[derive(Debug)]
pub struct OutgoingResponse {
  pub status: u16,
  pub headers: Vec<(String, String)>,
  pub body: Vec<u8>,
}
