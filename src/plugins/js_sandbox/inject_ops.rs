use deno_core::{OpState, op2};
use deno_error::JsErrorBox;

use crate::plugins::js_sandbox::request::{
  IncomingRequest, OutgoingResponse,
};

/// Read the injected request data from OpState. Called from JS bridge
/// script.
#[op2]
#[serde]
pub fn op_sandbox_read_request(
  state: &mut OpState,
) -> Result<SerdeIncomingRequest, JsErrorBox> {
  let req = state
    .try_take::<IncomingRequest>()
    .ok_or_else(|| JsErrorBox::generic("no injected request"))?;
  Ok(SerdeIncomingRequest {
    method: req.method,
    url: req.url,
    headers: req.headers,
    body: req.body,
  })
}

/// Write the response data into OpState. Called from JS bridge script.
#[op2]
pub fn op_sandbox_write_response(
  state: &mut OpState,
  #[smi] status: u32,
  #[serde] headers: Vec<(String, String)>,
  #[buffer] body: &[u8],
) -> Result<(), JsErrorBox> {
  if !(100..=599).contains(&status) {
    return Err(JsErrorBox::type_error(format!(
      "invalid status code: {status}"
    )));
  }
  state.put(OutgoingResponse {
    status: status as u16,
    headers,
    body: body.to_vec(),
  });
  Ok(())
}

#[derive(serde::Serialize)]
struct SerdeIncomingRequest {
  method: String,
  url: String,
  headers: Vec<(String, String)>,
  body: Vec<u8>,
}
