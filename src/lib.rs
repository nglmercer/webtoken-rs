
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod argon;
mod scrypt;
mod paseto;
mod opaque;

#[cfg(feature = "napi-base")]
use napi::bindgen_prelude::*;
#[cfg(feature = "napi-base")]
use napi_derive::napi;
#[cfg(feature = "napi-base")]
use serde_json::{Value, Map};

#[cfg(feature = "napi-base")]
#[napi]
pub async fn hash(password: String, iterations: Option<u32>, memory: Option<u32>, parallelism: Option<u32>) -> Result<String> {
    tokio::task::spawn_blocking(move || {
        argon::internal_hash(password, iterations, memory, parallelism)
    })
    .await
    .map_err(|e| Error::from_reason(format!("Task join error: {}", e)))?
    .map_err(|e| Error::from_reason(e))
}

#[cfg(feature = "napi-base")]
#[napi]
pub async fn scrypt_hash(password: String, log_n: Option<u8>, r: Option<u32>, p: Option<u32>) -> Result<String> {
    tokio::task::spawn_blocking(move || {
        scrypt::internal_scrypt_hash(password, log_n, r, p)
    })
    .await
    .map_err(|e| Error::from_reason(format!("Task join error: {}", e)))?
    .map_err(|e| Error::from_reason(e))
}

#[cfg(feature = "napi-base")]
#[napi(object)]
pub struct OpaqueRegisterStartResult {
  pub request: String,
  pub state: String,
}

#[cfg(feature = "napi-base")]
#[napi(object)]
pub struct OpaqueRegisterFinishResult {
  pub upload: String,
  pub export_key: String,
}

#[cfg(feature = "napi-base")]
#[napi(object)]
pub struct OpaqueLoginStartResult {
  pub request: String,
  pub state: String,
}

#[cfg(feature = "napi-base")]
#[napi(object)]
pub struct OpaqueServerLoginStartResult {
  pub response: String,
  pub state: String,
}

#[cfg(feature = "napi-base")]
#[napi(object)]
pub struct OpaqueLoginFinishResult {
  pub finalization: String,
  pub session_key: String,
  pub export_key: String,
  pub server_public_key: String,
}

#[cfg(feature = "napi-base")]
#[napi]
pub async fn compare(password: String, hash: String) -> Result<bool> {
    tokio::task::spawn_blocking(move || {
        argon::internal_compare(password, hash)
    })
    .await
    .map_err(|e| Error::from_reason(format!("Task join error: {}", e)))?
    .map_err(|e| Error::from_reason(e))
}

#[cfg(feature = "napi-base")]
#[napi]
pub async fn scrypt_compare(password: String, hash: String) -> Result<bool> {
    tokio::task::spawn_blocking(move || {
        scrypt::internal_scrypt_compare(password, hash)
    })
    .await
    .map_err(|e| Error::from_reason(format!("Task join error: {}", e)))?
    .map_err(|e| Error::from_reason(e))
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn create(payload: Map<String, Value>, secret: String, expires_in_seconds: Option<i64>) -> Result<String> {
    paseto::internal_create_local(payload, secret, expires_in_seconds).map_err(|e| Error::from_reason(e))
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn verify(token: String, secret: String) -> Result<Map<String, Value>> {
    paseto::internal_verify_local(&token, &secret).map_err(|e| Error::from_reason(e))
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn create_public(payload: Map<String, Value>, secret_key_hex: String, expires_in_seconds: Option<i64>) -> Result<String> {
    paseto::internal_create_public(payload, &secret_key_hex, expires_in_seconds).map_err(|e| Error::from_reason(e))
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn verify_public(token: String, public_key_hex: String) -> Result<Map<String, Value>> {
    paseto::internal_verify_public(&token, &public_key_hex).map_err(|e| Error::from_reason(e))
}

#[cfg(feature = "napi-base")]
#[napi(object)]
pub struct KeyGenerationResult {
  pub secret_key: String,
  pub public_key: String,
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn generate_keys() -> Result<KeyGenerationResult> {
    let (sk, pk) = paseto::internal_generate_keys();
    Ok(KeyGenerationResult {
        secret_key: sk,
        public_key: pk,
    })
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn opaque_generate_server_setup() -> String {
    opaque::internal_opaque_server_setup()
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn opaque_client_register_start(password: String) -> Result<OpaqueRegisterStartResult> {
    let res = opaque::internal_client_register_start(&password).map_err(|e| Error::from_reason(e))?;
    Ok(OpaqueRegisterStartResult {
        request: res.request,
        state: res.state,
    })
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn opaque_server_register_start(server_setup_hex: String, request_hex: String, client_id: String) -> Result<String> {
    opaque::internal_server_register_start(&server_setup_hex, &request_hex, &client_id).map_err(|e| Error::from_reason(e))
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn opaque_client_register_finish(
    password: String,
    response_hex: String,
    state_hex: String,
    client_id: Option<String>,
    server_id: Option<String>,
) -> Result<OpaqueRegisterFinishResult> {
    let res = opaque::internal_client_register_finish(&password, &response_hex, &state_hex, client_id, server_id)
        .map_err(|e| Error::from_reason(e))?;
    Ok(OpaqueRegisterFinishResult {
        upload: res.upload,
        export_key: res.export_key,
    })
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn opaque_server_register_finish(upload_hex: String) -> Result<String> {
    opaque::internal_server_register_finish(&upload_hex).map_err(|e| Error::from_reason(e))
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn opaque_client_login_start(password: String) -> Result<OpaqueLoginStartResult> {
    let res = opaque::internal_client_login_start(&password).map_err(|e| Error::from_reason(e))?;
    Ok(OpaqueLoginStartResult {
        request: res.request,
        state: res.state,
    })
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn opaque_server_login_start(
    server_setup_hex: String,
    password_file_hex: String,
    request_hex: String,
    client_id: String,
    server_id: Option<String>,
) -> Result<OpaqueServerLoginStartResult> {
    let res = opaque::internal_server_login_start(&server_setup_hex, &password_file_hex, &request_hex, &client_id, server_id)
        .map_err(|e| Error::from_reason(e))?;
    Ok(OpaqueServerLoginStartResult {
        response: res.response,
        state: res.state,
    })
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn opaque_client_login_finish(
    password: String,
    response_hex: String,
    state_hex: String,
    client_id: Option<String>,
    server_id: Option<String>,
) -> Result<OpaqueLoginFinishResult> {
    let res = opaque::internal_client_login_finish(&password, &response_hex, &state_hex, client_id, server_id)
        .map_err(|e| Error::from_reason(e))?;
    Ok(OpaqueLoginFinishResult {
        finalization: res.finalization,
        session_key: res.session_key,
        export_key: res.export_key,
        server_public_key: res.server_public_key,
    })
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn opaque_server_login_finish(finalization_hex: String, state_hex: String) -> Result<String> {
    opaque::internal_server_login_finish(&finalization_hex, &state_hex).map_err(|e| Error::from_reason(e))
}

#[cfg(feature = "napi-base")]
#[napi(object)]
pub struct TokenParsed {
    pub version: String,
    pub purpose: String,
    pub payload: String,
    pub footer: String,
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn parse_paseto(token: String) -> Result<TokenParsed> {
    let parts = paseto::parse_token(&token).map_err(|e| Error::from_reason(e))?;
    Ok(TokenParsed {
        version: parts.version.to_string(),
        purpose: parts.purpose.to_string(),
        payload: parts.payload.to_string(),
        footer: parts.footer.to_string(),
    })
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn decode_public_payload(token: String) -> Result<Map<String, Value>> {
    paseto::decode_public_payload(&token).map_err(|e| Error::from_reason(e))
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn decode_token(_token: String) -> Result<Map<String, Value>> {
    Err(Error::from_reason("PASETO local tokens are encrypted and cannot be decoded without the secret key."))
}
