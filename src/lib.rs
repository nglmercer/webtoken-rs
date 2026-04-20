use cfg_if::cfg_if;

mod argon;
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
pub fn create(payload: Map<String, Value>, secret: String, expires_in_seconds: Option<i64>) -> Result<String> {
    paseto::internal_create_local(payload, secret, expires_in_seconds).map_err(|e| Error::from_reason(e))
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn verify(token: String, secret: String) -> Result<Map<String, Value>> {
    paseto::internal_verify_local(token, secret).map_err(|e| Error::from_reason(e))
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn create_public(payload: Map<String, Value>, secret_key_hex: String, expires_in_seconds: Option<i64>) -> Result<String> {
    paseto::internal_create_public(payload, secret_key_hex, expires_in_seconds).map_err(|e| Error::from_reason(e))
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn verify_public(token: String, public_key_hex: String) -> Result<Map<String, Value>> {
    paseto::internal_verify_public(token, public_key_hex).map_err(|e| Error::from_reason(e))
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn generate_keys() -> Result<Map<String, Value>> {
    let (sk, pk) = paseto::internal_generate_keys();
    let mut map = Map::new();
    map.insert("secretKey".to_string(), Value::String(sk));
    map.insert("publicKey".to_string(), Value::String(pk));
    Ok(map)
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn opaque_generate_server_setup() -> String {
    opaque::internal_opaque_server_setup()
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn opaque_client_register_start(password: String) -> Result<Map<String, Value>> {
    let res = opaque::internal_client_register_start(&password).map_err(|e| Error::from_reason(e))?;
    let mut map = Map::new();
    map.insert("request".to_string(), Value::String(res.request));
    map.insert("state".to_string(), Value::String(res.state));
    Ok(map)
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
) -> Result<Map<String, Value>> {
    let res = opaque::internal_client_register_finish(&password, &response_hex, &state_hex, client_id, server_id)
        .map_err(|e| Error::from_reason(e))?;
    let mut map = Map::new();
    map.insert("upload".to_string(), Value::String(res.upload));
    map.insert("exportKey".to_string(), Value::String(res.export_key));
    Ok(map)
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn opaque_server_register_finish(upload_hex: String) -> Result<String> {
    opaque::internal_server_register_finish(&upload_hex).map_err(|e| Error::from_reason(e))
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn opaque_client_login_start(password: String) -> Result<Map<String, Value>> {
    let res = opaque::internal_client_login_start(&password).map_err(|e| Error::from_reason(e))?;
    let mut map = Map::new();
    map.insert("request".to_string(), Value::String(res.request));
    map.insert("state".to_string(), Value::String(res.state));
    Ok(map)
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn opaque_server_login_start(
    server_setup_hex: String,
    password_file_hex: String,
    request_hex: String,
    client_id: String,
    server_id: Option<String>,
) -> Result<Map<String, Value>> {
    let res = opaque::internal_server_login_start(&server_setup_hex, &password_file_hex, &request_hex, &client_id, server_id)
        .map_err(|e| Error::from_reason(e))?;
    let mut map = Map::new();
    map.insert("response".to_string(), Value::String(res.response));
    map.insert("state".to_string(), Value::String(res.state));
    Ok(map)
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn opaque_client_login_finish(
    password: String,
    response_hex: String,
    state_hex: String,
    client_id: Option<String>,
    server_id: Option<String>,
) -> Result<Map<String, Value>> {
    let res = opaque::internal_client_login_finish(&password, &response_hex, &state_hex, client_id, server_id)
        .map_err(|e| Error::from_reason(e))?;
    let mut map = Map::new();
    map.insert("finalization".to_string(), Value::String(res.finalization));
    map.insert("sessionKey".to_string(), Value::String(res.session_key));
    map.insert("exportKey".to_string(), Value::String(res.export_key));
    map.insert("serverPublicKey".to_string(), Value::String(res.server_public_key));
    Ok(map)
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn opaque_server_login_finish(finalization_hex: String, state_hex: String) -> Result<String> {
    opaque::internal_server_login_finish(&finalization_hex, &state_hex).map_err(|e| Error::from_reason(e))
}

#[cfg(feature = "napi-base")]
#[napi]
pub fn decode_token(_token: String) -> Result<Map<String, Value>> {
    Err(Error::from_reason("PASETO local tokens are encrypted and cannot be decoded without the secret key."))
}

cfg_if! {
    if #[cfg(feature = "wasm")] {
        use wasm_bindgen::prelude::*;
        use serde_json::{Value, Map};

        #[wasm_bindgen]
        pub fn hash_wasm(password: String) -> String {
            argon::internal_hash(password, None, None, None).unwrap_or_default()
        }

        #[wasm_bindgen]
        pub fn compare_wasm(password: String, hash: String) -> bool {
            argon::internal_compare(password, hash).unwrap_or(false)
        }

        #[wasm_bindgen]
        pub fn create_wasm(payload_json: String, secret: String, expires_in_seconds: Option<i64>) -> String {
            let payload: Map<String, Value> = serde_json::from_str(&payload_json).unwrap_or_default();
            paseto::internal_create_local(payload, secret, expires_in_seconds).unwrap_or_default()
        }

        #[wasm_bindgen]
        pub fn verify_wasm(token: String, secret: String) -> String {
            let res = paseto::internal_verify_local(token, secret).unwrap_or_default();
            serde_json::to_string(&res).unwrap_or_default()
        }
    }
}
