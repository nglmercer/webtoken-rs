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
