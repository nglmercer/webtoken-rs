use napi::bindgen_prelude::*;
use napi_derive::napi;
use bcrypt::{hash as bcrypt_hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};

#[napi]
pub fn hash(password: String, cost: Option<u32>) -> Result<String> {
    bcrypt_hash(password, cost.unwrap_or(DEFAULT_COST))
        .map_err(|e| Error::from_reason(format!("Bcrypt hashing error: {}", e)))
}

#[napi]
pub fn compare(password: String, hash: String) -> Result<bool> {
    verify(password, &hash)
        .map_err(|e| Error::from_reason(format!("Bcrypt comparison error: {}", e)))
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
}

#[napi]
pub fn create(sub: String, secret: String, expires_in_seconds: i64) -> Result<String> {
    let now = Utc::now();
    let expiration = now
        .checked_add_signed(Duration::seconds(expires_in_seconds))
        .ok_or_else(|| Error::from_reason("Invalid expiration time"))?
        .timestamp();

    let claims = Claims {
        sub,
        exp: expiration as usize,
        iat: now.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|e| Error::from_reason(format!("JWT creation error: {}", e)))
}
