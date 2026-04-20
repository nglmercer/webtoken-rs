use napi::bindgen_prelude::*;
use napi_derive::napi;
use bcrypt::{hash as bcrypt_hash, verify as bcrypt_verify, DEFAULT_COST};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm as JwtAlgorithm};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use serde_json::{Value, Map};

#[napi]
pub enum Algorithm {
  HS256,
  HS384,
  HS512,
}

impl From<Algorithm> for JwtAlgorithm {
    fn from(a: Algorithm) -> Self {
        match a {
            Algorithm::HS256 => JwtAlgorithm::HS256,
            Algorithm::HS384 => JwtAlgorithm::HS384,
            Algorithm::HS512 => JwtAlgorithm::HS512,
        }
    }
}

#[napi]
pub fn hash(password: String, cost: Option<u32>) -> Result<String> {
    bcrypt_hash(password, cost.unwrap_or(DEFAULT_COST))
        .map_err(|e| Error::from_reason(format!("Bcrypt hashing error: {}", e)))
}

#[napi]
pub fn compare(password: String, hash: String) -> Result<bool> {
    bcrypt_verify(password, &hash)
        .map_err(|e| Error::from_reason(format!("Bcrypt comparison error: {}", e)))
}

#[napi(object)]
pub struct TokenHeader {
  pub algo: String,
  pub typ: Option<String>,
  pub kid: Option<String>,
}

#[napi]
pub fn decode_header(token: String) -> Result<TokenHeader> {
    let header = jsonwebtoken::decode_header(&token)
        .map_err(|e| Error::from_reason(format!("JWT header decode error: {}", e)))?;
    
    Ok(TokenHeader {
        algo: format!("{:?}", header.alg),
        typ: header.typ,
        kid: header.kid,
    })
}

#[napi]
pub fn create(payload: Map<String, Value>, secret: String, expires_in_seconds: Option<i64>, algorithm: Option<Algorithm>) -> Result<String> {
    let mut claims = payload;
    
    if let Some(exp_sec) = expires_in_seconds {
        let expiration = Utc::now()
            .checked_add_signed(Duration::seconds(exp_sec))
            .ok_or_else(|| Error::from_reason("Invalid expiration time"))?
            .timestamp();
        claims.insert("exp".to_string(), Value::Number(expiration.into()));
    }

    if !claims.contains_key("iat") {
        claims.insert("iat".to_string(), Value::Number(Utc::now().timestamp().into()));
    }

    let algo = algorithm.unwrap_or(Algorithm::HS256);
    let header = Header::new(algo.into());

    encode(
        &header,
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|e| Error::from_reason(format!("JWT creation error: {}", e)))
}

#[napi]
pub fn verify(token: String, secret: String, algorithm: Option<Algorithm>) -> Result<Map<String, Value>> {
    let algo = algorithm.unwrap_or(Algorithm::HS256);
    let mut validation = Validation::new(algo.into());
    validation.validate_exp = true;

    let token_data = decode::<Map<String, Value>>(
        &token,
        &DecodingKey::from_secret(secret.as_ref()),
        &validation,
    )
    .map_err(|e| Error::from_reason(format!("JWT verification error: {}", e)))?;

    Ok(token_data.claims)
}

#[napi]
pub fn decode_token(token: String) -> Result<Map<String, Value>> {
    let mut validation = Validation::default();
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    validation.validate_aud = false;

    let token_data = decode::<Map<String, Value>>(
        &token,
        &DecodingKey::from_secret(b""), 
        &validation,
    )
    .map_err(|e| Error::from_reason(format!("JWT decode error: {}", e)))?;

    Ok(token_data.claims)
}
