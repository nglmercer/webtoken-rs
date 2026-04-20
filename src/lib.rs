use napi::bindgen_prelude::*;
use napi_derive::napi;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2, Params
};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm as JwtAlgorithm};
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
pub async fn hash(password: String, iterations: Option<u32>, memory: Option<u32>, parallelism: Option<u32>) -> Result<String> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        
        let params = Params::new(
            memory.unwrap_or(Params::DEFAULT_M_COST),
            iterations.unwrap_or(Params::DEFAULT_T_COST),
            parallelism.unwrap_or(Params::DEFAULT_P_COST),
            None,
        ).map_err(|e| Error::from_reason(format!("Argon2 params error: {}", e)))?;

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        );

        argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|e| Error::from_reason(format!("Argon2 hashing error: {}", e)))
            .map(|h| h.to_string())
    })
    .await
    .map_err(|e| Error::from_reason(format!("Task join error: {}", e)))?
}

#[napi]
pub async fn compare(password: String, hash: String) -> Result<bool> {
    tokio::task::spawn_blocking(move || {
        let parsed_hash = PasswordHash::new(&hash)
            .map_err(|e| Error::from_reason(format!("Invalid hash format: {}", e)))?;
        
        Ok(Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok())
    })
    .await
    .map_err(|e| Error::from_reason(format!("Task join error: {}", e)))?
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
