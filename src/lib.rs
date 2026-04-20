use napi::bindgen_prelude::*;
use napi_derive::napi;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2, Params
};
use pasetors::version4::V4;
use pasetors::local;
use pasetors::claims::{Claims, ClaimsValidationRules};
use pasetors::keys::SymmetricKey;
use pasetors::token::UntrustedToken;
use sha2::{Sha256, Digest};
use chrono::{Utc, Duration};
use serde_json::{Value, Map};


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

fn derive_key(secret: &str) -> SymmetricKey<V4> {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let result = hasher.finalize();
    SymmetricKey::<V4>::from(result.as_slice()).unwrap()
}

#[napi]
pub fn create(payload: Map<String, Value>, secret: String, expires_in_seconds: Option<i64>) -> Result<String> {
    let mut claims = Claims::new().map_err(|e| Error::from_reason(format!("PASETO claims error: {}", e)))?;
    
    for (k, v) in payload {
        match k.as_str() {
            "iss" => { if let Some(s) = v.as_str() { claims.issuer(s).map_err(|e| Error::from_reason(format!("PASETO issuer error: {}", e)))?; } },
            "sub" => { if let Some(s) = v.as_str() { claims.subject(s).map_err(|e| Error::from_reason(format!("PASETO subject error: {}", e)))?; } },
            "aud" => { if let Some(s) = v.as_str() { claims.audience(s).map_err(|e| Error::from_reason(format!("PASETO audience error: {}", e)))?; } },
            "jti" => { if let Some(s) = v.as_str() { claims.token_identifier(s).map_err(|e| Error::from_reason(format!("PASETO jti error: {}", e)))?; } },
            _ => { claims.add_additional(&k, v).map_err(|e| Error::from_reason(format!("PASETO payload error: {}: {}", k, e)))?; }
        }
    }

    if let Some(exp_sec) = expires_in_seconds {
        let expiration = Utc::now()
            .checked_add_signed(Duration::seconds(exp_sec))
            .ok_or_else(|| Error::from_reason("Invalid expiration time"))?;
        claims.expiration(&expiration.to_rfc3339()).map_err(|e| Error::from_reason(format!("PASETO expiration error: {}", e)))?;
    }

    let key = derive_key(&secret);
    local::encrypt(&key, &claims, None, None)
        .map_err(|e| Error::from_reason(format!("PASETO creation error: {}", e)))
}


#[napi]
pub fn verify(token: String, secret: String) -> Result<Map<String, Value>> {
    let key = derive_key(&secret);
    let validation_rules = ClaimsValidationRules::new();
    
    let untrusted_token = UntrustedToken::<pasetors::token::Local, V4>::try_from(&token)
        .map_err(|e| Error::from_reason(format!("Invalid PASETO token: {}", e)))?;

    let verified_claims = local::decrypt(&key, &untrusted_token, &validation_rules, None, None)
        .map_err(|e| Error::from_reason(format!("PASETO verification error: {}", e)))?;

    let payload = verified_claims.payload();
    let value: Value = serde_json::from_str(payload)
        .map_err(|e| Error::from_reason(format!("PASETO payload parse error: {}", e)))?;

    if let Some(obj) = value.as_object() {
        Ok(obj.clone())
    } else {
        Ok(Map::new())
    }
}
