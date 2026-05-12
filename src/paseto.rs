use pasetors::version4::V4;
use pasetors::{local, public};
use pasetors::claims::{Claims, ClaimsValidationRules};
use pasetors::keys::{SymmetricKey, AsymmetricPublicKey, AsymmetricSecretKey, AsymmetricKeyPair, Generate};
use pasetors::token::UntrustedToken;
use sha2::{Sha256, Digest};
use chrono::{Utc, Duration};
use serde_json::{Value, Map};

pub fn derive_symmetric_key(secret: &str) -> SymmetricKey<V4> {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let result = hasher.finalize();
    SymmetricKey::<V4>::from(result.as_slice()).unwrap()
}

pub fn internal_generate_keys() -> (String, String) {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    (hex::encode(kp.secret.as_bytes()), hex::encode(kp.public.as_bytes()))
}

pub fn internal_create_local(payload: Map<String, Value>, secret: String, expires_in_seconds: Option<i64>) -> Result<String, String> {
    let mut claims = Claims::new().map_err(|e| format!("PASETO claims error: {}", e))?;
    populate_claims(&mut claims, payload, expires_in_seconds)?;

    let key = derive_symmetric_key(&secret);
    local::encrypt(&key, &claims, None, None)
        .map_err(|e| format!("PASETO creation error: {}", e))
}

pub fn internal_verify_local(token: &str, secret: &str) -> Result<Map<String, Value>, String> {
    let key = derive_symmetric_key(secret);
    let validation_rules = ClaimsValidationRules::new();

    let untrusted_token = UntrustedToken::<pasetors::token::Local, V4>::try_from(token)
        .map_err(|e| format!("Invalid PASETO token: {}", e))?;

    let verified_claims = local::decrypt(&key, &untrusted_token, &validation_rules, None, None)
        .map_err(|e| format!("PASETO verification error: {}", e))?;

    parse_claims(verified_claims.payload())
}

pub fn internal_create_public(payload: Map<String, Value>, secret_key_hex: &str, expires_in_seconds: Option<i64>) -> Result<String, String> {
    let mut claims = Claims::new().map_err(|e| format!("PASETO claims error: {}", e))?;
    populate_claims(&mut claims, payload, expires_in_seconds)?;

    let sk_bytes = hex::decode(secret_key_hex).map_err(|_| "Invalid hex for secret key")?;
    let sk = AsymmetricSecretKey::<V4>::from(sk_bytes.as_slice()).map_err(|e| format!("Invalid secret key: {}", e))?;

    public::sign(&sk, &claims, None, None)
        .map_err(|e| format!("PASETO signing error: {}", e))
}

pub fn internal_verify_public(token: &str, public_key_hex: &str) -> Result<Map<String, Value>, String> {
    let pk_bytes = hex::decode(public_key_hex).map_err(|_| "Invalid hex for public key")?;
    let pk = AsymmetricPublicKey::<V4>::from(pk_bytes.as_slice()).map_err(|e| format!("Invalid public key: {}", e))?;

    let validation_rules = ClaimsValidationRules::new();
    let untrusted_token = UntrustedToken::<pasetors::token::Public, V4>::try_from(token)
        .map_err(|e| format!("Invalid PASETO token: {}", e))?;

    let verified_claims = public::verify(&pk, &untrusted_token, &validation_rules, None, None)
        .map_err(|e| format!("PASETO verification error: {}", e))?;

    parse_claims(verified_claims.payload())
}

fn populate_claims(claims: &mut Claims, payload: Map<String, Value>, expires_in_seconds: Option<i64>) -> Result<(), String> {
    for (k, v) in payload {
        match k.as_str() {
            "iss" => { if let Some(s) = v.as_str() { claims.issuer(s).map_err(|e| format!("PASETO issuer error: {}", e))?; } },
            "sub" => { if let Some(s) = v.as_str() { claims.subject(s).map_err(|e| format!("PASETO subject error: {}", e))?; } },
            "aud" => { if let Some(s) = v.as_str() { claims.audience(s).map_err(|e| format!("PASETO audience error: {}", e))?; } },
            "jti" => { if let Some(s) = v.as_str() { claims.token_identifier(s).map_err(|e| format!("PASETO jti error: {}", e))?; } },
            _ => { claims.add_additional(&k, v).map_err(|e| format!("PASETO payload error: {}: {}", k, e))?; }
        }
    }

    if let Some(exp_sec) = expires_in_seconds {
        let expiration = Utc::now()
            .checked_add_signed(Duration::seconds(exp_sec))
            .ok_or_else(|| "Invalid expiration time".to_string())?;
        claims.expiration(&expiration.to_rfc3339()).map_err(|e| format!("PASETO expiration error: {}", e))?;
    }
    Ok(())
}

fn parse_claims(payload: &str) -> Result<Map<String, Value>, String> {
    serde_json::from_str::<Map<String, Value>>(payload)
        .map_err(|e| format!("PASETO payload parse error: {}", e))
}

pub struct TokenParts<'a> {
    pub version: &'a str,
    pub purpose: &'a str,
    pub payload: &'a str,
    pub footer: &'a str,
}

pub fn parse_token(token: &str) -> Result<TokenParts<'_>, String> {
    let parts: Vec<&str> = token.splitn(4, '.').collect();
    if parts.len() < 3 {
        return Err("Invalid PASETO token: expected at least 3 dot-separated parts".into());
    }

    let version = parts[0];
    let purpose = parts[1];
    let payload = parts[2];
    let footer = parts.get(3).unwrap_or(&"");

    if version != "v4" {
        return Err(format!("Unsupported PASETO version: {}", version));
    }
    if purpose != "local" && purpose != "public" {
        return Err(format!("Unsupported PASETO purpose: {}", purpose));
    }

    Ok(TokenParts { version, purpose, payload, footer })
}

pub fn decode_public_payload(token: &str) -> Result<Map<String, Value>, String> {
    let parts = parse_token(token)?;
    if parts.purpose != "public" {
        return Err("Only v4.public tokens have a decodable payload".into());
    }

    let decoded = base64url_decode(parts.payload)?;
    // V4 Public: first 64 bytes are Ed25519 signature, rest is JSON payload
    if decoded.len() < 64 {
        return Err("Public token payload too short to contain signature".into());
    }
    let json_bytes = &decoded[..decoded.len() - 64];
    let payload_str = std::str::from_utf8(json_bytes)
        .map_err(|_| "Invalid UTF-8 in payload".to_string())?;

    parse_claims(payload_str)
}

fn base64url_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut b64 = input.to_string();
    match b64.len() % 4 {
        2 => b64.push_str("=="),
        3 => b64.push_str("="),
        _ => {}
    }
    b64 = b64.replace('-', "+").replace('_', "/");
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64)
        .map_err(|e| format!("Base64 decode error: {}", e))
}

use base64;
