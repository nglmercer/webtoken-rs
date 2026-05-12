use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Params, Scrypt,
};

pub fn internal_scrypt_hash(
    password: String,
    log_n: Option<u8>,
    r: Option<u32>,
    p: Option<u32>,
) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);

    let params = Params::new(
        log_n.unwrap_or(15),
        r.unwrap_or(8),
        p.unwrap_or(1),
        Params::RECOMMENDED_LEN,
    )
    .map_err(|e| format!("Scrypt params error: {}", e))?;

    Scrypt
        .hash_password_customized(password.as_bytes(), None, None, params, &salt)
        .map_err(|e| format!("Scrypt hashing error: {}", e))
        .map(|h| h.to_string())
}

pub fn internal_scrypt_compare(password: String, hash: String) -> Result<bool, String> {
    let parsed_hash =
        PasswordHash::new(&hash).map_err(|e| format!("Invalid hash format: {}", e))?;

    Ok(Scrypt
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}
