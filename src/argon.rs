use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2, Params
};
use cfg_if::cfg_if;

pub fn internal_hash(password: String, iterations: Option<u32>, memory: Option<u32>, parallelism: Option<u32>) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    
    cfg_if! {
        if #[cfg(not(target_arch = "wasm32"))] {
            let params = Params::new(
                memory.unwrap_or(Params::DEFAULT_M_COST),
                iterations.unwrap_or(Params::DEFAULT_T_COST),
                parallelism.unwrap_or(Params::DEFAULT_P_COST),
                None,
            ).map_err(|e| format!("Argon2 params error: {}", e))?;

            let argon2 = Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                params,
            );
        } else {
            // Simplified for WASM
            let argon2 = Argon2::default();
        }
    }

    argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Argon2 hashing error: {}", e))
        .map(|h| h.to_string())
}

pub fn internal_compare(password: String, hash: String) -> Result<bool, String> {
    let parsed_hash = PasswordHash::new(&hash)
        .map_err(|e| format!("Invalid hash format: {}", e))?;
    
    Ok(Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok())
}
