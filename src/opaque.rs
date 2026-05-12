use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
//use opaque_ke::key_exchange::Serialize;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize as SerdeSerialize};

pub struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange =
        opaque_ke::key_exchange::tripledh::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = argon2::Argon2<'static>;
}

// Helper for identifiers
fn get_identifiers<'a>(
    client_id: &'a Option<String>,
    server_id: &'a Option<String>,
) -> Identifiers<'a> {
    Identifiers {
        client: client_id.as_ref().map(|s| s.as_bytes()),
        server: server_id.as_ref().map(|s| s.as_bytes()),
    }
}

// --- Setup ---

pub fn internal_opaque_server_setup() -> String {
    let mut rng = OsRng;
    let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut rng);
    hex::encode(server_setup.serialize())
}

// --- Registration ---

#[derive(SerdeSerialize, Deserialize)]
pub struct ClientRegisterStartResult {
    pub request: String,
    pub state: String,
}

pub fn internal_client_register_start(password: &str) -> Result<ClientRegisterStartResult, String> {
    let mut rng = OsRng;
    let res = ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password.as_bytes())
        .map_err(|e| format!("Registration start error: {:?}", e))?;

    Ok(ClientRegisterStartResult {
        request: hex::encode(res.message.serialize()),
        state: hex::encode(res.state.serialize()),
    })
}

pub fn internal_server_register_start(
    server_setup_hex: &str,
    request_hex: &str,
    client_id: &str,
) -> Result<String, String> {
    let server_setup_bytes = hex::decode(server_setup_hex).map_err(|e| e.to_string())?;
    let server_setup = ServerSetup::<DefaultCipherSuite>::deserialize(&server_setup_bytes)
        .map_err(|e| format!("Server setup deserialize error: {:?}", e))?;

    let request_bytes = hex::decode(request_hex).map_err(|e| e.to_string())?;
    let request = RegistrationRequest::<DefaultCipherSuite>::deserialize(&request_bytes)
        .map_err(|e| format!("Request deserialize error: {:?}", e))?;

    let res = ServerRegistration::<DefaultCipherSuite>::start(
        &server_setup,
        request,
        client_id.as_bytes(),
    )
    .map_err(|e| format!("Server registration start error: {:?}", e))?;

    Ok(hex::encode(res.message.serialize()))
}

#[derive(SerdeSerialize, Deserialize)]
pub struct ClientRegisterFinishResult {
    pub upload: String,
    pub export_key: String,
}

pub fn internal_client_register_finish(
    password: &str,
    response_hex: &str,
    state_hex: &str,
    client_id: Option<String>,
    server_id: Option<String>,
) -> Result<ClientRegisterFinishResult, String> {
    let mut rng = OsRng;

    let response_bytes = hex::decode(response_hex).map_err(|e| e.to_string())?;
    let response = RegistrationResponse::<DefaultCipherSuite>::deserialize(&response_bytes)
        .map_err(|e| format!("Response deserialize error: {:?}", e))?;

    let state_bytes = hex::decode(state_hex).map_err(|e| e.to_string())?;
    let state = ClientRegistration::<DefaultCipherSuite>::deserialize(&state_bytes)
        .map_err(|e| format!("State deserialize error: {:?}", e))?;

    let ids = get_identifiers(&client_id, &server_id);
    let params = ClientRegistrationFinishParameters::new(ids, None);

    let res = state
        .finish(&mut rng, password.as_bytes(), response, params)
        .map_err(|e| format!("Registration finish error: {:?}", e))?;

    Ok(ClientRegisterFinishResult {
        upload: hex::encode(res.message.serialize()),
        export_key: hex::encode(res.export_key),
    })
}

pub fn internal_server_register_finish(upload_hex: &str) -> Result<String, String> {
    let upload_bytes = hex::decode(upload_hex).map_err(|e| e.to_string())?;
    let upload = RegistrationUpload::<DefaultCipherSuite>::deserialize(&upload_bytes)
        .map_err(|e| format!("Upload deserialize error: {:?}", e))?;

    let password_file = ServerRegistration::<DefaultCipherSuite>::finish(upload);
    Ok(hex::encode(password_file.serialize()))
}

// --- Login ---

#[derive(SerdeSerialize, Deserialize)]
pub struct ClientLoginStartResult {
    pub request: String,
    pub state: String,
}

pub fn internal_client_login_start(password: &str) -> Result<ClientLoginStartResult, String> {
    let mut rng = OsRng;
    let res = ClientLogin::<DefaultCipherSuite>::start(&mut rng, password.as_bytes())
        .map_err(|e| format!("Login start error: {:?}", e))?;

    Ok(ClientLoginStartResult {
        request: hex::encode(res.message.serialize()),
        state: hex::encode(res.state.serialize()),
    })
}

#[derive(SerdeSerialize, Deserialize)]
pub struct ServerLoginStartResult {
    pub response: String,
    pub state: String,
}

pub fn internal_server_login_start(
    server_setup_hex: &str,
    password_file_hex: &str,
    request_hex: &str,
    client_id: &str,
    server_id: Option<String>,
) -> Result<ServerLoginStartResult, String> {
    let mut rng = OsRng;

    let server_setup_bytes = hex::decode(server_setup_hex).map_err(|e| e.to_string())?;
    let server_setup = ServerSetup::<DefaultCipherSuite>::deserialize(&server_setup_bytes)
        .map_err(|e| format!("Server setup deserialize error: {:?}", e))?;

    let password_file_bytes = hex::decode(password_file_hex).map_err(|e| e.to_string())?;
    let password_file = ServerRegistration::<DefaultCipherSuite>::deserialize(&password_file_bytes)
        .map_err(|e| format!("Password file deserialize error: {:?}", e))?;

    let request_bytes = hex::decode(request_hex).map_err(|e| e.to_string())?;
    let request = CredentialRequest::<DefaultCipherSuite>::deserialize(&request_bytes)
        .map_err(|e| format!("Request deserialize error: {:?}", e))?;

    let ids = Identifiers {
        client: Some(client_id.as_bytes()),
        server: server_id.as_ref().map(|s| s.as_bytes()),
    };

    let res = ServerLogin::<DefaultCipherSuite>::start(
        &mut rng,
        &server_setup,
        Some(password_file),
        request,
        client_id.as_bytes(),
        ServerLoginParameters {
            context: None,
            identifiers: ids,
        },
    )
    .map_err(|e| format!("Server login start error: {:?}", e))?;

    Ok(ServerLoginStartResult {
        response: hex::encode(res.message.serialize()),
        state: hex::encode(res.state.serialize()),
    })
}

#[derive(SerdeSerialize, Deserialize)]
pub struct ClientLoginFinishResult {
    pub finalization: String,
    pub session_key: String,
    pub export_key: String,
    pub server_public_key: String,
}

pub fn internal_client_login_finish(
    password: &str,
    response_hex: &str,
    state_hex: &str,
    client_id: Option<String>,
    server_id: Option<String>,
) -> Result<ClientLoginFinishResult, String> {
    let mut rng = OsRng;

    let response_bytes = hex::decode(response_hex).map_err(|e| e.to_string())?;
    let response = CredentialResponse::<DefaultCipherSuite>::deserialize(&response_bytes)
        .map_err(|e| format!("Response deserialize error: {:?}", e))?;

    let state_bytes = hex::decode(state_hex).map_err(|e| e.to_string())?;
    let state = ClientLogin::<DefaultCipherSuite>::deserialize(&state_bytes)
        .map_err(|e| format!("State deserialize error: {:?}", e))?;

    let ids = get_identifiers(&client_id, &server_id);

    let res = state
        .finish(
            &mut rng,
            password.as_bytes(),
            response,
            ClientLoginFinishParameters::new(None, ids, None),
        )
        .map_err(|e| format!("Client login finish error: {:?}", e))?;

    Ok(ClientLoginFinishResult {
        finalization: hex::encode(res.message.serialize()),
        session_key: hex::encode(res.session_key),
        export_key: hex::encode(res.export_key),
        server_public_key: hex::encode(res.server_s_pk.serialize()),
    })
}

pub fn internal_server_login_finish(
    finalization_hex: &str,
    state_hex: &str,
) -> Result<String, String> {
    let finalization_bytes = hex::decode(finalization_hex).map_err(|e| e.to_string())?;
    let finalization =
        CredentialFinalization::<DefaultCipherSuite>::deserialize(&finalization_bytes)
            .map_err(|e| format!("Finalization deserialize error: {:?}", e))?;

    let state_bytes = hex::decode(state_hex).map_err(|e| e.to_string())?;
    let state = ServerLogin::<DefaultCipherSuite>::deserialize(&state_bytes)
        .map_err(|e| format!("State deserialize error: {:?}", e))?;

    let res = state
        .finish(finalization, ServerLoginParameters::default())
        .map_err(|e| format!("Server login finish error: {:?}", e))?;

    Ok(hex::encode(res.session_key))
}
