/**
 * OPAQUE PAKE (Password-Authenticated Key Exchange) Demo
 * 
 * This example demonstrates the full zero-knowledge password authentication flow.
 * OPAQUE allows a client to authenticate without ever sending their password
 * (or even a hash of it) to the server.
 */

import { 
  opaqueGenerateServerSetup, 
  opaqueClientRegisterStart, 
  opaqueServerRegisterStart,
  opaqueClientRegisterFinish,
  opaqueServerRegisterFinish,
  opaqueClientLoginStart,
  opaqueServerLoginStart,
  opaqueClientLoginFinish,
  opaqueServerLoginFinish 
} from "../index.js";

async function runDemo() {
  console.log("🚀 Starting OPAQUE Zero-Knowledge Auth Demo\n");

  const password = "my-secure-password-123";
  const userId = "alice@example.com";
  const serverId = "webtoken-server";

  // --- 1. SETUP (Server-side, done once) ---
  console.log("1. [Server] Generating global OPAQUE setup...");
  const serverSetup = opaqueGenerateServerSetup();
  console.log("   Setup generated (hex encoded state)\n");

  // --- 2. REGISTRATION FLOW ---
  console.log("2. [Registration] Starting flow...");

  // Client starts registration
  const clientRegStart = opaqueClientRegisterStart(password);
  console.log("   [Client] Registration request created.");

  // Server processes request
  const serverRegResponse = opaqueServerRegisterStart(serverSetup, clientRegStart.request, userId);
  console.log("   [Server] Registration response generated.");

  // Client finishes registration
  const clientRegFinish = opaqueClientRegisterFinish(password, serverRegResponse, clientRegStart.state, userId, serverId);
  console.log("   [Client] Registration upload created and export key derived.");

  // Server saves the "password file" (The registration record)
  const passwordFile = opaqueServerRegisterFinish(clientRegFinish.upload);
  console.log("   [Server] User registered. Password file stored in DB.\n");

  // --- 3. LOGIN FLOW ---
  console.log("3. [Login] Starting authentication...");

  // Client starts login
  const clientLoginStart = opaqueClientLoginStart(password);
  console.log("   [Client] Login request created.");

  // Server processes login request using the stored password file
  const serverLoginStart = opaqueServerLoginStart(serverSetup, passwordFile, clientLoginStart.request, userId, serverId);
  console.log("   [Server] Login challenge generated.");

  // Client finishes login
  const clientLoginFinish = opaqueClientLoginFinish(password, serverLoginStart.response, clientLoginStart.state, userId, serverId);
  console.log("   [Client] Login finalization created and session key derived.");

  // Server verifies client finalization
  const serverSessionKey = opaqueServerLoginFinish(clientLoginFinish.finalization, serverLoginStart.state);
  console.log("   [Server] Authentication successful. Session key derived.");

  // --- 4. VERIFICATION ---
  console.log("\n--- Verification ---");
  console.log(`Client Session Key: ${clientLoginFinish.sessionKey}`);
  console.log(`Server Session Key: ${serverSessionKey}`);

  if (clientLoginFinish.sessionKey === serverSessionKey) {
    console.log("✅ Success! Both parties derived the SAME secure session key without ever sharing the password.");
  } else {
    console.log("❌ Failure! Session keys do not match.");
  }
}

runDemo().catch(console.error);
