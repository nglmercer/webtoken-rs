/**
 * OPAQUE Authentication Server Example
 * 
 * This example implements a production-like flow using Bun.serve:
 * 1. OPAQUE Registration (Interactive 2-step)
 * 2. OPAQUE Login (Interactive 2-step)
 * 3. PASETO Token issuance upon success.
 */

import { 
  opaqueGenerateServerSetup, 
  opaqueServerRegisterStart, 
  opaqueServerRegisterFinish,
  opaqueServerLoginStart,
  opaqueServerLoginFinish,
  createPublic,
  generateKeys
} from "../index";

// --- Types for Request/Response Bodies ---
interface RegistrationRequest {
  email: string;
  request: string;
  upload?: string;
}

interface LoginRequest {
  email: string;
  request: string;
  finalization?: string;
}

interface ServerResponse {
  response?: string;
  status?: string;
  token?: string;
  sessionKey?: string;
}

// --- In-Memory "Database" ---
const SERVER_ID = "webtoken-auth-server";
const serverSetup = opaqueGenerateServerSetup();
const { secretKey, publicKey: serverPublicKey } = generateKeys(); // For PASETO tokens

const users = new Map<string, string>(); // email -> passwordFile
const loginStates = new Map<string, string>(); // email -> serverLoginState

console.log(`
🔒 Auth Server Initialized
   Server Setup: ${serverSetup.substring(0, 20)}...
   Public Key:   ${serverPublicKey}
`);

const server = Bun.serve({
  port: 3000,
  async fetch(req) {
    const url = new URL(req.url);
    const body = (req.method === "POST" ? await req.json() : {}) as any;

    try {
      // --- Registration Phase 1 ---
      if (url.pathname === "/register/start") {
        const { email, request } = body as RegistrationRequest;
        console.log(`[Reg] Start for ${email}`);
        
        const response = opaqueServerRegisterStart(serverSetup, request, email);
        return Response.json({ response });
      }

      // --- Registration Phase 2 ---
      if (url.pathname === "/register/finish") {
        const { email, upload } = body as RegistrationRequest;
        console.log(`[Reg] Finish for ${email}`);
        
        if (!upload) return new Response("Missing upload", { status: 400 });
        
        const passwordFile = opaqueServerRegisterFinish(upload);
        users.set(email, passwordFile);
        
        return Response.json({ status: "Registered successfully" });
      }

      // --- Login Phase 1 ---
      if (url.pathname === "/login/start") {
        const { email, request } = body as LoginRequest;
        console.log(`[Login] Start for ${email}`);

        const passwordFile = users.get(email);
        if (!passwordFile) return new Response("User not found", { status: 404 });

        const { response, state } = opaqueServerLoginStart(serverSetup, passwordFile, request, email, SERVER_ID);
        
        // We must persist the server login state to verify the finalization message later
        loginStates.set(email, state);
        
        return Response.json({ response });
      }

      // --- Login Phase 2 ---
      if (url.pathname === "/login/finish") {
        const { email, finalization } = body as LoginRequest;
        console.log(`[Login] Finish for ${email}`);

        if (!finalization) return new Response("Missing finalization", { status: 400 });

        const state = loginStates.get(email);
        if (!state) return new Response("Login session expired", { status: 400 });

        // Verify finalization and derive session key
        const sessionKey = opaqueServerLoginFinish(finalization, state);
        loginStates.delete(email); // Clean up

        console.log(`✅ ${email} authenticated! Session Key: ${sessionKey.substring(0, 16)}...`);

        // Issue a PASETO token for subsequent API calls
        const token = createPublic({ sub: email, scope: "user" }, secretKey, 3600);
        
        return Response.json({ 
          status: "Authenticated", 
          token,
          sessionKey // In a real app, you might use this to encrypt the channel
        });
      }

      return new Response("Not Found", { status: 404 });
    } catch (e: any) {
      console.error(e);
      return new Response(e.message || "Internal Error", { status: 500 });
    }
  },
});

console.log(`🚀 Server running at http://localhost:${server.port}`);

// --- Automated Client Script (to test the server) ---
async function testServer() {
  const password = "my-secret-password";
  const email = "demo@example.com";
  const BASE_URL = `http://localhost:${server.port}`;

  console.log("\n--- Starting Client Test Flow ---");

  // 1. Register
  const { opaqueClientRegisterStart, opaqueClientRegisterFinish } = await import("../index");
  
  console.log("Client: Registering...");
  const regStart = opaqueClientRegisterStart(password);
  const reg1Res = await fetch(`${BASE_URL}/register/start`, {
    method: "POST",
    body: JSON.stringify({ email, request: regStart.request })
  }).then(r => r.json() as Promise<ServerResponse>);

  if (!reg1Res.response) throw new Error("Missing response from reg/start");

  const regFin = opaqueClientRegisterFinish(password, reg1Res.response, regStart.state, email, SERVER_ID);
  await fetch(`${BASE_URL}/register/finish`, {
    method: "POST",
    body: JSON.stringify({ email, upload: regFin.upload })
  });
  console.log("Client: Registered.");

  // 2. Login
  const { opaqueClientLoginStart, opaqueClientLoginFinish } = await import("../index");

  console.log("Client: Logging in...");
  const loginStart = opaqueClientLoginStart(password);
  const login1Res = await fetch(`${BASE_URL}/login/start`, {
    method: "POST",
    body: JSON.stringify({ email, request: loginStart.request })
  }).then(r => r.json() as Promise<ServerResponse>);

  if (!login1Res.response) throw new Error("Missing response from login/start");

  const loginFin = opaqueClientLoginFinish(password, login1Res.response, loginStart.state, email, SERVER_ID);
  const loginFinalRes = await fetch(`${BASE_URL}/login/finish`, {
    method: "POST",
    body: JSON.stringify({ email, finalization: loginFin.finalization })
  }).then(r => r.json() as Promise<ServerResponse>);

  console.log("Client: Login Result:", loginFinalRes.status);
  console.log("Client: Received Token:", loginFinalRes.token?.substring(0, 30) + "...");
  
  process.exit(0);
}

// Run test after a short delay
setTimeout(testServer, 1000);
