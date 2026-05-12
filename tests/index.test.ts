import { expect, test, describe } from "bun:test";
import { 
  hash, compare, create, verify, generateKeys, createPublic, verifyPublic, decodeToken,
  parsePaseto, decodePublicPayload,
  opaqueGenerateServerSetup, 
  opaqueClientRegisterStart, opaqueServerRegisterStart, opaqueClientRegisterFinish, opaqueServerRegisterFinish,
  opaqueClientLoginStart, opaqueServerLoginStart, opaqueClientLoginFinish, opaqueServerLoginFinish
} from "../index";
import { parseToken, decodePublicPayload as tsDecodePublicPayload, verifyTokenFormat } from "../src/paseto-parser";

describe("Webtoken NAPI Tests", () => {
  const password = "my-secure-password";
  const secret = "super-secret-key";

  describe("Argon2 Hashing", () => {
    test("should hash password successfully", async () => {
      const result = await hash(password);
      expect(result).toBeDefined();
      expect(result.length).toBeGreaterThan(0);
      expect(result).toStartWith("$argon2id"); // Argon2id prefix
    });

    test("should compare correct password", async () => {
      const hashed = await hash(password);
      const isMatch = await compare(password, hashed);
      expect(isMatch).toBe(true);
    });

    test("should fail on wrong password", async () => {
      const hashed = await hash(password);
      const isMatch = await compare("wrong-password", hashed);
      expect(isMatch).toBe(false);
    });

    test("should respect custom iterations", async () => {
      const start = performance.now();
      await hash(password, 5); // iterations
      const end = performance.now();
      const highCostTime = end - start;

      const startLow = performance.now();
      await hash(password, 1); // iterations
      const endLow = performance.now();
      const lowCostTime = endLow - startLow;

      expect(highCostTime).toBeGreaterThan(lowCostTime);
    });

    test("should respect custom memory", async () => {
      const result = await hash(password, 2, 8192); // 8MB memory
      expect(result).toContain("m=8192");
    });

    test("should respect custom parallelism", async () => {
      const result = await hash(password, 2, 4096, 4); // p=4
      expect(result).toContain("p=4");
    });
  });

  describe("PASETO Tokens (V4 Local)", () => {
    test("should create a valid PASETO string", () => {
      const token = create({ user: "user-123" }, secret, 3600);
      expect(token).toBeDefined();
      expect(token).toStartWith("v4.local.");
    });

    test("should verify a valid token", () => {
      const payload = { sub: "user-123", role: "admin" };
      const token = create(payload, secret, 3600);
      const decoded = verify(token, secret);

      expect(decoded.sub).toBe(payload.sub);
      expect(decoded.role).toBe(payload.role);
    });

    test("should throw error with incorrect secret", () => {
      const token = create({ sub: "123" }, secret, 3600);
      expect(() => verify(token, "wrong-secret")).toThrow();
    });

    test("should throw error for expired token", () => {
      const token = create({ sub: "123" }, secret, -100);
      expect(() => verify(token, secret)).toThrow();
    });
  });

  describe("PASETO Keys", () => {
    test("should generate valid asymmetric keys", () => {
      const keys = generateKeys();
      expect(keys.secretKey).toBeDefined();
      expect(keys.publicKey).toBeDefined();
      expect(keys.secretKey.length).toBe(128); // 64 bytes in hex
      expect(keys.publicKey.length).toBe(64);   // 32 bytes in hex
    });
  });

  describe("PASETO Tokens (V4 Public)", () => {
    const keys = generateKeys();

    test("should create and verify asymmetric tokens", () => {
      const payload = { sub: "user-public", role: "editor" };
      const token = createPublic(payload, keys.secretKey, 3600);
      expect(token).toStartWith("v4.public.");

      const verified = verifyPublic(token, keys.publicKey);
      expect(verified.sub).toBe(payload.sub);
      expect(verified.role).toBe(payload.role);
    });

    test("should fail with invalid public key", () => {
      const payload = { sub: "test" };
      const token = createPublic(payload, keys.secretKey, 3600);
      const otherKeys = generateKeys();
      expect(() => verifyPublic(token, otherKeys.publicKey)).toThrow();
    });
  });

  describe("Token Utilities", () => {
    test("decodeToken should throw error for local tokens (unsupported)", () => {
      const token = create({ sub: "test" }, secret, 3600);
      expect(() => decodeToken(token)).toThrow();
    });
  });

  describe("Custom Parser (NAPI Rust)", () => {
    test("parsePaseto should extract local token components", () => {
      const token = create({ sub: "user-123" }, secret, 3600);
      const parsed = parsePaseto(token);
      expect(parsed.version).toBe("v4");
      expect(parsed.purpose).toBe("local");
      expect(parsed.payload.length).toBeGreaterThan(0);
      expect(parsed.footer).toBe("");
    });

    test("parsePaseto should extract public token components", () => {
      const keys = generateKeys();
      const token = createPublic({ sub: "user-public" }, keys.secretKey, 3600);
      const parsed = parsePaseto(token);
      expect(parsed.version).toBe("v4");
      expect(parsed.purpose).toBe("public");
      expect(parsed.payload.length).toBeGreaterThan(0);
    });

    test("parsePaseto should throw on invalid token", () => {
      expect(() => parsePaseto("invalid-token")).toThrow();
    });

    test("decodePublicPayload should extract claims from public token", () => {
      const keys = generateKeys();
      const payload = { sub: "user-public", role: "editor", custom_field: "value" };
      const token = createPublic(payload, keys.secretKey, 3600);
      const decoded = decodePublicPayload(token);
      expect(decoded.sub).toBe(payload.sub);
      expect(decoded.role).toBe(payload.role);
      expect(decoded.custom_field).toBe(payload.custom_field);
    });

    test("decodePublicPayload should throw on local token", () => {
      const token = create({ sub: "test" }, secret, 3600);
      expect(() => decodePublicPayload(token)).toThrow();
    });
  });

  describe("Custom Parser (TypeScript)", () => {
    test("parseToken should extract local token components", () => {
      const token = create({ sub: "user-123" }, secret, 3600);
      const parsed = parseToken(token);
      expect(parsed.version).toBe("v4");
      expect(parsed.purpose).toBe("local");
      expect(parsed.payload.length).toBeGreaterThan(0);
    });

    test("parseToken should extract public token components", () => {
      const keys = generateKeys();
      const token = createPublic({ sub: "user-public" }, keys.secretKey, 3600);
      const parsed = parseToken(token);
      expect(parsed.version).toBe("v4");
      expect(parsed.purpose).toBe("public");
    });

    test("parseToken should throw on invalid format", () => {
      expect(() => parseToken("not-a-token")).toThrow();
      expect(() => parseToken("v3.local.xxx")).toThrow();
      expect(() => parseToken("v4.unknown.xxx")).toThrow();
    });

    test("TS decodePublicPayload should extract claims from public token", () => {
      const keys = generateKeys();
      const payload = { sub: "user", role: "admin", data: 42 };
      const token = createPublic(payload, keys.secretKey, 3600);
      const decoded = tsDecodePublicPayload(token);
      expect(decoded.sub).toBe(payload.sub);
      expect(decoded.role).toBe(payload.role);
      expect(decoded.data).toBe(payload.data);
    });

    test("verifyTokenFormat should validate token structure", () => {
      const token = create({ sub: "test" }, secret, 3600);
      const result = verifyTokenFormat(token);
      expect(result.isValid).toBe(true);
      expect(result.type).toBe("local");
      expect(result.version).toBe("v4");
    });

    test("verifyTokenFormat should not throw on invalid tokens", () => {
      const result = verifyTokenFormat("garbage");
      expect(result.isValid).toBe(false);
    });
  });

  describe("OPAQUE (PAKE) Zero-Knowledge Auth", () => {
    const userPass = "secure-p@ss-123";
    const userEmail = "test@example.com";
    const srvId = "test-server";

    test("should complete full registration and login flow", () => {
      // 1. Setup
      const serverSetup = opaqueGenerateServerSetup();
      expect(serverSetup).toBeDefined();

      // 2. Registration
      const regStart = opaqueClientRegisterStart(userPass);
      expect(regStart.request).toBeDefined();
      expect(regStart.state).toBeDefined();

      const regResponse = opaqueServerRegisterStart(serverSetup, regStart.request, userEmail);
      expect(regResponse).toBeDefined();

      const regFinish = opaqueClientRegisterFinish(userPass, regResponse, regStart.state, userEmail, srvId);
      expect(regFinish.upload).toBeDefined();
      expect(regFinish.exportKey).toBeDefined();

      const passwordFile = opaqueServerRegisterFinish(regFinish.upload);
      expect(passwordFile).toBeDefined();

      // 3. Login
      const loginStart = opaqueClientLoginStart(userPass);
      const loginChallenge = opaqueServerLoginStart(serverSetup, passwordFile, loginStart.request, userEmail, srvId);
      expect(loginChallenge.response).toBeDefined();

      const loginFinish = opaqueClientLoginFinish(userPass, loginChallenge.response, loginStart.state, userEmail, srvId);
      expect(loginFinish.finalization).toBeDefined();
      expect(loginFinish.sessionKey).toBeDefined();

      const serverSessionKey = opaqueServerLoginFinish(loginFinish.finalization, loginChallenge.state);
      
      // Verification
      expect(serverSessionKey).toBe(loginFinish.sessionKey);
    });

    test("should fail login with wrong password", () => {
      const serverSetup = opaqueGenerateServerSetup();
      
      // Register with correct pass
      const regStart = opaqueClientRegisterStart(userPass);
      const regResp = opaqueServerRegisterStart(serverSetup, regStart.request, userEmail);
      const regFin = opaqueClientRegisterFinish(userPass, regResp, regStart.state, userEmail, srvId);
      const passwordFile = opaqueServerRegisterFinish(regFin.upload);

      // Login with WRONG pass
      const wrongPass = "wrong-password";
      const loginStart = opaqueClientLoginStart(wrongPass);
      const loginChallenge = opaqueServerLoginStart(serverSetup, passwordFile, loginStart.request, userEmail, srvId);
      
      // Client should fail to finish login (or derive wrong key/finalization)
      // Usually opaqueClientLoginFinish will throw if the unmasking fails or MAC is invalid
      expect(() => {
        opaqueClientLoginFinish(wrongPass, loginChallenge.response, loginStart.state, userEmail, srvId);
      }).toThrow();
    });
  });
});


