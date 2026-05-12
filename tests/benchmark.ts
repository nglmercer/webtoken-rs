import {
  hash as rustHash,
  compare as rustCompare,
  scryptHash as rustScryptHash,
  scryptCompare as rustScryptCompare,
  create as rustCreate,
  verify as rustVerify,
  generateKeys,
  createPublic,
  verifyPublic
} from "../index";
import { run, bench, group } from "mitata";
import crypto from "node:crypto";

const password = "benchmarking-is-fun";
const secret = "super-secret-key-that-is-long-enough-for-hs256";
const { secretKey, publicKey } = generateKeys();

// Setup
console.log("Generating hashes for verification benchmark...");
const rHash = await rustHash(password, 3, 4096, 1);
const sHash = await rustScryptHash(password, 15);
const sHashLow = await rustScryptHash(password, 10);

group("Password Hashing Comparison", () => {
  bench("Rust (Argon2id) - 3 iter, 4MB, p=1", async () => {
    await rustHash(password, 3, 4096, 1);
  });

  bench("Rust (Argon2id) - 3 iter, 4MB, p=4", async () => {
    await rustHash(password, 3, 4096, 4);
  });

  bench("Rust (Scrypt) - Default (logN=15)", async () => {
    await rustScryptHash(password);
  });

  bench("Rust (Scrypt) - Low (logN=10)", async () => {
    await rustScryptHash(password, 10);
  });

  bench("Node Crypto (Scrypt) - Cost 1024", () => {
    crypto.scryptSync(password, "salt-for-scrypt", 64, { cost: 1024 });
  });
});

group("Password Verification Comparison", () => {
  bench("Rust (Argon2id) - 3 iter, 4MB", async () => {
    await rustCompare(password, rHash);
  });

  bench("Rust (Scrypt) - Default (logN=15)", async () => {
    await rustScryptCompare(password, sHash);
  });

  bench("Rust (Scrypt) - Low (logN=10)", async () => {
    await rustScryptCompare(password, sHashLow);
  });
});

group("PASETO Tokens (V4 Local)", () => {
  const payload = { user: "user-123", role: "admin" };
  const token = rustCreate(payload, secret, 3600);

  bench("Creation (Symmetric)", () => {
    rustCreate(payload, secret, 3600);
  });

  bench("Verification (Symmetric)", () => {
    rustVerify(token, secret);
  });
});

group("PASETO Tokens (V4 Public - Ed25519)", () => {
  const payload = { user: "user-123", role: "admin" };
  const token = createPublic(payload, secretKey, 3600);

  bench("Creation (Asymmetric Sign)", () => {
    createPublic(payload, secretKey, 3600);
  });

  bench("Verification (Asymmetric Verify)", () => {
    verifyPublic(token, publicKey);
  });
});

group("Node Crypto Baseline (JWT)", () => {
  bench("JWT HS256 Creation", () => {
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({
      sub: "user-123",
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000)
    })).toString("base64url");
    const signature = crypto.createHmac("sha256", secret)
      .update(`${header}.${payload}`)
      .digest("base64url");
    return `${header}.${payload}.${signature}`;
  });
});

await run();


