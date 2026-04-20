import { hash, compare, createPublic, verifyPublic } from "../index";

async function main() {
  console.log("--- 1. Hardware-Accelerated Argon2id (SIMD) ---");
  const password = "ultra-secure-password-123";

  const start = performance.now();
  const hashedPassword = await hash(password);
  const end = performance.now();

  console.log(`Hashed: ${hashedPassword}`);
  console.log(`Time (SIMD Optimized): ${(end - start).toFixed(2)}ms`);

  const isMatch = await compare(password, hashedPassword);
  console.log(`Match: ${isMatch}\n`);

  console.log("--- 2. Public-Key PASETO (Ed25519) ---");

  /**
   * For Ed25519, you typically have a 64-byte secret key and a 32-byte public key.
   * Here are example hex-encoded keys for demonstration.
   * In production, generate these using a secure library.
   */
  const secretKeyHex = "b4c8a95311c67f0329a1b635201c107f90c37e937d4036f0195668e21a221236";
  const publicKeyHex = "66c85777a060f64c6778f6927a4d57a2e0a2d59048f075047b85c156f4d2a13a";

  const payload = {
    sub: "user_asymmetric_123",
    role: "manager",
    iss: "auth-service"
  };

  try {
    // Create an asymmetric token (v4.public)
    const token = createPublic(payload, secretKeyHex, 3600);
    console.log(`Asymmetric Token: ${token.substring(0, 40)}...`);
    console.log(`Prefix: ${token.split(".")[0]}.${token.split(".")[1]}`); // v4.public

    // Verify using only the Public Key
    const verified = verifyPublic(token, publicKeyHex);
    console.log("Verified Payload (Asymmetric):", JSON.stringify(verified, null, 2));

  } catch (error) {
    console.error("Asymmetric flow failed:", error);
  }
}

main().catch(console.error);
