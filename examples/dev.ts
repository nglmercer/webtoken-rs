import { hash, compare, create, verify } from "../index";

async function main() {
  const password = "my-super-secure-password";
  const secret = "your-32-character-secret-key-123";

  console.log("--- 1. Argon2id Password Hashing ---");
  
  // Hashing is async to keep the event loop responsive
  const startHash = performance.now();
  const hashedPassword = await hash(password);
  const endHash = performance.now();
  
  console.log(`Hashed: ${hashedPassword}`);
  console.log(`Time taken: ${(endHash - startHash).toFixed(2)}ms`);

  // Comparison is also async
  const isMatch = await compare(password, hashedPassword);
  console.log(`Password match: ${isMatch}`); // true

  const isWrong = await compare("wrong-password", hashedPassword);
  console.log(`Wrong password match: ${isWrong}`); // false

  console.log("\n--- 2. PASETO Token Management (V4 Local) ---");

  // Create a PASETO token (Symmetric Encryption)
  const payload = {
    sub: "user_12345",
    role: "admin",
    scopes: ["read", "write", "delete"],
    custom_data: {
      theme: "dark",
      notifications: true
    }
  };

  const token = create(payload, secret, 3600); // 1 hour expiration
  console.log(`PASETO Token: ${token}`);
  console.log(`Token Prefix: ${token.split(".")[0]}.${token.split(".")[1]}`); // v4.local

  // Verify and decrypt the token
  try {
    const decoded = verify(token, secret);
    console.log("Verified Payload:", JSON.stringify(decoded, null, 2));
    console.log(`Subject: ${decoded.sub}`);
  } catch (error) {
    console.error("Verification failed:", error);
  }

  console.log("\n--- 3. Error Handling ---");
  try {
    verify(token, "wrong-secret-key-long-enough");
  } catch (error) {
    console.log("Expected verification error caught:", (error as Error).message);
  }
}

main().catch(console.error);