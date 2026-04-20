import { expect, test, describe } from "bun:test";
import { hash, compare, create, verify } from "../index";

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
      // PASETO v4.local uses ISO8601 for expiration. 
      // Negative offset in create should result in an expired token.
      const token = create({ sub: "123" }, secret, -100);
      expect(() => verify(token, secret)).toThrow();
    });

  });
});


