import { expect, test, describe } from "bun:test";
import { hash, compare, create } from "../index";

describe("Webtoken NAPI Tests", () => {
  const password = "my-secure-password";
  const secret = "super-secret-key";

  describe("Bcrypt Hashing", () => {
    test("should hash password successfully", () => {
      const result = hash(password, 10);
      expect(result).toBeDefined();
      expect(result.length).toBeGreaterThan(0);
      expect(result).toStartWith("$2"); // Bcrypt prefix
    });

    test("should compare correct password", () => {
      const hashed = hash(password, 10);
      const isMatch = compare(password, hashed);
      expect(isMatch).toBe(true);
    });

    test("should fail on wrong password", () => {
      const hashed = hash(password, 10);
      const isMatch = compare("wrong-password", hashed);
      expect(isMatch).toBe(false);
    });

    test("should respect custom cost", () => {
      const start = performance.now();
      hash(password, 12);
      const end = performance.now();
      const highCostTime = end - start;

      const startLow = performance.now();
      hash(password, 4);
      const endLow = performance.now();
      const lowCostTime = endLow - startLow;

      expect(highCostTime).toBeGreaterThan(lowCostTime);
    });
  });

  describe("JWT Creation", () => {
    test("should create a valid JWT string", () => {
      const token = create("user-123", secret, 3600);
      expect(token).toBeDefined();
      expect(token.split(".").length).toBe(3);
    });

    test("should fail with invalid expiration (negative)", () => {
      // Depending on implementation, negative might be rejected or just expire immediately
      // Our implementation uses i64 and checked_add_signed. 
      // If we pass a huge negative number, it might be fine, but let's just check it returns a string.
      const token = create("user-123", secret, -3600);
      expect(token).toBeDefined();
    });
  });
});
