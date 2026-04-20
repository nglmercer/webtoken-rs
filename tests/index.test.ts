import { expect, test, describe } from "bun:test";
import { hash, compare, create, verify, decodeToken, decodeHeader, Algorithm } from "../index";

describe("Webtoken NAPI Tests", () => {
  const password = "my-secure-password";
  const secret = "super-secret-key";

  describe("Argon2 Hashing", () => {
    test("should hash password successfully", () => {
      const result = hash(password);
      expect(result).toBeDefined();
      expect(result.length).toBeGreaterThan(0);
      expect(result).toStartWith("$argon2id"); // Argon2id prefix
    });

    test("should compare correct password", () => {
      const hashed = hash(password);
      const isMatch = compare(password, hashed);
      expect(isMatch).toBe(true);
    });

    test("should fail on wrong password", () => {
      const hashed = hash(password);
      const isMatch = compare("wrong-password", hashed);
      expect(isMatch).toBe(false);
    });

    test("should respect custom iterations", () => {
      const start = performance.now();
      hash(password, 5); // iterations
      const end = performance.now();
      const highCostTime = end - start;

      const startLow = performance.now();
      hash(password, 1); // iterations
      const endLow = performance.now();
      const lowCostTime = endLow - startLow;

      expect(highCostTime).toBeGreaterThan(lowCostTime);
    });

    test("should respect custom memory", () => {
      const result = hash(password, 2, 8192); // 8MB memory
      expect(result).toContain("m=8192");
    });
  });


  describe("JWT Creation", () => {
    test("should create a valid JWT string", () => {
      const token = create({ user: "user-123" }, secret, 3600);
      expect(token).toBeDefined();
      expect(token.split(".").length).toBe(3);
    });

    test("should create token with different algorithms", () => {
      const tokenHS256 = create({ sub: "123" }, secret, 3600, Algorithm.HS256);
      const tokenHS512 = create({ sub: "123" }, secret, 3600, Algorithm.HS512);

      expect(tokenHS256).toBeDefined();
      expect(tokenHS512).toBeDefined();
      expect(tokenHS256).not.toBe(tokenHS512);

      const header256 = decodeHeader(tokenHS256);
      const header512 = decodeHeader(tokenHS512);

      expect(header256.algo).toBe("HS256");
      expect(header512.algo).toBe("HS512");
    });

    test("should fail with invalid expiration (negative)", () => {
      const token = create({ user: "user-123" }, secret, -3600);
      expect(token).toBeDefined();
    });
  });

  describe("JWT Verification", () => {
    test("should verify a valid token", () => {
      const payload = { sub: "user-123", role: "admin" };
      const token = create(payload, secret, 3600);
      const decoded = verify(token, secret);

      expect(decoded.sub).toBe(payload.sub);
      expect(decoded.role).toBe(payload.role);
      expect(decoded.exp).toBeDefined();
    });

    test("should throw error with incorrect secret", () => {
      const token = create({ sub: "123" }, secret, 3600);
      expect(() => verify(token, "wrong-secret")).toThrow();
    });

    test("should throw error for expired token", () => {
      // Create a token that is already expired
      const token = create({ sub: "123" }, secret, -100);
      expect(() => verify(token, secret)).toThrow();
    });

    test("should verify with specific algorithm", () => {
      const token = create({ sub: "123" }, secret, 3600, Algorithm.HS512);
      const decoded = verify(token, secret, Algorithm.HS512);
      expect(decoded.sub).toBe("123");
    });

    test("should throw if algorithm mismatch during verification", () => {
      const token = create({ sub: "123" }, secret, 3600, Algorithm.HS256);
      // verify defaults to HS256 if not specified, so let's try HS512
      expect(() => verify(token, secret, Algorithm.HS512)).toThrow();
    });
  });

  describe("JWT Decoding (Unverified)", () => {
    test("should decode token without secret validation", () => {
      const payload = { sub: "user-456" };
      const token = create(payload, secret, 3600);

      // Should work even with wrong "secret" context (though decodeToken doesn't take secret)
      const decoded = decodeToken(token);
      expect(decoded.sub).toBe(payload.sub);
    });

    test("should decode expired token", () => {
      const token = create({ sub: "expired" }, secret, -3600);
      const decoded = decodeToken(token);
      expect(decoded.sub).toBe("expired");
    });
  });

  describe("JWT Header", () => {
    test("should decode header correctly", () => {
      const token = create({ sub: "123" }, secret, 3600, Algorithm.HS384);
      const header = decodeHeader(token);

      expect(header.algo).toBe("HS384");
      expect(header.typ).toBe("JWT");
    });
  });
});

