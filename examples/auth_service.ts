import { create, verify } from "../index";

/**
 * A modular Auth Service to handle token logic in a centralized way.
 */
class AuthService {
  private secret: string;

  constructor(secret: string) {
    this.secret = secret;
  }

  /**
   * Generates a token for a user with specific roles/scopes.
   */
  generateUserToken(userId: string, role: string, scopes: string[] = []) {
    return create(
      {
        sub: userId,
        role: role,
        scopes: scopes,
      },
      this.secret,
      3600 // 1 hour
    );
  }

  /**
   * Validates a token and returns the payload if valid.
   */
  validateToken(token: string) {
    try {
      return verify(token, this.secret);
    } catch (e) {
      throw new Error(`Unauthorized: ${(e as Error).message}`);
    }
  }

  /**
   * Higher-order function to validate specific requirements.
   */
  authorize(token: string, requirements: { role?: string; scope?: string }) {
    const payload = this.validateToken(token);

    if (requirements.role && payload.role !== requirements.role) {
      throw new Error(`Forbidden: Required role ${requirements.role}, got ${payload.role}`);
    }

    if (requirements.scope && Array.isArray(payload.scopes)) {
      if (!payload.scopes.includes(requirements.scope)) {
        throw new Error(`Forbidden: Missing required scope ${requirements.scope}`);
      }
    }

    return payload;
  }
}

// --- Usage Example ---

async function demo() {
  const auth = new AuthService("your-32-character-secret-key-123");

  // 1. Create tokens for different users
  const adminToken = auth.generateUserToken("admin_1", "admin", ["read", "write", "delete"]);
  const userToken = auth.generateUserToken("user_1", "user", ["read"]);

  console.log("--- Role Validation Demo ---");

  try {
    console.log("Admin accessing admin resource...");
    const adminData = auth.authorize(adminToken, { role: "admin" });
    console.log(`Access Granted for: ${adminData.sub}\n`);

    console.log("User accessing user resource...");
    const userData = auth.authorize(userToken, { role: "user" });
    console.log(`Access Granted for: ${userData.sub}\n`);

    console.log("User trying to access admin resource...");
    auth.authorize(userToken, { role: "admin" });
  } catch (error) {
    console.log(`Access Denied: ${(error as Error).message}\n`);
  }

  console.log("--- Scope Validation Demo ---");

  try {
    console.log("User checking for 'write' scope...");
    auth.authorize(userToken, { scope: "write" });
  } catch (error) {
    console.log(`Access Denied: ${(error as Error).message}\n`);
  }

  try {
    console.log("Admin checking for 'delete' scope...");
    const data = auth.authorize(adminToken, { scope: "delete" });
    console.log(`Access Granted. Admin can delete!\n`, data);
  } catch (error) {
    console.log(`Access Denied: ${(error as Error).message}`);
  }
}

demo().catch(console.error);
