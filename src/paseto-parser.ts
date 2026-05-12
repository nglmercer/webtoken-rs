export type PasetoPurpose = "local" | "public";
export type PasetoVersion = "v4";

export interface PasetoTokenParts {
  version: PasetoVersion;
  purpose: PasetoPurpose;
  payload: string;
  footer: string;
}

export interface ParsedPasetoToken extends PasetoTokenParts {
  type: "local" | "public";
  isValid: boolean;
}

export function base64UrlDecode(input: string): Uint8Array {
  const b64 = input
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(input.length + ((4 - (input.length % 4)) % 4), "=");

  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function base64UrlEncode(data: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...data));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function parseToken(token: string): PasetoTokenParts {
  const parts = token.split(".");
  if (parts.length < 3) {
    throw new Error("Invalid PASETO token: expected at least 3 dot-separated parts");
  }

  const version = parts[0];
  const purpose = parts[1];
  const payload = parts[2];
  const footer = parts.slice(3).join(".");

  if (version !== "v4") {
    throw new Error(`Unsupported PASETO version: ${version}`);
  }
  if (purpose !== "local" && purpose !== "public") {
    throw new Error(`Unsupported PASETO purpose: ${purpose}`);
  }

  return {
    version: version as PasetoVersion,
    purpose: purpose as PasetoPurpose,
    payload,
    footer,
  };
}

export function decodePublicPayload(token: string): Record<string, unknown> {
  const parts = parseToken(token);
  if (parts.purpose !== "public") {
    throw new Error("Only v4.public tokens have a decodable payload");
  }

  const decoded = base64UrlDecode(parts.payload);
  if (decoded.length < 64) {
    throw new Error("Public token payload too short to contain signature");
  }

  const jsonBytes = decoded.slice(0, decoded.length - 64);
  const jsonStr = new TextDecoder().decode(jsonBytes);
  return JSON.parse(jsonStr);
}

export function verifyTokenFormat(token: string): ParsedPasetoToken {
  try {
    const parts = parseToken(token);
    const payloadLen = parts.payload.length;

    const type = parts.purpose as "local" | "public";
    const minLen = type === "local" ? 64 : 86;

    return {
      ...parts,
      type,
      isValid: payloadLen >= minLen,
    };
  } catch {
    return {
      version: "v4",
      purpose: "local",
      payload: "",
      footer: "",
      type: "local",
      isValid: false,
    };
  }
}

export function createTokenString(
  purpose: PasetoPurpose,
  payloadBytes: Uint8Array,
  footer?: string,
): string {
  const encoded = base64UrlEncode(payloadBytes);
  const base = `v4.${purpose}.${encoded}`;
  return footer ? `${base}.${base64UrlEncode(new TextEncoder().encode(footer))}` : base;
}
