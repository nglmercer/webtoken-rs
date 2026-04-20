# webtoken-rs 🦀

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org/)
[![Bun](https://img.shields.io/badge/Bun-v1.0%2B-blue.svg)](https://bun.sh/)

A high-performance NAPI (Node-API) native addon for **Argon2id password hashing** and **PASETO (Platform-Agnostic Security Tokens)**, built with Rust for the Bun runtime.

## 🚀 Features

- **Blazing Fast**: Native Rust implementation using `argon2` and `pasetors` crates.
- **Bun Optimized**: Specifically tuned for use with the Bun runtime.
- **Type Safe**: Includes full TypeScript definitions automatically generated from Rust.
- **Modern Security**: Implements **Argon2id** (OWASP recommendation) and **PASETO V4.Local** (secure alternative to JWT).

## 📦 Installation

```bash
bun install webtoken-rs
```

## 🛠 Usage

```typescript
import { hash, compare, create, verify } from "webtoken-rs";

// 1. Hash a password
const hashedPassword = await hash("my-super-secret-password");

// 2. Compare a password
const isMatch = await compare("my-super-secret-password", hashedPassword);

// 3. Create a PASETO Token (V4 Local)
// Secure by design: Encrypted, authenticated, and no algorithm confusion risks.
const token = create({ sub: "user-123", role: "admin" }, "your-secret-key", 3600);
console.log(`PASETO: ${token}`);

// 4. Verify a PASETO Token
const payload = verify(token, "your-secret-key");
console.log(payload.sub); // "user-123"
```


## 📊 Benchmarks

Measured on **AMD Ryzen 7 3750H** with **Bun 1.3.12**.

### Password Hashing
| Implementation | Algorithm | Average Time |
| :--- | :--- | :--- |
| **Rust (NAPI)** | **Argon2id (Default)** | **~55.47 ms/iter** (🚀 **Faster**) |
| **Rust (NAPI)** | **Argon2id (High Mem)** | **~50.96 ms/iter** |
| Bun (Native) | Bcrypt (Cost 10) | ~87.88 ms/iter |

### Password Verification
| Implementation | Algorithm | Average Time |
| :--- | :--- | :--- |
| **Rust (NAPI)** | **Argon2id** | **~17.84 ms/iter** (🚀 **~4.3x Faster**) |
| Bun (Native) | Bcrypt | ~77.47 ms/iter |

### Token Creation
| Implementation | Algorithm | Average Time |
| :--- | :--- | :--- |
| **Rust (NAPI)** | **PASETO V4.Local** | **~18.58 µs/iter** |
| Node Crypto | JWT (Manual HMAC) | ~13.63 µs/iter |



> [!TIP]
> Our Rust implementation is significantly faster at JWT creation because it performs JSON serialization, Base64Url encoding, and HMAC signing in a single high-performance native pass.

## 🛠 Development

### Build
```bash
bun run build          # Release build
bun run build:debug    # Debug build
```

### Test
```bash
bun test
```

### Benchmark
```bash
bun run bench
```

## 🏗 Project Structure

- `src/lib.rs` - Native Rust implementation.
- `index.js` - Generated NAPI entry point.
- `index.d.ts` - Generated TypeScript definitions.
- `tests/` - Comprehensive test and benchmark suite.

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

## 👤 Author

**nglmercer** - [GitHub](https://github.com/nglmercer)
