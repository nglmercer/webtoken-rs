# webtoken-rs 🦀

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-stable-brightgreen.svg)](https://www.rust-lang.org/)
[![Bun](https://img.shields.io/badge/Bun-v1.0%2B-blue.svg)](https://bun.sh/)

A high-performance NAPI (Node-API) native addon for **Bcrypt password hashing** and **JWT (JSON Web Token) creation**, built with Rust for the Bun runtime.

## 🚀 Features

- **Blazing Fast**: Native Rust implementation using `bcrypt` and `jsonwebtoken` crates.
- **Bun Optimized**: Specifically tuned for use with the Bun runtime.
- **Type Safe**: Includes full TypeScript definitions automatically generated from Rust.
- **Secure**: Implements industry-standard Bcrypt for password storage and HS256 for tokens.

## 📦 Installation

```bash
bun install webtoken-rs
```

## 🛠 Usage

```typescript
import { hash, compare, create } from "webtoken-rs";

// 1. Hash a password
const hashedPassword = hash("my-super-secret-password", 10);
console.log(`Hashed: ${hashedPassword}`);

// 2. Compare a password
const isMatch = compare("my-super-secret-password", hashedPassword);
console.log(`Match: ${isMatch}`); // true

// 3. Create a JWT
const token = create("user-123", "your-secret-key", 3600);
console.log(`JWT: ${token}`);
```

## 📊 Benchmarks

Measured on **AMD Ryzen 7 3750H** with **Bun 1.3.12** and **Node Crypto**.

### Password Hashing (Cost 10)
| Implementation | Algorithm | Average Time |
| :--- | :--- | :--- |
| **Rust (NAPI)** | **Bcrypt** | **73.42 ms/iter** |
| Bun (Native) | Bcrypt | 74.87 ms/iter |
| Node Crypto | Scrypt | 2.50 ms/iter |

### Password Verification
| Implementation | Algorithm | Average Time |
| :--- | :--- | :--- |
| Bun (Native) | Bcrypt | 72.10 ms/iter |
| **Rust (NAPI)** | **Bcrypt** | **76.62 ms/iter** |

### JWT Creation (HS256)
| Implementation | Library | Average Time |
| :--- | :--- | :--- |
| **Rust (NAPI)** | **jsonwebtoken** | **4.91 µs/iter** (🚀 **~2.7x Faster**) |
| Node Crypto | Manual HMAC | 13.11 µs/iter |

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
