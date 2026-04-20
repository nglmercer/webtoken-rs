# Multiplatform Local Build Guide

This guide explains how to build the `webtoken-rs` library for all required platforms directly from your Linux machine using **NAPI-RS** and **Zig**.

## Prerequisites

1.  **Rust**: Ensure you have `rustup` installed.
2.  **Zig**: (Already installed on your system) Used as a cross-compiler for Windows and macOS.
3.  **NAPI-RS CLI**: Installed as a dev dependency (`@napi-rs/cli`).

---

## 1. Add All Target Architectures

Run this command once to install all necessary Rust toolchains:

```bash
rustup target add \
  x86_64-pc-windows-msvc \
  aarch64-pc-windows-msvc \
  x86_64-apple-darwin \
  aarch64-apple-darwin \
  x86_64-unknown-linux-gnu \
  aarch64-unknown-linux-gnu
```

---

## 2. Build Commands

You can build for each target individually. Use the `--cross-compile` flag for non-Linux targets.

### Linux
```bash
# Linux x64 (Native)
npm run build

# Linux ARM64
npx napi build --release --target aarch64-unknown-linux-gnu --use-napi-cross --platform
```

### Windows (requires Zig)
```bash
# Windows x64
npx napi build --release --target x86_64-pc-windows-msvc --cross-compile --platform
```

### macOS (requires Zig)
```bash
# macOS Intel
npx napi build --release --target x86_64-apple-darwin --cross-compile --platform

# macOS Apple Silicon (M1/M2/M3)
npx napi build --release --target aarch64-apple-darwin --cross-compile --platform
```

---

## 3. Automation Script

To build everything at once, you can run this one-liner:

```bash
rustup target add x86_64-pc-windows-msvc x86_64-apple-darwin aarch64-apple-darwin aarch64-unknown-linux-gnu && \
bun run scripts/build_multiplatform.ts
```

## Generated Artifacts
After running the builds, you will find several `.node` files in the root directory:
- `webtoken.linux-x64-gnu.node`
- `webtoken.linux-arm64-gnu.node`
- `webtoken.win32-x64-msvc.node`
- `webtoken.darwin-x64.node`
- `webtoken.darwin-arm64.node`
