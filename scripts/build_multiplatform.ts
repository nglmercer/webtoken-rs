import { $ } from "bun";

const targets = [
  { target: "x86_64-pc-windows-msvc", cross: true },
  { target: "aarch64-pc-windows-msvc", cross: true },
  { target: "x86_64-apple-darwin", cross: true },
  { target: "aarch64-apple-darwin", cross: true },
  { target: "aarch64-unknown-linux-gnu", napiCross: true },
  { target: "x86_64-unknown-linux-gnu", native: true },
];

console.log("🚀 Starting Multiplatform Build Process...\n");

// 1. Ensure all targets are added to rustup
console.log("📦 Ensuring Rust targets are installed...");
for (const { target } of targets) {
  try {
    await $`rustup target add ${target}`;
  } catch (e) {
    console.error(`⚠️  Failed to add target ${target}, but continuing...`);
  }
}

// 2. Sequential Builds
const results: { target: string; success: boolean }[] = [];

for (const { target, cross, napiCross, native } of targets) {
  console.log(`\n🛠️  Building for ${target}...`);

  try {
    if (native) {
      await $`npx napi build --release --platform`;
    } else if (napiCross) {
      await $`npx napi build --release --target ${target} --use-napi-cross --platform`;
    } else if (cross) {
      await $`npx napi build --release --target ${target} --cross-compile --platform`;
    }
    console.log(`✅ Success: ${target}`);
    results.push({ target, success: true });
  } catch (error) {
    console.error(`❌ Failed: ${target}`);
    results.push({ target, success: false });
  }
}

console.log("\n📊 Build Summary:");
results.forEach(r => {
  console.log(`${r.success ? "✅" : "❌"} ${r.target}`);
});

if (results.some(r => !r.success)) {
  console.log("\n⚠️ Some builds failed. Check the logs above.");
  process.exit(1);
} else {
  console.log("\n✨ All multiplatform builds complete!");
}
