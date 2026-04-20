import { hash as rustHash, compare as rustCompare } from "../index";
import { run, bench, group } from "mitata";

const password = "benchmarking-is-fun";
const cost = 10;

// Setup
console.log("Generating hashes for verification benchmark...");
const rHash = rustHash(password, cost);
const bHash = await Bun.password.hash(password, {
  algorithm: "bcrypt",
  cost: cost,
});

group("Password Hashing (Bcrypt, Cost 10)", () => {
  bench("Rust (NAPI/Bcrypt)", () => {
    rustHash(password, cost);
  });

  bench("Bun (Native)", async () => {
    await Bun.password.hash(password, {
      algorithm: "bcrypt",
      cost: cost,
    });
  });
});

group("Password Verification", () => {
  bench("Rust (NAPI/Bcrypt)", () => {
    rustCompare(password, rHash);
  });

  bench("Bun (Native)", async () => {
    await Bun.password.verify(password, bHash);
  });
});

await run();
