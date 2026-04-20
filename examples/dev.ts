import { hash, compare, create } from "../index";

const password = "[PASSWORD]";
const cost = 10;

const hashed = await hash(password, cost);
console.log("hashed", hashed);
console.log("compare", compare(password, hashed));
console.log("create", create({ user: "user-123" }, "secret", 3600));