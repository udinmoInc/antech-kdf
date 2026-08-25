import { hash, verify, hashWithConfig, defaultConfig, needsRehash, needsRehashWithPolicy, defaultRehashPolicy } from "../dist";

const stored = hash("correct_horse_battery_staple");
console.log(stored, verify("correct_horse_battery_staple", stored));

const cfg = defaultConfig();
cfg.memory_kib = 1024;
const custom = hashWithConfig("pw", cfg);
console.log("needs_rehash", needsRehash(custom));
const pol = defaultRehashPolicy();
pol.preferred_memory_kib = 32768;
console.log("policy", needsRehashWithPolicy(custom, pol));
