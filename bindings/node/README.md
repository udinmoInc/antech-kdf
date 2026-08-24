# Antech KDF Node.js Binding

Uses Node-API / `napi-rs` calling `antech-kdf-ffi`.

```javascript
const { hashPassword, verifyPassword, needsRehash } = require("antech-kdf");

async function demo() {
    const stored = await hashPassword("hello");
    const valid = await verifyPassword("hello", stored);
}
```
