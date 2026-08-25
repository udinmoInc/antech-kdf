# Antech KDF — Node.js Language Bindings

Node.js bindings for Antech KDF via Node-API (`napi-rs`) calling `antech-kdf-ffi`.

```javascript
const { hashPassword, verifyPassword, needsRehash } = require("antech-kdf");

async function demo() {
    const stored = await hashPassword("secret_password");
    const valid = await verifyPassword("secret_password", stored);
}
```

For official repository updates, visit [Antech KDF on GitHub](https://github.com/udinmoInc/antech-kdf).
