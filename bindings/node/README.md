# Node.js bindings

Node-API bindings over `antech-kdf-ffi`.

```javascript
const { hashPassword, verifyPassword, needsRehash } = require("antech-kdf");

const stored = await hashPassword("secret_password");
const ok = await verifyPassword("secret_password", stored);
```
