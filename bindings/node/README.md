# Antech KDF — Node.js / TypeScript

```bash
./sdk/scripts/build-native.sh
cd bindings/node && npm install && npm run build
node -e "const a=require('./dist'); console.log(a.hash('x'))"
```

Exports: `hash`, `verify`, `needsRehash`, `hashWithConfig`, `needsRehashWithPolicy`, `hashWithConfigAndSalt`.
