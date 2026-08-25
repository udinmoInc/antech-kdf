# Antech KDF — Java Language Bindings

Java bindings for Antech KDF via JNI / Project Panama Foreign Function API.

```java
import org.antech.AntechKdf;

String hash = AntechKdf.hash("secret_password");
boolean valid = AntechKdf.verify("secret_password", hash);
```

For official repository updates, visit [Antech KDF on GitHub](https://github.com/udinmoInc/antech-kdf).
