# Antech KDF Java Binding

Uses JNI / Project Panama Foreign Function API calling `antech-kdf-ffi`.

```java
import org.antech.AntechKdf;

String hash = AntechKdf.hash("hello");
boolean valid = AntechKdf.verify("hello", hash);
```
