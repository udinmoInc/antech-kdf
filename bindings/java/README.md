# Java bindings

JNI / Panama wrappers around the C ABI.

```java
import org.antech.AntechKdf;

String hash = AntechKdf.hash("secret_password");
boolean ok = AntechKdf.verify("secret_password", hash);
```
