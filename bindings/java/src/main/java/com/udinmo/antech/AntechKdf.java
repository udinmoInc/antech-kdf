package com.udinmo.antech;

import com.sun.jna.*;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

import java.nio.charset.StandardCharsets;

public final class AntechKdf {
  public static final String PACKAGE_VERSION = "0.1.0";

  private AntechKdf() {}

  public static final int GRAPH_COMBINED_FRONTIER = 3;

  public static class AntechException extends RuntimeException {
    public AntechException(String m) { super(m); }
  }

  @Structure.FieldOrder({
      "memory_kib", "salt_length", "block_size", "fan_in", "graph", "output_length"
  })
  public static class Config extends Structure {
    public int memory_kib;
    public int salt_length;
    public int block_size;
    public int fan_in;
    public int graph;
    public int output_length;

    public static Config defaults() {
      Config c = new Config();
      raise(NativeLib.INSTANCE.antech_config_default(c));
      return c;
    }
  }

  @Structure.FieldOrder({
      "minimum_memory_kib", "preferred_memory_kib", "preferred_fan_in",
      "preferred_output_length", "preferred_secret_required", "preferred_associated_data"
  })
  public static class RehashPolicy extends Structure {
    public int minimum_memory_kib;
    public int preferred_memory_kib;
    public int preferred_fan_in;
    public int preferred_output_length;
    public int preferred_secret_required;
    public int preferred_associated_data;

    public static RehashPolicy defaults() {
      RehashPolicy p = new RehashPolicy();
      raise(NativeLib.INSTANCE.antech_rehash_policy_default(p));
      return p;
    }
  }

  public interface NativeLib extends Library {
    NativeLib INSTANCE = Native.load(libName(), NativeLib.class);

    String antech_version();
    void antech_free(Pointer p);
    int antech_config_default(Config out);
    int antech_rehash_policy_default(RehashPolicy out);
    int antech_hash_bytes(Pointer password, NativeLong len, PointerByReference out);
    int antech_hash_with_config_bytes(Pointer password, NativeLong len, Config config, PointerByReference out);
    int antech_hash_with_config_and_salt(
        Pointer password, NativeLong passwordLen,
        Pointer salt, NativeLong saltLen,
        Config config, PointerByReference out);
    int antech_hash_with_inputs_bytes(
        Pointer password, NativeLong passwordLen,
        Config config,
        Pointer secret, NativeLong secretLen,
        Pointer associatedData, NativeLong associatedDataLen,
        PointerByReference out);
    int antech_hash_with_inputs_and_salt(
        Pointer password, NativeLong passwordLen,
        Pointer salt, NativeLong saltLen,
        Config config,
        Pointer secret, NativeLong secretLen,
        Pointer associatedData, NativeLong associatedDataLen,
        PointerByReference out);
    int antech_verify_bytes(Pointer password, NativeLong len, String encoded);
    int antech_verify_with_inputs_bytes(
        Pointer password, NativeLong passwordLen,
        String encoded,
        Pointer secret, NativeLong secretLen,
        Pointer associatedData, NativeLong associatedDataLen);
    int antech_needs_rehash(String encoded, IntByReference out);
    int antech_needs_rehash_with_policy(String encoded, RehashPolicy policy, IntByReference out);
  }

  private static String libName() {
    String env = System.getenv("ANTECH_KDF_LIB");
    if (env != null && !env.isEmpty()) return env;
    return "antech_kdf_ffi";
  }

  private static void raise(int st) {
    if (st == 0) return;
    if (st == -1) throw new AntechException("invalid input");
    if (st == -2) throw new AntechException("invalid hash");
    if (st == -4) throw new AntechException("invalid config");
    throw new AntechException("internal error: " + st);
  }

  private static String take(PointerByReference ref) {
    Pointer p = ref.getValue();
    if (p == null) throw new AntechException("null string");
    String s = p.getString(0, "utf8");
    NativeLib.INSTANCE.antech_free(p);
    return s;
  }

  private static Memory mem(byte[] b) {
    if (b.length == 0) return null;
    Memory m = new Memory(b.length);
    m.write(0, b, 0, b.length);
    return m;
  }

  // null = absent; empty array = present empty (non-null scratch). See antech_kdf.h.
  private static class OptBuf {
    final Pointer ptr;
    final long len;
    final Memory keep;

    OptBuf(byte[] data) {
      if (data == null) {
        ptr = null;
        len = 0;
        keep = null;
      } else if (data.length == 0) {
        keep = new Memory(1);
        keep.setByte(0, (byte) 0);
        ptr = keep;
        len = 0;
      } else {
        keep = new Memory(data.length);
        keep.write(0, data, 0, data.length);
        ptr = keep;
        len = data.length;
      }
    }
  }

  public static String version() {
    return NativeLib.INSTANCE.antech_version();
  }

  public static String hash(String password) {
    return hash(password.getBytes(StandardCharsets.UTF_8));
  }

  public static String hash(byte[] password) {
    PointerByReference out = new PointerByReference();
    Memory m = mem(password);
    raise(NativeLib.INSTANCE.antech_hash_bytes(m, new NativeLong(password.length), out));
    return take(out);
  }

  public static String hashWithConfig(byte[] password, Config config) {
    PointerByReference out = new PointerByReference();
    Memory m = mem(password);
    raise(NativeLib.INSTANCE.antech_hash_with_config_bytes(
        m, new NativeLong(password.length), config, out));
    return take(out);
  }

  public static String hashWithConfigAndSalt(byte[] password, byte[] salt, Config config) {
    PointerByReference out = new PointerByReference();
    raise(NativeLib.INSTANCE.antech_hash_with_config_and_salt(
        mem(password), new NativeLong(password.length),
        mem(salt), new NativeLong(salt.length),
        config, out));
    return take(out);
  }

  public static String hashWithInputs(
      byte[] password, Config config, byte[] secret, byte[] associatedData) {
    PointerByReference out = new PointerByReference();
    OptBuf sec = new OptBuf(secret);
    OptBuf ad = new OptBuf(associatedData);
    raise(NativeLib.INSTANCE.antech_hash_with_inputs_bytes(
        mem(password), new NativeLong(password.length), config,
        sec.ptr, new NativeLong(sec.len), ad.ptr, new NativeLong(ad.len), out));
    return take(out);
  }

  public static String hashWithInputsAndSalt(
      byte[] password, byte[] salt, Config config, byte[] secret, byte[] associatedData) {
    PointerByReference out = new PointerByReference();
    OptBuf sec = new OptBuf(secret);
    OptBuf ad = new OptBuf(associatedData);
    raise(NativeLib.INSTANCE.antech_hash_with_inputs_and_salt(
        mem(password), new NativeLong(password.length),
        mem(salt), new NativeLong(salt.length),
        config,
        sec.ptr, new NativeLong(sec.len), ad.ptr, new NativeLong(ad.len), out));
    return take(out);
  }

  private static boolean asVerified(int st) {
    if (st == 0) return true;
    if (st == 1) return false;
    raise(st);
    return false;
  }

  public static boolean verify(byte[] password, String encodedHash) {
    return asVerified(NativeLib.INSTANCE.antech_verify_bytes(
        mem(password), new NativeLong(password.length), encodedHash));
  }

  public static boolean verifyWithInputs(
      byte[] password, String encodedHash, byte[] secret, byte[] associatedData) {
    OptBuf sec = new OptBuf(secret);
    OptBuf ad = new OptBuf(associatedData);
    return asVerified(NativeLib.INSTANCE.antech_verify_with_inputs_bytes(
        mem(password), new NativeLong(password.length), encodedHash,
        sec.ptr, new NativeLong(sec.len), ad.ptr, new NativeLong(ad.len)));
  }

  public static boolean verify(String password, String encodedHash) {
    return verify(password.getBytes(StandardCharsets.UTF_8), encodedHash);
  }

  public static boolean needsRehash(String encodedHash) {
    IntByReference out = new IntByReference();
    raise(NativeLib.INSTANCE.antech_needs_rehash(encodedHash, out));
    return out.getValue() != 0;
  }

  public static boolean needsRehashWithPolicy(String encodedHash, RehashPolicy policy) {
    IntByReference out = new IntByReference();
    raise(NativeLib.INSTANCE.antech_needs_rehash_with_policy(encodedHash, policy, out));
    return out.getValue() != 0;
  }
}
