package com.udinmo.antech

/**
 * Kotlin façade over the Java JNA bindings — same native library, no crypto duplication.
 */
object Antech {
  const val GRAPH_COMBINED_FRONTIER = AntechKdf.GRAPH_COMBINED_FRONTIER

  fun hash(password: String): String = AntechKdf.hash(password)
  fun hash(password: ByteArray): String = AntechKdf.hash(password)
  fun hashWithConfig(password: ByteArray, config: AntechKdf.Config): String =
    AntechKdf.hashWithConfig(password, config)
  fun hashWithConfigAndSalt(password: ByteArray, salt: ByteArray, config: AntechKdf.Config): String =
    AntechKdf.hashWithConfigAndSalt(password, salt, config)
  fun verify(password: String, encoded: String): Boolean = AntechKdf.verify(password, encoded)
  fun needsRehash(encoded: String): Boolean = AntechKdf.needsRehash(encoded)
  fun needsRehashWithPolicy(encoded: String, policy: AntechKdf.RehashPolicy): Boolean =
    AntechKdf.needsRehashWithPolicy(encoded, policy)
  fun version(): String = AntechKdf.version()
}
