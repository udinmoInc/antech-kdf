plugins {
  kotlin("jvm") version "1.9.22"
}

group = "com.udinmo"
version = "0.1.0"

repositories { mavenCentral() }

dependencies {
  implementation(project(":java")) // when used as composite; otherwise depend on published antech-kdf
  implementation("net.java.dev.jna:jna:5.14.0")
}

// Standalone: compile against sibling Java sources
sourceSets {
  main {
    java.srcDir("../java/src/main/java")
  }
}
