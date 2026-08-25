package com.udinmo.antech;

public class BasicExample {
  public static void main(String[] args) {
    String stored = AntechKdf.hash("correct_horse_battery_staple");
    System.out.println(stored);
    System.out.println(AntechKdf.verify("correct_horse_battery_staple", stored));
    AntechKdf.Config cfg = AntechKdf.Config.defaults();
    cfg.memory_kib = 1024;
    String custom = AntechKdf.hashWithConfig("pw".getBytes(), cfg);
    System.out.println("needs_rehash=" + AntechKdf.needsRehash(custom));
    AntechKdf.RehashPolicy pol = AntechKdf.RehashPolicy.defaults();
    pol.preferred_memory_kib = 32768;
    System.out.println("policy=" + AntechKdf.needsRehashWithPolicy(custom, pol));
  }
}
