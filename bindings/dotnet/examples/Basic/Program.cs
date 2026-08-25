using Antech.Kdf;

var stored = AntechKdf.Hash("correct_horse_battery_staple");
Console.WriteLine(stored);
Console.WriteLine(AntechKdf.Verify("correct_horse_battery_staple", stored));

var cfg = AntechKdf.DefaultConfig();
cfg.MemoryKib = 1024;
var custom = AntechKdf.HashWithConfig(System.Text.Encoding.UTF8.GetBytes("pw"), cfg);
Console.WriteLine($"needs_rehash={AntechKdf.NeedsRehash(custom)}");
var pol = AntechKdf.DefaultRehashPolicy();
pol.PreferredMemoryKib = 32768;
Console.WriteLine($"policy={AntechKdf.NeedsRehashWithPolicy(custom, pol)}");
