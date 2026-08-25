using System.Runtime.InteropServices;
using System.Text;

namespace Antech.Kdf;

public enum AntechStatus : int
{
    Ok = 0,
    VerificationFailed = 1,
    InvalidInput = -1,
    InvalidHash = -2,
    InternalError = -3,
    InvalidConfig = -4,
}

[StructLayout(LayoutKind.Sequential)]
public struct AntechConfig
{
    public uint MemoryKib;
    public uint SaltLength;
    public uint BlockSize;
    public uint FanIn;
    public uint Graph;
    public uint OutputLength;
}

[StructLayout(LayoutKind.Sequential)]
public struct AntechRehashPolicy
{
    public uint MinimumMemoryKib;
    public uint PreferredMemoryKib;
    public uint PreferredFanIn;
    public uint PreferredOutputLength;
}

public sealed class AntechException : Exception
{
    public AntechException(string message) : base(message) { }
}

/// <summary>Thin P/Invoke wrapper over antech-kdf-ffi. Thread-safe.</summary>
public static class AntechKdf
{
    public const uint GraphCombinedFrontier = 3;

    const string Lib = "antech_kdf_ffi";

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    static extern IntPtr antech_version();

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    static extern void antech_free(IntPtr ptr);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    static extern AntechStatus antech_config_default(out AntechConfig config);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    static extern AntechStatus antech_rehash_policy_default(out AntechRehashPolicy policy);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    static extern AntechStatus antech_hash_bytes(byte[]? password, UIntPtr len, out IntPtr outHash);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    static extern AntechStatus antech_hash_with_config_bytes(
        byte[]? password, UIntPtr len, in AntechConfig config, out IntPtr outHash);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    static extern AntechStatus antech_hash_with_config_and_salt(
        byte[]? password, UIntPtr passwordLen,
        byte[]? salt, UIntPtr saltLen,
        in AntechConfig config, out IntPtr outHash);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    static extern AntechStatus antech_verify_bytes(byte[]? password, UIntPtr len, [MarshalAs(UnmanagedType.LPUTF8Str)] string encoded);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    static extern AntechStatus antech_needs_rehash([MarshalAs(UnmanagedType.LPUTF8Str)] string encoded, out int outNeeds);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    static extern AntechStatus antech_needs_rehash_with_policy(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string encoded, in AntechRehashPolicy policy, out int outNeeds);

    static void Raise(AntechStatus st)
    {
        if (st == AntechStatus.Ok) return;
        throw st switch
        {
            AntechStatus.InvalidInput => new AntechException("invalid input"),
            AntechStatus.InvalidHash => new AntechException("invalid hash"),
            AntechStatus.InvalidConfig => new AntechException("invalid config"),
            _ => new AntechException($"internal error ({(int)st})"),
        };
    }

    static string Take(IntPtr p)
    {
        if (p == IntPtr.Zero) throw new AntechException("null string");
        var s = Marshal.PtrToStringUTF8(p) ?? throw new AntechException("null string");
        antech_free(p);
        return s;
    }

    public static string Version()
    {
        var p = antech_version();
        return Marshal.PtrToStringUTF8(p) ?? "";
    }

    public static AntechConfig DefaultConfig()
    {
        Raise(antech_config_default(out var c));
        return c;
    }

    public static AntechRehashPolicy DefaultRehashPolicy()
    {
        Raise(antech_rehash_policy_default(out var p));
        return p;
    }

    public static string Hash(string password) => Hash(Encoding.UTF8.GetBytes(password));

    public static string Hash(byte[] password)
    {
        Raise(antech_hash_bytes(password, (UIntPtr)password.Length, out var outHash));
        return Take(outHash);
    }

    public static string HashWithConfig(byte[] password, AntechConfig config)
    {
        Raise(antech_hash_with_config_bytes(password, (UIntPtr)password.Length, in config, out var outHash));
        return Take(outHash);
    }

    public static string HashWithConfigAndSalt(byte[] password, byte[] salt, AntechConfig config)
    {
        Raise(antech_hash_with_config_and_salt(
            password, (UIntPtr)password.Length, salt, (UIntPtr)salt.Length, in config, out var outHash));
        return Take(outHash);
    }

    public static bool Verify(string password, string encodedHash) =>
        Verify(Encoding.UTF8.GetBytes(password), encodedHash);

    public static bool Verify(byte[] password, string encodedHash)
    {
        var st = antech_verify_bytes(password, (UIntPtr)password.Length, encodedHash);
        if (st == AntechStatus.Ok) return true;
        if (st == AntechStatus.VerificationFailed) return false;
        Raise(st);
        return false;
    }

    public static bool NeedsRehash(string encodedHash)
    {
        Raise(antech_needs_rehash(encodedHash, out var outNeeds));
        return outNeeds != 0;
    }

    public static bool NeedsRehashWithPolicy(string encodedHash, AntechRehashPolicy policy)
    {
        Raise(antech_needs_rehash_with_policy(encodedHash, in policy, out var outNeeds));
        return outNeeds != 0;
    }
}
