using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace OmniHub.Core;

/// <summary>
/// Current-user Windows DPAPI wrapper via crypt32.dll (CryptProtectData / CryptUnprotectData).
/// Protects sensitive cross-app artifacts such as exported Aeon Playwright auth.json sessions at rest.
/// </summary>
public static class DpapiProtector
{
    private const uint CRYPTPROTECT_UI_FORBIDDEN = 0x1;
    private static readonly byte[] DefaultEntropy = Encoding.UTF8.GetBytes("DelgadoLogic.OmniHub.SessionVault.v1");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(
        ref DATA_BLOB pDataIn,
        string? szDataDescr,
        ref DATA_BLOB pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        uint dwFlags,
        out DATA_BLOB pDataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn,
        IntPtr ppszDataDescr,
        ref DATA_BLOB pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        uint dwFlags,
        out DATA_BLOB pDataOut);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);

    public static byte[] ProtectBytes(ReadOnlySpan<byte> plaintext, byte[]? entropy = null)
    {
        var effectiveEntropy = entropy ?? DefaultEntropy;
        var inHandle = GCHandle.Alloc(plaintext.ToArray(), GCHandleType.Pinned);
        var entHandle = GCHandle.Alloc(effectiveEntropy, GCHandleType.Pinned);
        DATA_BLOB outBlob = default;

        try
        {
            var inBlob = new DATA_BLOB
            {
                cbData = plaintext.Length,
                pbData = plaintext.Length == 0 ? IntPtr.Zero : inHandle.AddrOfPinnedObject()
            };
            var entBlob = new DATA_BLOB
            {
                cbData = effectiveEntropy.Length,
                pbData = entHandle.AddrOfPinnedObject()
            };

            if (!CryptProtectData(
                    ref inBlob,
                    "DelgadoLogic OmniHub Session",
                    ref entBlob,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CRYPTPROTECT_UI_FORBIDDEN,
                    out outBlob))
            {
                throw new CryptographicException("DPAPI CryptProtectData failed.", new Win32Exception(Marshal.GetLastWin32Error()));
            }

            var cipher = new byte[outBlob.cbData];
            if (outBlob.cbData > 0 && outBlob.pbData != IntPtr.Zero)
            {
                Marshal.Copy(outBlob.pbData, cipher, 0, outBlob.cbData);
            }
            return cipher;
        }
        finally
        {
            if (outBlob.pbData != IntPtr.Zero)
                LocalFree(outBlob.pbData);
            if (entHandle.IsAllocated)
                entHandle.Free();
            if (inHandle.IsAllocated)
                inHandle.Free();
        }
    }

    public static byte[] UnprotectBytes(ReadOnlySpan<byte> ciphertext, byte[]? entropy = null)
    {
        if (ciphertext.IsEmpty)
            throw new CryptographicException("Cannot unprotect empty DPAPI payload.");

        var effectiveEntropy = entropy ?? DefaultEntropy;
        var inHandle = GCHandle.Alloc(ciphertext.ToArray(), GCHandleType.Pinned);
        var entHandle = GCHandle.Alloc(effectiveEntropy, GCHandleType.Pinned);
        DATA_BLOB outBlob = default;

        try
        {
            var inBlob = new DATA_BLOB
            {
                cbData = ciphertext.Length,
                pbData = inHandle.AddrOfPinnedObject()
            };
            var entBlob = new DATA_BLOB
            {
                cbData = effectiveEntropy.Length,
                pbData = entHandle.AddrOfPinnedObject()
            };

            if (!CryptUnprotectData(
                    ref inBlob,
                    IntPtr.Zero,
                    ref entBlob,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CRYPTPROTECT_UI_FORBIDDEN,
                    out outBlob))
            {
                throw new CryptographicException("DPAPI CryptUnprotectData failed.", new Win32Exception(Marshal.GetLastWin32Error()));
            }

            var plain = new byte[outBlob.cbData];
            if (outBlob.cbData > 0 && outBlob.pbData != IntPtr.Zero)
            {
                Marshal.Copy(outBlob.pbData, plain, 0, outBlob.cbData);
            }
            return plain;
        }
        finally
        {
            if (outBlob.pbData != IntPtr.Zero)
                LocalFree(outBlob.pbData);
            if (entHandle.IsAllocated)
                entHandle.Free();
            if (inHandle.IsAllocated)
                inHandle.Free();
        }
    }

    public static byte[] ProtectString(string plaintextUtf8)
    {
        ArgumentNullException.ThrowIfNull(plaintextUtf8);
        return ProtectBytes(Encoding.UTF8.GetBytes(plaintextUtf8));
    }

    public static string UnprotectString(ReadOnlySpan<byte> ciphertext)
    {
        var bytes = UnprotectBytes(ciphertext);
        return Encoding.UTF8.GetString(bytes);
    }
}
