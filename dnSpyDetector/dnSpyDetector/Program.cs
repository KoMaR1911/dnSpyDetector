using System;
using System.Threading;

namespace dnSpyDetector
{
    class Program
    {

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllToLoad);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);
        public static IntPtr kernel32 = LoadLibrary("kernel32.dll");
        public static IntPtr GetProcessIdIsDebuggerPresent = GetProcAddress(kernel32, "IsDebuggerPresent");
        public static IntPtr GetProcessIdCheckRemoteDebuggerPresent = GetProcAddress(kernel32, "CheckRemoteDebuggerPresent");
         static void Main(string[] args) {

            
            while (true)
            {
                Console.WriteLine("Checking the presence of dnSpy hooks ...");
                CheckForHookedIsDebuggerPresent();
                CheckForHookedCheckRemoteDebuggerPresent();
                Thread.Sleep(2000);
                Console.Clear();
            }
        }

        public static void CheckForHookedIsDebuggerPresent()
        {
            byte[] data = new byte[5];
            System.Runtime.InteropServices.Marshal.Copy(GetProcessIdIsDebuggerPresent, data, 0, 5);
            Console.WriteLine("[IDP]Data[0]: 0x" + data[0].ToString("X"));
            Console.WriteLine("[IDP]Data[1]: 0x" + data[1].ToString("X"));
            Console.WriteLine("[IDP]Data[2]: 0x" + data[2].ToString("X"));
            Console.WriteLine("[IDP]Data[3]: 0x" + data[3].ToString("X"));
            Console.WriteLine("[IDP]Data[4]: 0x" + data[4].ToString("X"));

            if (((((data[0] == 0xE9 || data[0] == 0x68 || data[0] == 0xB8)
                || (data[1] == 0xE9 || data[1] == 0x68 || data[1] == 0xB8)
                || (data[2] == 0xE9 || data[2] == 0x68 || data[2] == 0xB8)
                || (data[3] == 0xE9 || data[3] == 0x68 || data[3] == 0xB8)
                || (data[4] == 0xE9 || data[4] == 0x68 || data[4] == 0xB8)))))
            {
                Console.WriteLine($"IsDebuggerPresent hook detected ...");
            }
            else
            {
                Console.WriteLine($"IsDebuggerPresent not hook detected ...");
            }
        }

    public static void CheckForHookedCheckRemoteDebuggerPresent()
        {
            GetProcessIdCheckRemoteDebuggerPresent = GetProcAddress(kernel32, "CheckRemoteDebuggerPresent");
            byte [] data = new byte[5];
            System.Runtime.InteropServices.Marshal.Copy(GetProcessIdCheckRemoteDebuggerPresent, data, 0, 5);
            Console.WriteLine("[CRDP]Data[0]: 0x" + data[0].ToString("X"));
            Console.WriteLine("[CRDP]Data[1]: 0x" + data[1].ToString("X"));
            Console.WriteLine("[CRDP]Data[2]: 0x" + data[2].ToString("X"));
            Console.WriteLine("[CRDP]Data[3]: 0x" + data[3].ToString("X"));
            Console.WriteLine("[CRDP]Data[4]: 0x" + data[4].ToString("X"));
            
            if (((((data[0] == 0xE9 || data[0] == 0x68 || data[0] == 0xB8)
                || (data[1] == 0xE9 || data[1] == 0x68 || data[1] == 0xB8)
                || (data[2] == 0xE9 || data[2] == 0x68 || data[2] == 0xB8)
                || (data[3] == 0xE9 || data[3] == 0x68 || data[3] == 0xB8)
                || (data[4] == 0xE9 || data[4] == 0x68 || data[4] == 0xB8)))))
            {
                Console.WriteLine($"CheckRemoteDebuggerPresent hook detected ...");
            }
            else
            {
                Console.WriteLine($"CheckRemoteDebuggerPresent not hook detected ...");
            }
        }
    }
}
