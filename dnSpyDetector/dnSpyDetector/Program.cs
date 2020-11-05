using System;
using System.Diagnostics;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using dnSpyDetector.WinTrusts;
namespace dnSpyDetector
{
    static class Program
    {
        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllToLoad);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);
        public static IntPtr kernel32 = LoadLibrary("kernel32.dll");
        public static IntPtr wintrust = LoadLibrary("wintrust.dll");
        public static IntPtr GetProcessIdIsDebuggerPresent = GetProcAddress(kernel32, "IsDebuggerPresent");
        public static IntPtr hWintrust = GetProcAddress(wintrust, "WinVerifyTrust");
        public static IntPtr GetProcessIdCheckRemoteDebuggerPresent = GetProcAddress(kernel32, "CheckRemoteDebuggerPresent");
        public static string ParrentProcessName = Process.GetProcessById(Process.GetCurrentProcess().Id).Parent().ProcessName;
        public static int ParrentProcessId = Process.GetProcessById(Process.GetCurrentProcess().Id).Parent().Id;


        //https://stackoverflow.com/questions/394816/how-to-get-parent-process-in-net-in-managed-way
        public static string FindIndexedProcessName(int pid)
        {
            var processName = Process.GetProcessById(pid).ProcessName;
            var processesByName = Process.GetProcessesByName(processName);
            string processIndexdName = null;

            for (var index = 0; index < processesByName.Length; index++)
            {
                processIndexdName = index == 0 ? processName : processName + "#" + index;
                var processId = new PerformanceCounter("Process", "ID Process", processIndexdName);
                if ((int)processId.NextValue() == pid)
                {
                    return processIndexdName;
                }
            }

            return processIndexdName;
        }
        public static Process FindPidFromIndexedProcessName(string indexedProcessName)
        {
            var parentId = new PerformanceCounter("Process", "Creating Process ID", indexedProcessName);
            return Process.GetProcessById((int)parentId.NextValue());
        }

        public static Process Parent(this Process process)
        {
            return FindPidFromIndexedProcessName(FindIndexedProcessName(process.Id));
        }

        static void Main(string[] args)
        {
            while (true)
            {
                Console.WriteLine("Checking the presence of dnSpy hooks...");
                CheckForHookedIsDebuggerPresent();
                CheckForHookedCheckRemoteDebuggerPresent();
                Console.WriteLine("Checking WinTrust Hooks...");
               CheckForHookedWinVerifyTrust();
                Console.WriteLine("Checking parent process...");
                CheckForParrentProcess();
                CheckForSignedExec();
                Console.WriteLine("Parent Process: " + ParrentProcessName);
                Console.WriteLine("Done :)");
                Thread.Sleep(5000);
                Console.Clear();

            }
        }

        public static void CheckForSignedExec()
        {
            Process proc = Process.GetProcessById(ParrentProcessId);
            string filename = proc.MainModule.FileName;
            Console.WriteLine("[Digital Signature]: {0}", WinTrust.VerifyEmbeddedSignature(filename));
            Console.WriteLine("Signature is OK: {0}", (filename));
            Console.WriteLine("Parent process path: " + filename);
        }
        public static void CheckForParrentProcess()
        {
            if ((!ParrentProcessName.Equals("explorer")) & (!ParrentProcessName.Equals("cmd")))
            {
                Console.WriteLine("Wrong parrent process! maybe your process is runned by debugger!");
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
        public static void CheckForHookedWinVerifyTrust()
        {
            byte[] data = new byte[5];
            System.Runtime.InteropServices.Marshal.Copy(hWintrust, data, 0, 5);
            Console.WriteLine("[WinTrustV]Data[0]: 0x" + data[0].ToString("X"));
            Console.WriteLine("[WinTrustV]Data[1]: 0x" + data[1].ToString("X"));
            Console.WriteLine("[WinTrustV]Data[2]: 0x" + data[2].ToString("X"));
            Console.WriteLine("[WinTrustV]Data[3]: 0x" + data[3].ToString("X"));
            Console.WriteLine("[WinTrustV]Data[4]: 0x" + data[4].ToString("X"));

            if (((((data[0] == 0xE9 || data[0] == 0x68 || data[0] == 0xB8)
                || (data[1] == 0xE9 || data[1] == 0x68 || data[1] == 0xB8)
                || (data[2] == 0xE9 || data[2] == 0x68 || data[2] == 0xB8)
                || (data[3] == 0xE9 || data[3] == 0x68 || data[3] == 0xB8)
                || (data[4] == 0xE9 || data[4] == 0x68 || data[4] == 0xB8)))))
            {
                Console.WriteLine($"WinVerifyTrust hook detected ...");
            }
            else
            {
                Console.WriteLine($"WinVerifyTrust not hook detected ...");
            }

        }
        public static void CheckForHookedCheckRemoteDebuggerPresent()
        {
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
