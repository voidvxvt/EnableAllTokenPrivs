using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace EnableAllTokenPrivs
{
    class ProcessChild
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll")]
        static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll")]
        static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        static uint TH32CS_SNAPPROCESS = 2;

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        };


        public static Process GetParentProcess()
        {
            int iParentPid = 0;
            int iCurrentPid = Process.GetCurrentProcess().Id;

            IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

            if (hSnapshot == IntPtr.Zero)
                return null;

            PROCESSENTRY32 procEntry = new PROCESSENTRY32();
            procEntry.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));

            if (Process32First(hSnapshot, ref procEntry) == false)
                return null;

            do
            {
                if (iCurrentPid == procEntry.th32ProcessID)
                {
                    iParentPid = (int)procEntry.th32ParentProcessID;
                    break;
                }

            }
            while (iParentPid == 0 && Process32Next(hSnapshot, ref procEntry));

            if (iParentPid > 0)
                return Process.GetProcessById(iParentPid);
            else
                return null;
        }
    }
}
