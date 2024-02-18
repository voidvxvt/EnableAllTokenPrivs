using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace EnableAllTokenPrivs
{
    class EnableAllTokenPrivs
    {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, ref IntPtr TokenHandle);

        private static void printUsage()
        {
            Console.Write(
                "EnableAllTokenPrivs.exe -> Enable/Disable TokenPrivilege(s)\n" +
                "By default, this program will enable all disabled TokenPrivileges of the parent / calling process\n" +
                "Options:\n" +
                "-p --pid 6969".PadRight(40) +                      "enable/disable privilege(s) of a process\n" +
                "-d --disable".PadRight(40) +                       "disable privilege(s)\n" +
                "-P --privilege SeDebugPrivilege".PadRight(40) +    "enable/disable only one specific privilege\n" +
                "-l --list".PadRight(40) +                          "list privileges\n" +
                "-h --help".PadRight(40) +                          "print help (this output)\n"
            );
        }

        public static void Main(string[] args)
        {
            bool disable = false;
            int processId = -1;
            string privilege = "";
            bool listPrivs = false;

            try {
                for (int ctr = 0; ctr < args.Length; ctr++)
                {
                    switch(args[ctr])
                    {
                        case "-h":
                        case "--help":
                            printUsage();
                            return;

                        case "-p":
                        case "--pid":
                            processId = int.Parse(args[++ctr]);
                            break;

                        case "-d":
                        case "--disable":
                            disable = true;
                            break;

                        case "-P":
                        case "--privilege":
                            privilege = args[++ctr];
                            break;

                        case "-l":
                        case "--list":
                            listPrivs = true;
                            break;

                        default:
                            break;
                    }
                }
            } catch (IndexOutOfRangeException) {
                Console.Error.Write("[-] Invalid arguments. Use --help for additional help.");
            } catch (Exception ex) {
                Console.Error.Write($"[-] {ex.Message}");
            }

            IntPtr hProcess = new IntPtr();
            if (processId == -1) {
                hProcess = ProcessChild.GetParentProcess().Handle;
            } else {
                hProcess = Process.GetProcessById(processId).Handle;
            }

            IntPtr hToken = IntPtr.Zero;
            if (!OpenProcessToken(hProcess, (AccessToken.TOKEN_ADJUST_PRIVILEGES | AccessToken.TOKEN_QUERY), ref hToken))
                throw new Exception("OpenProcessToken failed. Error: " + Marshal.GetLastWin32Error());

            if (listPrivs == true)
            {
                AccessToken.TOKEN_PRIVILEGES TokenPrivileges = AccessToken.GetTokenPrivileges(hToken);
                AccessToken.PrintTokenPrivileges(TokenPrivileges);
                return;
            }
            if (privilege.Length > 0)
            {
                AccessToken.SetTokenPrivilege(hToken, disable, privilege);
                return;
            }
            if (privilege.Length == 0)
            {
                AccessToken.SetAllTokenPrivileges(hToken, disable);
                return;
            }
        }
    }
}

// sliver has this functionality too but doesnt expose the operator an interface to enable/disable privileges. 
// https://github.com/BishopFox/sliver/blob/master/implant/sliver/priv/priv_windows.go