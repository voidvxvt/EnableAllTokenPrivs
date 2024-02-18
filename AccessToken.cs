using System;
using System.Runtime.InteropServices;
using System.Text;

namespace EnableAllTokenPrivs
{
    // https://github.com/antonioCoco/RunasCs/blob/a1e47b55952fadd46bf097be74a6efbcbe846c2b/RunasCs.cs#L1303
    public static class AccessToken
    {
        private const uint SE_PRIVILEGE_DISABLED = 0x00000000;
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;

        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;

        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY = 0x0008;
        public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
        public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
        public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
        public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
        public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const UInt32 TOKEN_ALL_ACCESS = (
            STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE |
            TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID);

        private enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            TokenIsAppContainer,
            TokenCapabilities,
            TokenAppContainerSid,
            TokenAppContainerNumber,
            TokenUserClaimAttributes,
            TokenDeviceClaimAttributes,
            TokenRestrictedUserClaimAttributes,
            TokenRestrictedDeviceClaimAttributes,
            TokenDeviceGroups,
            TokenRestrictedDeviceGroups,
            TokenSecurityAttributes,
            TokenIsRestricted,
            TokenProcessTrustLevel,
            TokenPrivateNameSpace,
            TokenSingletonAttributes,
            TokenBnoIsolation,
            TokenChildProcessFlags,
            TokenIsLessPrivilegedAppContainer,
            TokenIsSandboxed,
            TokenIsAppSilo,
            MaxTokenInfoClass
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public Int32 HighPart;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        public struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TOKEN_PRIVILEGE // represents one privilege
        {
            public int Count;
            public LUID Luid;
            public UInt32 Attr;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeName(string lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref int cchName);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, [MarshalAs(UnmanagedType.Struct)] ref LUID pLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, [MarshalAs(UnmanagedType.Struct)] ref TOKEN_PRIVILEGE Newstate, uint Bufferlength, IntPtr PreivousState, IntPtr Returnlength);

        private static string convertAttributeToString(UInt32 attribute)
        {
            if (attribute == SE_PRIVILEGE_DISABLED)
                return "Disabled";
            if (attribute == SE_PRIVILEGE_ENABLED)
                return "Enabled";
            if (attribute == (SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED))
                return "Enabled | Default Enabled";

            return "Error";
        }

        public static TOKEN_PRIVILEGES GetTokenPrivileges(IntPtr hToken)
        {
            uint TokenInfoLength = 0;
            if (!GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, TokenInfoLength, out TokenInfoLength))
                if (Marshal.GetLastWin32Error() != 122) // ERROR_INSUFFICIENT_BUFFER
                    throw new Exception("GetTokenInformation");
            IntPtr TokenInformation = Marshal.AllocHGlobal((int)TokenInfoLength);
            if (!GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenPrivileges, TokenInformation, TokenInfoLength, out TokenInfoLength))
                throw new Exception("GetTokenInformation");

            TOKEN_PRIVILEGES TokenPrivileges = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_PRIVILEGES));

            return TokenPrivileges;
        }

        public static void PrintTokenPrivileges(TOKEN_PRIVILEGES TokenPrivileges)
        {
            Console.WriteLine(string.Format("{0}\t{1}", "Privilege".PadRight(41), "Status"));
            Console.WriteLine(string.Format("{0}\t{1}", "=========================================".PadRight(41), "========"));

            for (int i = 0; i < TokenPrivileges.PrivilegeCount; i++)
            {
                LUID luid = new LUID();
                luid = TokenPrivileges.Privileges[i].Luid;
                IntPtr ptrLuid = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LUID)));
                Marshal.StructureToPtr(luid, ptrLuid, true);
                int luidNameLen = 0;
                LookupPrivilegeName(null, ptrLuid, null, ref luidNameLen); // call once to get the name len
                StringBuilder sb = new StringBuilder();
                sb.EnsureCapacity(luidNameLen + 1);
                if (!LookupPrivilegeName(null, ptrLuid, sb, ref luidNameLen)) // call again to get the name
                    throw new Exception("LookupPrivilegeName");

                string privilegeName = sb.ToString();

                Console.WriteLine($"{privilegeName.PadRight(41)}\t{AccessToken.convertAttributeToString(TokenPrivileges.Privileges[i].Attributes)}");
            }
        }

        public static bool SetTokenPrivilege(IntPtr hToken, bool disable, string privilege)
        {
            LUID luid = new LUID();
            LookupPrivilegeValue(null, privilege, ref luid);
            TOKEN_PRIVILEGE tp = new TOKEN_PRIVILEGE();
            tp.Count = 1;
            tp.Luid = luid;
            tp.Attr = (disable) ? SE_PRIVILEGE_DISABLED : SE_PRIVILEGE_ENABLED;

            if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                return false;

            return true;
        }

        public static void SetAllTokenPrivileges(IntPtr hToken, bool disable)
        {
            TOKEN_PRIVILEGES TokenPrivileges = GetTokenPrivileges(hToken);
            for (int i = 0; i < TokenPrivileges.PrivilegeCount; i++)
            {
                if (TokenPrivileges.Privileges[i].Attributes == (disable ? SE_PRIVILEGE_ENABLED: SE_PRIVILEGE_DISABLED))
                {
                    LUID luid = new LUID();
                    luid = TokenPrivileges.Privileges[i].Luid;
                    IntPtr ptrLuid = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LUID)));
                    Marshal.StructureToPtr(luid, ptrLuid, true);

                    int luidNameLen = 0;
                    LookupPrivilegeName(null, ptrLuid, null, ref luidNameLen); // call once to get the name len

                    StringBuilder sb = new StringBuilder();
                    sb.EnsureCapacity(luidNameLen + 1);

                    if (!LookupPrivilegeName(null, ptrLuid, sb, ref luidNameLen)) // call again to get the name
                        throw new Exception("LookupPrivilegeName");

                    string privilege = sb.ToString();

                    SetTokenPrivilege(hToken, disable, privilege);                 
                }
            }
        }

        public static void EnableAllPrivileges(IntPtr hToken)
        {
            string[] privs = { "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeDelegateSessionUserImpersonatePrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege", "SeUndockPrivilege", "SeUnsolicitedInputPrivilege" };
            foreach (string priv in privs)
            {
                SetTokenPrivilege(hToken, false, priv);
            }
        }
    }
}