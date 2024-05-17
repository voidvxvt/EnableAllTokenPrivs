# EnableAllTokenPrivs

Enable or Disable TokenPrivilege(s)

This program is actually pretty useless as it is just a wrapper for the [`AdjustTokenPrivileges()`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges) WinAPI function and enables or disables privileges on processes.  
Typically, when a program needs to perform a privileged task, it will simply call `AdjustTokenPrivileges` to enable the privileges it needs, or disable the privileges when it is done performing that privileged task.

## Usage

```cmd
C:\tools>.\EnableAllTokenPrivs.exe
EnableAllTokenPrivs.exe -> Enable/Disable TokenPrivilege(s)

-p --pid 6969                           enable/disable privilege(s) of a process
-d --disable                            disable privilege(s)
-P --privilege SeDebugPrivilege         enable/disable a single privilege
-l --list                               list privileges
-h --help                               print help (this output)
```

**Examples**

enable all disabled TokenPrivileges of the calling/parent process:
```cmd
EnableAllTokenPrivs.exe
```

list the TokenPrivileges of the calling/parent process (`whoami /priv`):
```cmd
EnableAllTokenPrivs.exe -l
```

enable the SeDebugPrivilege of the calling/parent process:
```cmd
EnableAllTokenPrivs.exe -P SeDebugPrivilege
```

disabled the SeDebugPrivilege of the process with PID 6969:
```cmd
EnableAllTokenPrivs.exe --pid 6969 --disable --privilege SeDebugPrivilege
```

list the TokenPrivileges of the process with PID 6969:
```cmd
EnableAllTokenPrivs.exe --pid 6969 --list
```

disable all enabled privileges of the process with PID 6969:
```cmd
EnableAllTokenPrivs.exe --pid 6969 --disable
```

disable the SeDebugPrivilege of the process with PID 6969:
```cmd
EnableAllTokenPrivs.exe --pid 6969 --disable --privilege SeDebugPrivilege
```


## Usage in sliver implant with `execute-assembly`

execute the assembly in a sacrifical process which enables all TokenPrivileges of the implant process (idk why you would do this but you can):
```sliver
execute-assembly -c EnableAllTokenPrivs.EnableAllTokenPrivs -m Main /tmp/EnableAllTokenPrivs.exe
```

___
if you just want to enable all privileges for your powershell process, you can use:
[EnableAllTokenPrivs.ps1](https://github.com/fashionproof/EnableAllTokenPrivs/blob/master/EnableAllTokenPrivs.ps1)

___
## Sources

[MSDN - OpenProcessToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)  
[MSDN - AdjustTokenPrivileges](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges)  
[antonioCoco/RunasCs](https://github.com/antonioCoco/RunasCs/blob/master/RunasCs.cs)  
