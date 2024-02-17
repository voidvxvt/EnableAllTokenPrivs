# EnableAllTokenPrivs

Enable or Disable TokenPrivilege(s)

## Usage

```cmd
.\EnableAllTokenPrivs.exe
```

```log
EnableAllTokenPrivs.exe -> Enable/Disable TokenPrivilege(s)

-p --pid 6969                           enable/disable privilege(s) of a process
-d --disable                            disable privilege(s)
-P --privilege SeDebugPrivilege         enable/disable just one specific privilege
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


## Usage in Sliver Implant with `execute-assembly`

execute the assembly in a sacrifical process which enables all TokenPrivileges of the implant process:
```sliver
execute-assembly -c EnableAllTokenPrivs.EnableAllTokenPrivs -m Main /tmp/EnableAllTokenPrivs.exe
```

___
if you just want to enable all privileges for your powershell process, you're fine using:
[EnableAllTokenPrivs.ps1](https://github.com/fashionproof/EnableAllTokenPrivs/blob/master/EnableAllTokenPrivs.ps1)

___
## Sources

[MSDN - OpenProcessToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)  
[MSDN - AdjustTokenPrivileges](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges)  
[antonioCoco/RunasCs](https://github.com/antonioCoco/RunasCs/blob/master/RunasCs.cs)  
