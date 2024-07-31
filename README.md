# toyDebugger
Toy debugger created for learning purposes

### About
Learning project to understand how a debugger works under the hood.

### Functionality
- Debug Events:
  - Load DLL
  - Unload DLL
  - Create Thread
  - Exit Thread
  - Create Process
  - Exit Process
- Choose a target function to set a breakpoint 
- Choose breakpoint type (hardware/software)
- Dump all data inside the chosen section

### Disclaimer & Recommendation
This debugger is not usable in real environments; its purpose is to serve as a repository for learning how a debugger works under the hood. The **BEST** way to enjoy this repo is to modify the code, trying to redirect the execution flow or code other target programs that could be more difficult to debug.

### Preview
Here is a preview of how it works.

The start of the code, where you choose the target function, the section to dump, and the breakpoint type (software or hardware), is as follows:
````c
// Set a software breakpoint
#define SOFTWAREbp

// Set a Hardware breakpoint
// #define HARDWAREbp

///----------------------------------------------------------------------------------------------------------------------------------------------------------
///----------------------------------------------------------------------------------------------------------------------------------------------------------
///----------------------------------------------------------------------------------------------------------------------------------------------------------

// function to track and set the bp
const char* pGlobalTargetFunction = "NtWriteFile";

// choose the section to dump data and obtain information
const char* PEsection = ".rdata";

// original byte before the software breakpoint
BYTE bGlobalOriginalByte = NULL;

// address of nt function we want to set the breakpoint (hardware or software)
PVOID pGlobalFuncAddress = NULL;

// target.exe entry address
PVOID pGlobalEntryImageAddress = NULL;
...
````

We only have to execute the debugger with the target image file as the first argument.

Here is the output:
````
C:\tmp\toyDebugger\toyDebugger\Debug>toydebugger.exe C:\tmp\toyDebugger\2Debug\Debug\2debug.exe

[+] TARGET PATH: 'C:\tmp\toyDebugger\2Debug\Debug\2debug.exe'

[+] Target Process ID [20032]
        \__Thread ID [21128]

Press ENTER to quit debug loop


[CREATE_PROCESS_DEBUG_EVENT]

Target loaded at 0x00A30000

Target entry point at 0x00A41023

        [!] Getting image file of C:\tmp\toyDebugger\2Debug\Debug\2debug.exe
                \__hfile = 0x0000013C
                        \____size -> 40448

        .textbss

        .text

        .rdata


           [.rdata] at 0x00A47000
           Image loaded at: 0x00A30000
           size = 9025
           Virtual Address = 0x00017000

                [.rdata] Dumping all data...

                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        ...
                        ...
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00
        .data

        .idata

        .msvcjmc├☺

        .00cfg

        .rsrc

        .reloc


[LOADED DLL] C:\Windows\SysWOW64\ntdll.dll
        \__hfile = 0x00000144
                \____size -> 1700936

                [LOADED DLL INFO]
                        \__PE Dll base -> 0x76F50000
                        \__PE Dll Entry point -> 0x76F50000

                                [ntdll.dll] 0x7705DB40
                                        \__[NtWriteFile] Found at 0x76FC3060

                                        [SOFTWARE BREAKPOINT] at 0x76FC3060
                                                \__Original byte replaced by 0xcc -> [0xB8]


[LOADED DLL] C:\Windows\SysWOW64\kernel32.dll
        \__hfile = 0x00000154
                \____size -> 650272

                [LOADED DLL INFO]
                        \__PE Dll base -> 0x768A0000
                        \__PE Dll Entry point -> 0x768BF8E0


[LOADED DLL] C:\Windows\SysWOW64\KernelBase.dll
        \__hfile = 0x00000148
                \____size -> 2337824

                [LOADED DLL INFO]
                        \__PE Dll base -> 0x753E0000
                        \__PE Dll Entry point -> 0x754F91D0


[LOADED DLL] C:\Windows\SysWOW64\apphelp.dll
        \__hfile = 0x00000148
                \____size -> 652800

                [LOADED DLL INFO]
                        \__PE Dll base -> 0x6E970000
                        \__PE Dll Entry point -> 0x6E9AC0D0


[LOADED DLL] C:\Windows\SysWOW64\vcruntime140d.dll
        \__hfile = 0x00000144
                \____size -> 126848

                [LOADED DLL INFO]
                        \__PE Dll base -> 0x74280000
                        \__PE Dll Entry point -> 0x742978C0


[LOADED DLL] C:\Windows\SysWOW64\ucrtbased.dll
        \__hfile = 0x00000168
                \____size -> 1710568

                [LOADED DLL INFO]
                        \__PE Dll base -> 0x5DB50000
                        \__PE Dll Entry point -> 0x5DBDBA90


[EXCEPTION_BREAKPOINT] 0x77001B72



[EXCEPTION_BREAKPOINT] NtWriteFile at 0x76FC3060


                EIP before CONTEXT fix: 0x76FC3061
                EIP after CONTEXT fix: 0x76FC3060
                This is the byte after the breakpoint 0xCC
                This is the original byte 0xB8

                {NtWriteFile STACK FRAME}


[LOADED DLL] C:\Windows\SysWOW64\kernel.appcore.dll
        \__hfile = 0x00000144
                \____size -> 53760

                [LOADED DLL INFO]
                        \__PE Dll base -> 0x73A90000
                        \__PE Dll Entry point -> 0x73A947E0


[LOADED DLL] C:\Windows\SysWOW64\msvcrt.dll
        \__hfile = 0x00000144
                \____size -> 776448

                [LOADED DLL INFO]
                        \__PE Dll base -> 0x75260000
                        \__PE Dll Entry point -> 0x75295AC0


[LOADED DLL] C:\Windows\SysWOW64\rpcrt4.dll
        \__hfile = 0x00000144
                \____size -> 770240

                [LOADED DLL INFO]
                        \__PE Dll base -> 0x75320000
                        \__PE Dll Entry point -> 0x7535AC90


[EXIT_PROCESS_DEBUG_EVENT]
        \__Exit code [0]
bien :u
````
