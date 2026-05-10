# APC Injector
A proof-of-concept shellcode injector implementing the Early Bird APC injection technique with several evasion improvements over a naive implementation.

Techniques
Early Bird APC Injection
Spawns a target process in a suspended state and queues an APC to its main thread before it executes a single instruction. When the thread is resumed, the Windows loader drains the APC queue, executing the shellcode prior to the process entry point.

PPID Spoofing
The spawned process is created with a spoofed parent process ID using PROC_THREAD_ATTRIBUTE_PARENT_PROCESS. The target process appears as a child of explorer.exe in the process tree, defeating process tree correlation used by EDRs and forensic tools.

XOR-Encrypted Shellcode
The shellcode payload is stored XOR-encrypted in the binary. Decryption happens at runtime in memory, preventing static signature detection on the binary itself.

RW → RX Memory Protection
Memory is allocated with PAGE_READWRITE, written, then transitioned to PAGE_EXECUTE_READ via NtProtectVirtualMemory. The region is never marked PAGE_EXECUTE_READWRITE, avoiding one of the most common behavioral IOCs monitored by security products.

NTAPI via Runtime Resolution
All sensitive operations bypass the high-level Win32 API layer and call NTAPI functions directly:

NtAllocateVirtualMemory
NtWriteVirtualMemory
NtProtectVirtualMemory
NtQueueApcThread
Functions are resolved at runtime via GetProcAddress, keeping the IAT clean.

Stack Strings
All sensitive strings (process paths, API names, DLL names) are constructed on the stack at runtime rather than stored as literals, preventing static string analysis.

Requirements
Windows (x86)
Visual Studio
Disclaimer
This project is intended for educational purposes and authorized security research only. Do not use against systems you do not own or have explicit permission to test.
