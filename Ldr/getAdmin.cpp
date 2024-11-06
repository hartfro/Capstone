#include "headers.h"



BOOL checkPriv() {
    LUID debugPrivilegeLuid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &debugPrivilegeLuid)) {
    }

    TOKEN_PRIVILEGES tokenPrivileges;
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = debugPrivilegeLuid;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    HANDLE processHandle = GetCurrentProcess();
    HANDLE processToken;

    if (!OpenProcessToken(processHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &processToken)) {

    }

    DWORD tokenInfoLength;
    GetTokenInformation(processToken, TokenPrivileges, NULL, 0, &tokenInfoLength);

    PTOKEN_PRIVILEGES processTokenPrivileges = (PTOKEN_PRIVILEGES)malloc(tokenInfoLength);
    if (!GetTokenInformation(processToken, TokenPrivileges, processTokenPrivileges, tokenInfoLength, &tokenInfoLength)) {

    }

    PLUID_AND_ATTRIBUTES privilegeEntry;
    BOOL isDebugPrivilegeAvailable = FALSE;

    for (DWORD i = 0; i < processTokenPrivileges->PrivilegeCount; i++) {
        privilegeEntry = &processTokenPrivileges->Privileges[i];

        if (privilegeEntry->Luid.LowPart == debugPrivilegeLuid.LowPart && privilegeEntry->Luid.HighPart == debugPrivilegeLuid.HighPart) {

            isDebugPrivilegeAvailable = TRUE;
            break;
        }
    }

    if (!isDebugPrivilegeAvailable) {

        free(processTokenPrivileges);
        return FALSE;
    }

    if (!AdjustTokenPrivileges(processToken, FALSE, &tokenPrivileges, 0, NULL, NULL)) {

    }

    free(processTokenPrivileges);
    CloseHandle(processToken);

    return TRUE;
}


#define MAX_EXEC_PATH_LENGTH 5000

void rerun(void) {
    SHELLEXECUTEINFO execInfo;
    WCHAR execPath[MAX_EXEC_PATH_LENGTH];
    DWORD execPathLength = MAX_EXEC_PATH_LENGTH;

    // Get the path of the current executable
    GetModuleFileName(NULL, execPath, execPathLength);

    // Set up the SHELLEXECUTEINFO structure
    execInfo.cbSize = sizeof(SHELLEXECUTEINFO);
    execInfo.fMask = SEE_MASK_DEFAULT;
    execInfo.hwnd = NULL;
    execInfo.lpVerb = _T("runas");
    execInfo.lpFile = execPath;
    execInfo.lpParameters = NULL;
    execInfo.lpDirectory = NULL;
    execInfo.nShow = SW_SHOWNORMAL;

    // Execute the file with elevated privileges
    ShellExecuteEx(&execInfo);  // You can also use ShellExecute
}