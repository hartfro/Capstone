
typedef struct {
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
} Crypt, * PCrypt;

BOOL LoadDriver(LPWSTR szPath);
BOOL EnablePriv();
BOOL WriteToTempFile(Crypt* memData, LPCWSTR szFileName);
BOOL UnloadDriver();
BOOL DeleteRegistryValues();