
struct DATA {

    LPVOID data;
    size_t len;

};

DATA GetRemotePE(LPCWSTR domain, LPCWSTR path);