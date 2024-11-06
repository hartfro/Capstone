#include "headers.h"



typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY;



BOOL MapPE(unsigned char* PEdata) {

    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)PEdata;
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((char*)(PEdata)+DOSheader->e_lfanew);
    if (!NTheader) {
        //printf(" [-] Not a PE file\n");
        return FALSE;
    }
    BYTE* MemImage = (BYTE*)VirtualAlloc(NULL, NTheader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!MemImage) {
        //printf(" [-] Failed in Allocating Image Memory (%u)\n", GetLastError());
        return FALSE;
    }
    // Map Headers&Sections
    memcpy(MemImage, PEdata, NTheader->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER sectionHdr = IMAGE_FIRST_SECTION(NTheader);
    for (WORD i = 0; i < NTheader->FileHeader.NumberOfSections; i++) {
        memcpy((BYTE*)(MemImage)+sectionHdr[i].VirtualAddress, (BYTE*)(PEdata)+sectionHdr[i].PointerToRawData, sectionHdr[i].SizeOfRawData);
    }
    // Apply Relocations
    IMAGE_DATA_DIRECTORY DirectoryReloc = NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (DirectoryReloc.VirtualAddress == 0) {
        //printf("Failed in Relocating Image\n");
        return FALSE;
    }
    PIMAGE_BASE_RELOCATION BaseReloc = (PIMAGE_BASE_RELOCATION)(DirectoryReloc.VirtualAddress + (ULONG_PTR)MemImage);
    while (BaseReloc->VirtualAddress != 0) {
        DWORD page = BaseReloc->VirtualAddress;
        if (BaseReloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            size_t count = (BaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            BASE_RELOCATION_ENTRY* list = (BASE_RELOCATION_ENTRY*)(LPWORD)(BaseReloc + 1);
            for (size_t i = 0; i < count; i++) {
                if (list[i].Type & 0xA) {
                    DWORD rva = list[i].Offset + page;
                    PULONG_PTR p = (PULONG_PTR)((LPBYTE)MemImage + rva);
                    // Relocate the address
                    *p = ((*p) - NTheader->OptionalHeader.ImageBase) + (ULONG_PTR)MemImage;
                }
            }
        }
        BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)BaseReloc + BaseReloc->SizeOfBlock);
    }
    // Loading Imports
    IMAGE_DATA_DIRECTORY DirectoryImports = NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!DirectoryImports.VirtualAddress) {
        return FALSE;
    }
    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(DirectoryImports.VirtualAddress + (ULONG_PTR)MemImage);
    while (ImportDescriptor->Name != NULL)
    {
        LPCSTR ModuleName = (LPCSTR)ImportDescriptor->Name + (ULONG_PTR)MemImage;
        HMODULE Module = LoadLibraryA(ModuleName);
        if (Module)
        {
            PIMAGE_THUNK_DATA thunk = NULL;
            thunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)MemImage + ImportDescriptor->FirstThunk);

            while (thunk->u1.AddressOfData != NULL)
            {
                ULONG_PTR FuncAddr = NULL;
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                {
                    LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                    FuncAddr = (ULONG_PTR)GetProcAddress(Module, functionOrdinal);
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME FuncName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)MemImage + thunk->u1.AddressOfData);
                    FuncAddr = (ULONG_PTR)GetProcAddress(Module, FuncName->Name);
                }
                thunk->u1.Function = FuncAddr;
                ++thunk;
            }
        }
        ImportDescriptor++;
    }
    ULONG_PTR EntryPoint = NTheader->OptionalHeader.AddressOfEntryPoint + (ULONG_PTR)MemImage;
    //printf("[+] Run PE:\n");

    //SleepEx(20000, FALSE);


    int (*Entry)() = (int(*)())EntryPoint;
    Entry();

}
