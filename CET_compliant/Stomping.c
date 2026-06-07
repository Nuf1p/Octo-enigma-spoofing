#include "COFFLoader.h"
#include <windows.h>

void getDLLtxt (
    HMODULE hMod, 
    BYTE** text, 
    DWORD* textSz
)
{
    BYTE* base = (BYTE*)hMod;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

    PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nt);

    *text = NULL;
    *textSz = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sect++) {
        if (memcmp(sect->Name, ".text", 5) == 0) {
            *text = base + sect->VirtualAddress;
            *textSz = sect->Misc.VirtualSize;
    
            return;
        }
    }
}