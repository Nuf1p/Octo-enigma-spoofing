/*
 * COFF Loader Project
 * -------------------
 * This is a re-implementation of a COFF loader, with a BOF compatibility layer
 * it's meant to provide functional example of loading a COFF file in memory
 * and maybe be useful.
 */

#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#if defined(_WIN32)
#include <windows.h> 

#include "beacon_compatibility.h"
#endif

#include "COFFLoader.h"

 /* Enable or disable debug output if testing or adding new relocation types */
#ifdef DEBUG
#define DEBUG_PRINT(x, ...) printf(x, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(x, ...)
#endif

/* Defining symbols for the OS version, will try to define anything that is
 * different between the arch versions by specifying them here. */
#if defined(__x86_64__) || defined(_WIN64)
#define PREPENDSYMBOLVALUE "__imp_"
#else
#define PREPENDSYMBOLVALUE "__imp__"
#endif

#define COFFLOADER_RETURN_VAL_IF(expr, val, fmt, ...) if ((expr)) { DEBUG_PRINT(fmt, ##__VA_ARGS__); return val; }

#if defined(_WIN32)
typedef struct {
    void (*foo)(char*, unsigned long);
    char         *args;
    unsigned long alen;
} BofCtx;

extern void NTAPI BofTrampoline(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
#endif


unsigned char* unhexlify(unsigned char* value, int *outlen) {
    unsigned char* retval = NULL;
    char byteval[3] = { 0 };
    unsigned int counter = 0;
    int counter2 = 0;
    char character = 0;
    if (value == NULL) {
        return NULL;
    }
    DEBUG_PRINT("Unhexlify Strlen: %lu\n", (long unsigned int)strlen((char*)value));
    if (strlen((char*)value) % 2 != 0) {
        DEBUG_PRINT("Either value is NULL, or the hexlified string isn't valid\n");
        goto errcase;
    }

    retval = calloc(strlen((char*)value) + 1, 1);
    if (retval == NULL) {
        goto errcase;
    }

    counter2 = 0;
    for (counter = 0; counter < strlen((char*)value); counter += 2) {
        memcpy(byteval, value + counter, 2);
        character = (char)strtol(byteval, NULL, 16);
        memcpy(retval + counter2, &character, 1);
        counter2++;
    }
    *outlen = counter2;

errcase:
    return retval;
}


/* Helper to just get the contents of a file, used for testing. Real
 * implementations of this in an agent would use the tasking from the
 * C2 server for this */
unsigned char* getContents(char* filepath, uint32_t* outsize) {
    FILE *fin = NULL;
    uint32_t fsize = 0;
    size_t readsize = 0;
    unsigned char* buffer = NULL;
    unsigned char* tempbuffer = NULL;

    fin = fopen(filepath, "rb");
    if (fin == NULL) {
        return NULL;
    }
    fseek(fin, 0, SEEK_END);
    fsize = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    tempbuffer = calloc(fsize, 1);
    if (tempbuffer == NULL) {
        fclose(fin);
        return NULL;
    }

    memset(tempbuffer, 0, fsize);
    readsize = fread(tempbuffer, 1, fsize, fin);

    fclose(fin);
    buffer = calloc(readsize, 1);
    if (buffer == NULL) {
        free(tempbuffer);
        return NULL;
    }
    
    memset(buffer, 0, readsize);
    memcpy(buffer, tempbuffer, readsize - 1);
    free(tempbuffer);
    *outsize = fsize;
    return buffer;
}

static BOOL starts_with(const char* string, const char* substring) {
    return strncmp(string, substring, strlen(substring)) == 0;
}

/* Helper function to process a symbol string, determine what function and
 * library its from, and return the right function pointer. Will need to
 * implement in the loading of the beacon internal functions, or any other
 * internal functions you want to have available. */
void* process_symbol(char* symbolstring) {
    void* functionaddress = NULL;
    char localcopy[1024] = { 0 };
    char* locallib = NULL;
    char* localfunc = NULL;
#if defined(_WIN32)    
    int tempcounter = 0;
    HMODULE llHandle = NULL;
#endif

    strncpy(localcopy, symbolstring, sizeof(localcopy) - 1);
    if (starts_with(symbolstring, PREPENDSYMBOLVALUE"Beacon") || starts_with(symbolstring, PREPENDSYMBOLVALUE"toWideChar") ||
        starts_with(symbolstring, PREPENDSYMBOLVALUE"GetProcAddress") || starts_with(symbolstring, PREPENDSYMBOLVALUE"LoadLibraryA") ||
        starts_with(symbolstring, PREPENDSYMBOLVALUE"GetModuleHandleA") || starts_with(symbolstring, PREPENDSYMBOLVALUE"FreeLibrary") ||
        starts_with(symbolstring, "__C_specific_handler")) {
        if(strcmp(symbolstring, "__C_specific_handler") == 0)
        {
            localfunc = symbolstring;
            return InternalFunctions[29][1];
        }
        else
        {
            localfunc = symbolstring + strlen(PREPENDSYMBOLVALUE);
        }
        DEBUG_PRINT("\t\tInternalFunction: %s\n", localfunc);
        /* TODO: Get internal symbol here and set to functionaddress, then
         * return the pointer to the internal function*/
#if defined(_WIN32)
        for (tempcounter = 0; tempcounter < 30; tempcounter++) {
            if (InternalFunctions[tempcounter][0] != NULL) {
                if (starts_with(localfunc, (char*)(InternalFunctions[tempcounter][0]))) {
                    functionaddress = (void*)InternalFunctions[tempcounter][1];
                    return functionaddress;
                }
            }
        }
#endif
    }
    else if (strncmp(symbolstring, PREPENDSYMBOLVALUE, strlen(PREPENDSYMBOLVALUE)) == 0) {
        DEBUG_PRINT("\t\tYep its an external symbol\n");
        locallib = localcopy + strlen(PREPENDSYMBOLVALUE);

        locallib = strtok(locallib, "$");
        localfunc = strtok(NULL, "$");
        DEBUG_PRINT("\t\tLibrary: %s\n", locallib);
        localfunc = strtok(localfunc, "@");
        DEBUG_PRINT("\t\tFunction: %s\n", localfunc);
        /* Resolve the symbols here, and set the functionpointervalue */
#if defined(_WIN32)
        llHandle = LoadLibraryA(locallib);
        DEBUG_PRINT("\t\tHandle: 0x%lx\n", llHandle);
        functionaddress = GetProcAddress(llHandle, localfunc);
        DEBUG_PRINT("\t\tProcAddress: 0x%p\n", functionaddress);
#endif
    }
    return functionaddress;
}

static bool coff_symbol_is_defined(struct coff_sym *symbol) {
    return symbol->SectionNumber > 0;
}

static bool coff_symbol_is_external(struct coff_sym *symbol) {
    return symbol->StorageClass == IMAGE_SYM_CLASS_EXTERNAL
        || symbol->StorageClass == IMAGE_SYM_CLASS_EXTERNAL_DEF;
}

/*
*   Calculate required size for the BoF
*   Abort if requiredSize > textSize

*   requiredSize = sum_of_sections + nSymbols*sizeof(void*)
*/
size_t compute_required_size(coff_file_header_t *hdr, char *coff_data)
  {
      size_t total = 0;
      int relocs = 0;

      coff_sect_t *s = (coff_sect_t *)(coff_data + sizeof(*hdr) + hdr->SizeOfOptionalHeader);

      for (int i = 0; i < hdr->NumberOfSections; i++, s++) {

          total = (total + 15) & ~((size_t)15);
          total += s->SizeOfRawData;
          relocs += s->NumberOfRelocations;
      }

      total = (total + 15) & ~((size_t)15);
      total += (size_t)relocs * sizeof(void *);

      return total;
  }

/* Just a generic runner for testing, this is pretty much just a reference
 * implementation, return values will need to be checked, more relocation
 * types need to be handled, and needs to have different arguments for use
 * in any agent. */
int RunCOFF(
    char*           functionname, 
    unsigned char*  coff_data, 
    uint32_t        filesize, 
    unsigned char*  argumentdata, 
    int             argumentSize
) 
{
    coff_sect_t *coff_sect_ptr = NULL;
    coff_reloc_t *coff_reloc_ptr = NULL;
    int retcode = 0;
    int counter = 0;
    int reloccount = 0;
    unsigned int tempcounter = 0;
    char *symbol_name = NULL;

    COFFLOADER_RETURN_VAL_IF(functionname == NULL, 1, "Function name is NULL\n");
    COFFLOADER_RETURN_VAL_IF(coff_data == NULL, 1, "Can't execute NULL\n");
    COFFLOADER_RETURN_VAL_IF(filesize == 0, 1, "COFF file size is 0\n");
    COFFLOADER_RETURN_VAL_IF(filesize < sizeof(struct coff_file_header), 1,
            "COFF file size too small for a COFF file header\n");

    struct coff_file_header *coff_header_ptr = (struct coff_file_header*)coff_data;

    COFFLOADER_RETURN_VAL_IF(coff_header_ptr->PointerToSymbolTable < sizeof(struct coff_file_header),
            1, "COFF symbol table offset is inside the file header\n");
    COFFLOADER_RETURN_VAL_IF(filesize < coff_header_ptr->PointerToSymbolTable, 1,
            "COFF symbol table offset exceeds file size\n");

    // Byte index of the strtab/end of symtab
    size_t coff_strtab_index =
        coff_header_ptr->PointerToSymbolTable + coff_header_ptr->NumberOfSymbols * sizeof(struct coff_sym);

    COFFLOADER_RETURN_VAL_IF(filesize < coff_strtab_index, 1, "COFF symbol table exceeds COFF file size\n");
    COFFLOADER_RETURN_VAL_IF(filesize < coff_strtab_index + sizeof(uint32_t), 1,
            "COFF string table offset exceeds COFF file size\n");

    uint32_t coff_strtab_size = *(uint32_t*)(coff_data + coff_strtab_index);

    COFFLOADER_RETURN_VAL_IF(filesize < coff_strtab_index + coff_strtab_size, 1,
            "COFF string table exceeds COFF file size\n");
    COFFLOADER_RETURN_VAL_IF(filesize != coff_strtab_index + coff_strtab_size, 1,
            "COFF file contains extraneous data\n");

    struct coff_sym *coff_sym_ptr = (struct coff_sym*)(coff_data + coff_header_ptr->PointerToSymbolTable);

#ifdef _WIN32
    void* funcptrlocation = NULL;
    size_t offsetvalue = 0;
#endif
    char* entryfuncname = functionname;
#if defined(__x86_64__) || defined(_WIN64)
#ifdef _WIN32
    uint64_t longoffsetvalue = 0;
#endif
#else
    /* Set the input function name to match the 32 bit version */
    entryfuncname = calloc(strlen(functionname) + 2, 1);
    if (entryfuncname == NULL) {
        return 1;
    }
    (void)sprintf(entryfuncname, "_%s", functionname);
#endif

    /*
        populate InternalFunctions[29][1] with
        kernel32!__C_specific_handler
    */
    HMODULE kern = GetModuleHandleA("kernel32.dll");
    InternalFunctions[29][1] = (unsigned char *) GetProcAddress(kern, "__C_specific_handler");

    printf("[*] found address of kernel32!__C_specific_handler: %x\n", InternalFunctions[29][1]);

#ifdef _WIN32


    char** sectionMapping = NULL;
    int *sectionSize = NULL;

    void(*foo)(char* in, unsigned long datalen);
    void **functionMapping = NULL;
    int functionMappingCount = 0;
    int relocationCount = 0;

#endif

    char symbol_shortname_buffer[9] = {0};

    /* Actually allocate an array to keep track of the sections */
    sectionMapping = (char**)calloc(sizeof(char*)*(coff_header_ptr->NumberOfSections+1), 1);
    sectionSize = (int*)calloc(sizeof(int)*(coff_header_ptr->NumberOfSections+1), 1);

    if (sectionMapping == NULL){
        printf("Failed to allocate sectionMapping\n");
        goto cleanup;
    }

    // Dll Will be stomped
    HMODULE hMod = LoadLibraryA("windows.storage.dll");
    printf("[*] Dll loaded @(%p)\n", hMod);

    BYTE *text      = NULL;
    DWORD textSize  = 0 ;

    // retrieve .text section of the dll 
    getDLLtxt(hMod, &text, &textSize);

    printf("[*] Dll .text @(%p)\n"
            "\tsection size: %ld\n",
            text, textSize);

    size_t required = compute_required_size(coff_header_ptr, coff_data);

    if (required > textSize) {
      fprintf(stderr, "[-] BOF needs %zu bytes, host .text only %lu\n",
              required, (unsigned long)textSize);
      return 1;
    }

    printf("[*] Required size: %zu\n", required);

    // Changing from RX - RWX 
    DWORD oldProt = 0;
    if (!VirtualProtect(text, required, PAGE_EXECUTE_READWRITE, &oldProt )) {
            printf("[-] Failed to change mem protection\n");
            return 1;
    }
    
    printf("[*] Memory protection changed\n");

/*
    for each section, memcpy it to the stomped RWX DLL memory region
*/
  size_t running = 0;
  int pdataIdx = -1;

  printf("[*] Copying BoF sections...\n");

  for (counter = 0; counter < coff_header_ptr->NumberOfSections; counter++) 
  {
    coff_sect_ptr = (coff_sect_t*)(coff_data
                      + sizeof(coff_file_header_t)
                      + coff_header_ptr->SizeOfOptionalHeader
                      + (counter * sizeof(coff_sect_t)));

    printf("\tCopying section: %s\n", coff_sect_ptr->Name);
    printf("\tSizeOfRawData: 0x%X\n", coff_sect_ptr->SizeOfRawData);
    printf("\tNumberOfRelocations: %d\n", coff_sect_ptr->NumberOfRelocations);
    relocationCount += coff_sect_ptr->NumberOfRelocations;

    // later for RtlAddFuncTable
    if (strncmp((char*)coff_sect_ptr->Name, ".pdata", 6) == 0) 
        pdataIdx = counter;
    
    // 16 bytes alignment
    running = (running + 15) & ~((size_t)15);

    sectionMapping[counter] = (char*)text + running;
    sectionSize[counter]    = coff_sect_ptr->SizeOfRawData;

    // getchar();
    if (coff_sect_ptr->PointerToRawData != 0) {
        memcpy(sectionMapping[counter],
                coff_data + coff_sect_ptr->PointerToRawData,
                coff_sect_ptr->SizeOfRawData);
    } else {
        // .bss is uninitialized — zero it.
        memset(sectionMapping[counter], 0,
                coff_sect_ptr->SizeOfRawData);
    }

    printf("\tSection %d mapped @ %p (size 0x%X)\n",
                counter, sectionMapping[counter],
                coff_sect_ptr->SizeOfRawData);

    // each section must be positioned at known distance between them
    // The distance is calculated with (16-byte alignment + SizeOfRawData)
    running += coff_sect_ptr->SizeOfRawData;
    printf("\n");
  }

    // Final align in order to place the GOT right after the last section
    running = (running + 15) & ~((size_t)15);

    // point GOT table at the end of the last sect
    // setting up the GOT, with module stomping i dont need to allocate any memory 
    //
    functionMapping = (void**)((char*)text + running); 
    printf("[*] Total Relocations: %d\n", relocationCount);

    /* Start parsing the relocations, and *hopefully* handle them correctly. */
    for (counter = 0; counter < coff_header_ptr->NumberOfSections; counter++) 
    {
        coff_sect_ptr = (coff_sect_t*)(coff_data + sizeof(coff_file_header_t) + (sizeof(coff_sect_t) * counter));
        coff_reloc_ptr = (coff_reloc_t*)(coff_data + coff_sect_ptr->PointerToRelocations);
        
        printf("[*] Doing Relocations of section: %d\n", counter);

        for (reloccount = 0; reloccount < coff_sect_ptr->NumberOfRelocations; reloccount++) 
        {
            printf("\t--- COFF reloc %d ---\n", reloccount);
            printf("\t - VirtualAddress: 0x%X\n", coff_reloc_ptr->VirtualAddress);
            printf("\t - SymbolTableIndex: 0x%X\n", coff_reloc_ptr->SymbolTableIndex);
            printf("\t - Type: 0x%X\n", coff_reloc_ptr->Type);

            /* Check if the symbol name is a long symbol name */
            //
            //  Resolve symbols name, check if is a short or long one
            //
            if (coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.value[0] == 0) {
                /* Long symbol name from the string table */

                symbol_name = ((char*)(coff_sym_ptr + coff_header_ptr->NumberOfSymbols))
                    + coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.value[1];

            } else {
                /* Short symbol name */

                /* If the short symbol name is 8 bytes in length, it is not NULL
                 * terminated. Copy it to a temporary buffer to add the NULL terminator. */
                if (coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.Name[7] != '\0') {
                    strncpy_s(
                        symbol_shortname_buffer,
                        sizeof(symbol_shortname_buffer),
                        &coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.Name[0],
                        sizeof(coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.Name)
                    );

                    symbol_name = symbol_shortname_buffer;
                } else {
                    symbol_name = &coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].first.Name[0];
                }
            }

            DEBUG_PRINT("\tSymNamePtr: %p\n", symbol_name);
            printf("\t SymName: %s\n", symbol_name);
            DEBUG_PRINT("\tSectionNumber: 0x%X\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber);

            /* 
                Check if the target symbol is a local symbol or an external undefined symbol
                and resolve it 
             */
            if (coff_symbol_is_defined(&coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex])) {
                
                /* Locally defined symbol. Find the mapped address. */
                funcptrlocation = sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1];

                funcptrlocation = (void *)((char *)funcptrlocation + coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value);
            } else if (coff_symbol_is_external(&coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex])
                    && coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value == 0) {
                
                /* Imported symbol. Resolve it and map it in */
                funcptrlocation = process_symbol(symbol_name);
                if (funcptrlocation == NULL) {
                    DEBUG_PRINT("Failed resolving imported symbol '%s'\n", symbol_name);
                    retcode = 1;
                    goto cleanup;
                }

                /* Map the imported symbol address to the local import table */
                //
                //
                //getchar();
                functionMapping[functionMappingCount] = funcptrlocation;

                /* Get the address of the imported symbol mapped in the local import 
                 * table for the relocation target */
                funcptrlocation = &functionMapping[functionMappingCount];

                /* Increment the number of mapped imported functions */
                functionMappingCount += 1;

            } else {

                /* Relocation to an undefined symbol */
                DEBUG_PRINT("Relocation %d in section index %d references undefined symbol %s\n", reloccount, counter, symbol_name);
                retcode = 1;
                goto cleanup;
            }

#ifdef _WIN32
#ifdef _WIN64
            /* Type == 1 relocation is the 64-bit VA of the relocation target */
            if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_ADDR64) {
                memcpy(&longoffsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(uint64_t));
                DEBUG_PRINT("\tReadin longOffsetValue : 0x%llX\n", longoffsetvalue);
                longoffsetvalue += (uint64_t)funcptrlocation;
                DEBUG_PRINT("\tModified longOffsetValue : 0x%llX Base Address: %p\n", longoffsetvalue, funcptrlocation);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &longoffsetvalue, sizeof(uint64_t));
            }

            /* This is Type == 3 relocation code */
            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_ADDR32NB) {
                int32_t addend = 0;
                memcpy(&addend, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\tReadin addend : 0x%0X\n", addend);

                uintptr_t target_va = (uintptr_t)(sectionMapping[coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber - 1])
                                    + coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value
                                    + (int64_t)addend;

                int64_t rva = (int64_t)target_va - (int64_t)(uintptr_t)hMod;
                DEBUG_PRINT("\t\ttarget_va: 0x%llX  base: %p  rva: 0x%llX\n",
                            (unsigned long long)target_va, (void*)hMod, (long long)rva);

                if (rva < 0 || rva > 0xFFFFFFFFLL) {
                    DEBUG_PRINT("ADDR32NB target out of 4 GB range from image base, exiting\n");
                    retcode = 1;
                    goto cleanup;
                }

                offsetvalue = (int32_t)rva;
                DEBUG_PRINT("\tSetting 0x%p to RVA: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }
            /* This is Type == 4 relocation code, this is either a relocation to a global
             * or imported symbol */
            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32) {
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);

                if (llabs((long long)funcptrlocation - (long long)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4)) > UINT_MAX) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    goto cleanup;
                }

                offsetvalue += ((size_t)funcptrlocation - ((size_t)sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4));
                DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }
            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_1) {
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);

                if (llabs((long long)funcptrlocation - (long long)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 1)) > UINT_MAX) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    retcode = 1;
                    goto cleanup;
                }

                offsetvalue += (size_t)funcptrlocation - ((size_t)sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 1);
                DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }

            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_2) {
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);

                if (llabs((long long)funcptrlocation - (long long)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 2)) > UINT_MAX) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    retcode = 1;
                    goto cleanup;
                }

                offsetvalue += (size_t)funcptrlocation - ((size_t)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 2));
                DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }

            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_3) {
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);

                if (llabs((long long)funcptrlocation - (long long)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 3)) > UINT_MAX) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    retcode = 1;
                    goto cleanup;
                }

                offsetvalue += (size_t)funcptrlocation - ((size_t)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 3));
                DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }

            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_4) {
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);

                if (llabs((long long)funcptrlocation - (long long)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 4)) > UINT_MAX) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    retcode = 1;
                    goto cleanup;
                }

                offsetvalue += (size_t)funcptrlocation - ((size_t)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 4));
                DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }
            else if (coff_reloc_ptr->Type == IMAGE_REL_AMD64_REL32_5) {
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\t\tReadin offset value: 0x%X\n", offsetvalue);

                if (llabs((long long)funcptrlocation - (long long)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 5)) > UINT_MAX) {
                    DEBUG_PRINT("Relocations > 4 gigs away, exiting\n");
                    retcode = 1;
                    goto cleanup;
                }

                offsetvalue += (size_t)funcptrlocation - ((size_t)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4 + 5));
                DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }

            else {
                DEBUG_PRINT("No code for relocation type: %d\n", coff_reloc_ptr->Type);
            }
#else
            /* This is Type == IMAGE_REL_I386_DIR32 relocation code */
            if (coff_reloc_ptr->Type == IMAGE_REL_I386_DIR32){
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\tReadin OffsetValue : 0x%0X\n", offsetvalue);
                offsetvalue = (uint32_t)funcptrlocation + offsetvalue;
                DEBUG_PRINT("\tSetting 0x%p to: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }
            else if (coff_reloc_ptr->Type == IMAGE_REL_I386_REL32){
                offsetvalue = 0;
                memcpy(&offsetvalue, sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, sizeof(int32_t));
                DEBUG_PRINT("\tReadin OffsetValue : 0x%0X\n", offsetvalue);
                offsetvalue += (uint32_t)funcptrlocation - (uint32_t)(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress + 4);
                DEBUG_PRINT("\tSetting 0x%p to relative address: 0x%X\n", sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, offsetvalue);
                memcpy(sectionMapping[counter] + coff_reloc_ptr->VirtualAddress, &offsetvalue, sizeof(uint32_t));
            }
#endif //WIN64 statement close
#endif //WIN32 statement close

            DEBUG_PRINT("\tValueNumber: 0x%X\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].Value);
            DEBUG_PRINT("\tSectionNumber: 0x%X\n", coff_sym_ptr[coff_reloc_ptr->SymbolTableIndex].SectionNumber);
            coff_reloc_ptr += 1;
            DEBUG_PRINT("\n");
        }
        DEBUG_PRINT("\n");
    }

    /* Some debugging code to see what the sections look like in memory */
#if DEBUG
#ifdef _WIN32
    for (tempcounter = 0; tempcounter < coff_header_ptr->NumberOfSections; tempcounter++) {
        DEBUG_PRINT("Section: %u\n", tempcounter);
        if (sectionMapping[tempcounter] != NULL) {
            DEBUG_PRINT("\t");
            for (counter = 0; counter < sectionSize[tempcounter]; counter++) {
                DEBUG_PRINT("%02X ", (uint8_t)(sectionMapping[tempcounter][counter]));
            }
            DEBUG_PRINT("\n");
        }
    }
#endif
#endif


/*
*   Need to consider what the .pdata look like in a COFF file

*  struct RUNTIME_FUNCTION {
      DWORD BeginAddress;       
      DWORD EndAddress;          
      DWORD UnwindInfoAddress;   
  };

*  Everything is 0ed:   objdump -r -j .pdata msgbox64.o
     RELOCATION RECORDS FOR [.pdata]:
        OFFSET           TYPE              VALUE
        0000000000000000 IMAGE_REL_AMD64_ADDR32NB  .text
        0000000000000004 IMAGE_REL_AMD64_ADDR32NB  .text
        0000000000000008 IMAGE_REL_AMD64_ADDR32NB  .xdata

*/
#ifdef _WIN64
if (pdataIdx >= 0) {

    printf("[*] Calling RtlAddFunctionTable...\n");
    
    RtlAddFunctionTable(
        (PRUNTIME_FUNCTION)sectionMapping[pdataIdx],
        sectionSize[pdataIdx] / sizeof(RUNTIME_FUNCTION),
        (DWORD64)hMod
    );

/*
...
7, user32.dll!MessageBoxA+0x45
8, windows.storage.dll!...>+0x3f
9, COFFLoader64.exe+0x3b6a
10, COFFLoader64.exe+0x3c9c
11, COFFLoader64.exe+0x1307
12, COFFLoader64.exe+0x142a
13, kernel32.dll!BaseThreadInitThunk+0x17
14, ntdll.dll!RtlUserThreadStart+0x2c
*/
}
#endif
    DEBUG_PRINT("Symbols:\n");
    for (tempcounter = 0; tempcounter < coff_header_ptr->NumberOfSymbols; tempcounter++) {
        DEBUG_PRINT("\t%s: Section: %d, Value: 0x%X\n", coff_sym_ptr[tempcounter].first.Name, coff_sym_ptr[tempcounter].SectionNumber, coff_sym_ptr[tempcounter].Value);
        if (strcmp(coff_sym_ptr[tempcounter].first.Name, entryfuncname) == 0) {
            DEBUG_PRINT("\t\tFound entry!\n");
#ifdef _WIN32
#ifdef _MSC_VER
            foo = (void(__cdecl*)(char*, unsigned long))(sectionMapping[coff_sym_ptr[tempcounter].SectionNumber - 1] + coff_sym_ptr[tempcounter].Value);
#else
            foo = (void(*)(char *, unsigned long))(sectionMapping[coff_sym_ptr[tempcounter].SectionNumber - 1] + coff_sym_ptr[tempcounter].Value);
#endif
            printf("[*] BOF entry @ %p - dispatching via thread pool\n", foo);

            BofCtx ctx = { foo, (char*)argumentdata, (unsigned long)argumentSize };
            PTP_WORK work = CreateThreadpoolWork(BofTrampoline, &ctx, NULL);
            if (work == NULL) {
                printf("[-] CreateThreadpoolWork failed: %lu\n", GetLastError());
                retcode = 1;
                goto cleanup;
            }
            SubmitThreadpoolWork(work);
            WaitForThreadpoolWorkCallbacks(work, FALSE);
            CloseThreadpoolWork(work);
#endif
        }
    }
    DEBUG_PRINT("Back\n");

    /* Cleanup the allocated memory */
    cleanup :
            
        /* 
            With module stomping here the cleanup work like this: 
             - Restore the host .text section
             - VirtualProtect back to RX
        */ 
            printf("[/] Cleanup RunCOFF...\n");
            return retcode;
}

#ifdef COFF_STANDALONE

int main(int argc, char* argv[]) {

    char* coff_data = NULL;
    unsigned char* arguments = NULL;
    int argumentSize = 0;

#ifdef _WIN32

    char* outdata = NULL;
    int outdataSize = 0;

#endif
    uint32_t filesize = 0;
    int checkcode = 0;
    if (argc < 3) 
    {
        printf("ERROR: %s go /path/to/object/file.o (arguments)\n", argv[0]);
        return 1;
    }

    coff_data = (char*)getContents(argv[2], &filesize);
    if (coff_data == NULL) {
        return 1;
    }

    printf("[+] Got contents of COFF file\n");
    arguments = unhexlify((unsigned char*)argv[3], &argumentSize);

    printf("[+] Running/Parsing the COFF file\n");
    
    //
    //  Perform a tal-jmp call to RunCOFF 
    checkcode = RunCOFF(argv[1], (unsigned char*)coff_data, filesize, arguments, argumentSize);

    if (checkcode == 0) 
    {
#ifdef _WIN32
        printf("Ran/parsed the coff\n");
        outdata = BeaconGetOutputData(&outdataSize);
        if (outdata != NULL) {

            printf("Outdata Below:\n\n%s\n", outdata);
        }
#endif
    }
    else {
        printf("Failed to run/parse the COFF file\n");
    }
    if (coff_data) {
        free(coff_data);
    }
    return 0;
}

#endif
