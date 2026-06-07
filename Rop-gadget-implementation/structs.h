#pragma once
#include <Windows.h>

typedef enum _THREADINFOCLASS
{
    ThreadBasicInformation,                         // q: THREAD_BASIC_INFORMATION
    ThreadTimes,                                    // q: KERNEL_USER_TIMES
    ThreadPriority,                                 // s: KPRIORITY (requires SeIncreaseBasePriorityPrivilege)
    ThreadBasePriority,                             // s: KPRIORITY
    ThreadAffinityMask,                             // s: KAFFINITY
    ThreadImpersonationToken,                       // s: HANDLE
    ThreadDescriptorTableEntry,                     // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
    ThreadEnableAlignmentFaultFixup,                // s: BOOLEAN
    ThreadEventPair,                                // q: Obsolete
    ThreadQuerySetWin32StartAddress,                // q: PVOID
    ThreadZeroTlsCell,                              // s: ULONG // TlsIndex // 10
    ThreadPerformanceCount,                         // q: LARGE_INTEGER
    ThreadAmILastThread,                            // q: ULONG
    ThreadIdealProcessor,                           // s: ULONG
    ThreadPriorityBoost,                            // qs: ULONG
    ThreadSetTlsArrayAddress,                       // s: ULONG_PTR
    ThreadIsIoPending,                              // q: ULONG
    ThreadHideFromDebugger,                         // q: BOOLEAN; s: void
    ThreadBreakOnTermination,                       // qs: ULONG
    ThreadSwitchLegacyState,                        // s: void // NtCurrentThread // NPX/FPU
    ThreadIsTerminated,                             // q: ULONG // 20
    ThreadLastSystemCall,                           // q: THREAD_LAST_SYSCALL_INFORMATION
    ThreadIoPriority,                               // qs: IO_PRIORITY_HINT (requires SeIncreaseBasePriorityPrivilege)
    ThreadCycleTime,                                // q: THREAD_CYCLE_TIME_INFORMATION (requires THREAD_QUERY_LIMITED_INFORMATION)
    ThreadPagePriority,                             // qs: PAGE_PRIORITY_INFORMATION
    ThreadActualBasePriority,                       // s: LONG (requires SeIncreaseBasePriorityPrivilege)
    ThreadTebInformation,                           // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
    ThreadCSwitchMon,                               // q: Obsolete
    ThreadCSwitchPmu,                               // q: Obsolete
    ThreadWow64Context,                             // qs: WOW64_CONTEXT, ARM_NT_CONTEXT since 20H1
    ThreadGroupInformation,                         // qs: GROUP_AFFINITY // 30
    ThreadUmsInformation,                           // q: THREAD_UMS_INFORMATION // Obsolete
    ThreadCounterProfiling,                         // q: BOOLEAN; s: THREAD_PROFILING_INFORMATION?
    ThreadIdealProcessorEx,                         // qs: PROCESSOR_NUMBER; s: previous PROCESSOR_NUMBER on return
    ThreadCpuAccountingInformation,                 // q: BOOLEAN; s: HANDLE (NtOpenSession) // NtCurrentThread // since WIN8
    ThreadSuspendCount,                             // q: ULONG // since WINBLUE
    ThreadHeterogeneousCpuPolicy,                   // q: KHETERO_CPU_POLICY // since THRESHOLD
    ThreadContainerId,                              // q: GUID
    ThreadNameInformation,                          // qs: THREAD_NAME_INFORMATION (requires THREAD_SET_LIMITED_INFORMATION)
    ThreadSelectedCpuSets,                          // q: ULONG[]
    ThreadSystemThreadInformation,                  // q: SYSTEM_THREAD_INFORMATION // 40
    ThreadActualGroupAffinity,                      // q: GROUP_AFFINITY // since THRESHOLD2
    ThreadDynamicCodePolicyInfo,                    // q: ULONG; s: ULONG (NtCurrentThread)
    ThreadExplicitCaseSensitivity,                  // qs: ULONG; s: 0 disables, otherwise enables // (requires SeDebugPrivilege and PsProtectedSignerAntimalware)
    ThreadWorkOnBehalfTicket,                       // q: ALPC_WORK_ON_BEHALF_TICKET // RTL_WORK_ON_BEHALF_TICKET_EX // NtCurrentThread
    ThreadSubsystemInformation,                     // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ThreadDbgkWerReportActive,                      // s: ULONG; s: 0 disables, otherwise enables
    ThreadAttachContainer,                          // s: HANDLE (job object) // NtCurrentThread
    ThreadManageWritesToExecutableMemory,           // s: MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ThreadPowerThrottlingState,                     // qs: POWER_THROTTLING_THREAD_STATE // since REDSTONE3 (set), WIN11 22H2 (query)
    ThreadWorkloadClass,                            // q: THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
    ThreadCreateStateChange,                        // s: Obsolete // since WIN11
    ThreadApplyStateChange,                         // s: Obsolete
    ThreadStrongerBadHandleChecks,                  // s: ULONG // NtCurrentThread // since 22H1
    ThreadEffectiveIoPriority,                      // q: IO_PRIORITY_HINT
    ThreadEffectivePagePriority,                    // q: ULONG
    ThreadUpdateLockOwnership,                      // s: THREAD_LOCK_OWNERSHIP // since 24H2
    ThreadSchedulerSharedDataSlot,                  // q: SCHEDULER_SHARED_DATA_SLOT_INFORMATION
    ThreadTebInformationAtomic,                     // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_QUERY_INFORMATION)
    ThreadIndexInformation,                         // q: THREAD_INDEX_INFORMATION
    MaxThreadInfoClass
} THREADINFOCLASS;

typedef NTSTATUS(NTAPI* fnNtQueryInformationThread)(
    HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG
    );

/* --------------------------------------------------------------------------- */


typedef struct
{
    PVOID       Fixup;             // 0
    PVOID       OG_retaddr;
    PVOID       rbx;
    PVOID       rdi;
    PVOID       BTIT_ss;
    PVOID       BTIT_retaddr;
    PVOID       Gadget_ss;
    PVOID       RUTS_ss;            // 56     
    PVOID       RUTS_retaddr;       // 64  
    PVOID       ssn;
    PVOID       trampoline;
    PVOID       rsi;
    PVOID       r12;
    PVOID       r13;
    PVOID       r14;
    PVOID       r15;
    PVOID       TSA_ss;             // 128
    PVOID       TSA_retaddr;        // 136
    PVOID       jop;                // 144 - JMP [RBX] gadget address
    PVOID       saved_rsp;          // 152
    PVOID       Gadget_FpOff16;     // 160 - FrameOffset * 16 of dispatch-gadget function
    PVOID       og_rbp;             // 168 - saved original rbp
} PRM, * PPRM;



typedef struct
{
    LPCWSTR dllPath;
    ULONG offset;
    ULONG totalStackSize;
    BOOL requiresLoadLibrary;
    BOOL setsFramePointer;
    PVOID returnAddress;
    BOOL pushRbp;
    ULONG countOfCodes;
    BOOL pushRbpIndex;
} StackFrame, * PStackFrame;

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
    /*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
    *   union {
    *       OPTIONAL ULONG ExceptionHandler;
    *       OPTIONAL ULONG FunctionEntry;
    *   };
    *   OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, * PUNWIND_INFO;
