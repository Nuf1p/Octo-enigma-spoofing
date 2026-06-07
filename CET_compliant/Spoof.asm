BITS 64
default rel

section .text
global BofTrampoline

;
; Callback perform a tail-jmp call to BoF entry
; 
BofTrampoline:
    mov rax, [rdx]          	; rax = foo()
    mov rcx, [rdx + 8]		; args
    mov edx, [rdx + 16]
    jmp rax			; Tail-jmp
