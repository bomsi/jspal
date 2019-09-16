; Simple program to read a random number with RDRAND on macOS

; To build and run:
; ~/Downloads/nasm-2.14.02/nasm -f macho64 rand.asm
; ld -macosx_version_min 10.14.6 -static -e start -o rand rand.o
; ./rand

; Inspecting the code:
; objdump -x86-asm-syntax=intel -d rand

; To check for RDRAND support:
; sysctl -a|grep cpu.features

; For the syscall list, see:
; https://opensource.apple.com/source/xnu/xnu-2782.20.48/bsd/kern/syscalls.masters

default rel

global start

section .text
start:
; clear the location
    xor     rax, rax
    mov     qword [random], rax

; read the random number
    rdrand  rax
    jnc     .invalidvalue
    mov     qword [random], rax

; write the number to stdout
    mov     rax, 0x2000000 + 4  ; write
    mov     rdi, 1              ; file handle stdout
    lea     rsi, [random]       ; address of the value to print
    mov     rdx, 8              ; number of bytes to print
    syscall

; exit the application
    mov     rax, 0x2000000 + 1  ; exit
    mov     rdi, 0              ; exit code (success)
    syscall
    ; unreachable

.invalidvalue:
    mov     rax, 0x2000000 + 1  ; exit
    mov     rdi, 1              ; exit code (fail)
    syscall
    ; unreachable

section .bss
random: resb 8 ; 64 bits reserved for RDRAND result
