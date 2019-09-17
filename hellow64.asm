; Simple program which returns the kernel32.dll base address

; To build, open "x64 Native Tools Command Prompt for VS 2019" and run:
; "C:\Program Files\NASM\nasm.exe" -f win64 hellow64.asm
; link.exe hellow64.obj /out:hellow64.exe /machine:x64 /subsystem:windows /entry:start /nodefaultlib /nologo
; start /wait hellow64.exe
; echo %errorlevel%

; Inspecting the code:
; dumpbin /nologo /disasm hellow64.exe

; Structs/offsets have been observed with WinDbg on:
; > vertarget
; Windows 10 Version 18362 MP (8 procs) Free x64
; Product: WinNt, suite: SingleUserTS Personal
; 18362.1.amd64fre.19h1_release.190318-1202

; > dt -v ntdll!_PEB
; struct _PEB, 115 elements, 0x7c8 bytes
;    +0x000 InheritedAddressSpace : UChar
;    +0x001 ReadImageFileExecOptions : UChar
;    +0x002 BeingDebugged    : UChar
;    +0x003 BitField         : UChar
;    +0x003 ImageUsesLargePages : Bitfield Pos 0, 1 Bit
;    +0x003 IsProtectedProcess : Bitfield Pos 1, 1 Bit
;    +0x003 IsImageDynamicallyRelocated : Bitfield Pos 2, 1 Bit
;    +0x003 SkipPatchingUser32Forwarders : Bitfield Pos 3, 1 Bit
;    +0x003 IsPackagedProcess : Bitfield Pos 4, 1 Bit
;    +0x003 IsAppContainer   : Bitfield Pos 5, 1 Bit
;    +0x003 IsProtectedProcessLight : Bitfield Pos 6, 1 Bit
;    +0x003 IsLongPathAwareProcess : Bitfield Pos 7, 1 Bit
;    +0x004 Padding0         : [4] UChar
;    +0x008 Mutant           : Ptr64 to Void
;    +0x010 ImageBaseAddress : Ptr64 to Void
;    +0x018 Ldr              : Ptr64 to struct _PEB_LDR_DATA, 9 elements, 0x58 bytes
; ...

; > dt -v ntdll!_PEB_LDR_DATA
; struct _PEB_LDR_DATA, 9 elements, 0x58 bytes
;    +0x000 Length           : Uint4B
;    +0x004 Initialized      : UChar
;    +0x008 SsHandle         : Ptr64 to Void
;    +0x010 InLoadOrderModuleList : struct _LIST_ENTRY, 2 elements, 0x10 bytes
;    +0x020 InMemoryOrderModuleList : struct _LIST_ENTRY, 2 elements, 0x10 bytes
; ...

; > dt -v ntdll!_LIST_ENTRY
; struct _LIST_ENTRY, 2 elements, 0x10 bytes
;    +0x000 Flink            : Ptr64 to struct _LIST_ENTRY, 2 elements, 0x10 bytes
;    +0x008 Blink            : Ptr64 to struct _LIST_ENTRY, 2 elements, 0x10 bytes

default rel

global start

section .text
start:
; get the Process Environment Block (PEB) from the Thread Environment Block
    xor rcx, rcx
    mov rax, [gs:rcx + 0x60]

; walk the InMemoryOrderModuleList list until the third entry (module kernel32.dll)
    mov rax, [rax + 0x18]       ; PEB->Ldr
    mov rsi, [rax + 0x20]       ; PEB->Ldr.InMemoryOrderModuleList.Flink
    lodsq                       ; load quadword at address RSI into RAX (second module), RSI incremented
    xchg rax, rsi
    lodsq                       ; load quadword at address RSI into RAX (third module), RSI incremented
    mov rax, [rax + 0x20]       ; set the base address as the return value
    ret
