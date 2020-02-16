; Simple program which returns the kernel32.dll base address

; To build and run:
; "C:\Program Files\NASM\nasm.exe" -fwin32 hellow32.asm
; GoLink.exe /console /entry start hellow32.obj
; start /wait hellow32.exe
; echo %errorlevel%

; Tested on (systeminfo.exe output):
; OS Name:    Microsoft Windows XP Professional
; OS Version: 5.1.2600 Service Pack 3 Build 2600

[bits 32]
global start

section .text
start:
; get the Process Environment Block (PEB) from the Thread Environment Block
    xor    ecx, ecx
    mov    eax, [fs:ecx + 0x30]

; walk the InMemoryOrderModuleList list until the second or third entry (module kernel32.dll)
    mov    eax, [eax + 0x0c]   ; follow PPEB_LDR_DATA LoaderData
    mov    eax, [eax + 0x14]   ; follow LIST_ENTRY InMemoryOrderModuleList
    mov    eax, [eax]          ; follow Flink (first LDR_MODULE, i.e. ntdll.dll)
    mov    eax, [eax]          ; follow Flink (second LDR_MODULE, i.e. kernel32.dll or kernelbase.dll)
	
    ; TODO handle case when kernelbase.dll and not kernel32.dll

    mov eax, [eax + 0x10]      ; PVOID BaseAddress (EAX is already at offset 0x08, so just add 0x10, to get to 0x18)
    ret

