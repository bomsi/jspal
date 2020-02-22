; Simple program which stores addresses for LoadLibraryA and GetProcAddress
;  functions on the stack. Returns 0 on success, 1 otherwise.

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
; prepare stack which will be used for local variables
   push   ebp                      ; EBP must be preserved across calls
   mov    ebp, esp                 ; from now on EBP points to the current 
                                   ;  stack frame
   sub    esp, 0x28                ; allocate space for local variables

; get the Process Environment Block (PEB) from the Thread Environment Block
   xor    ecx, ecx
   mov    eax, [fs:ecx + 0x30]

; walk the InMemoryOrderModuleList list until the second or third entry
;  (module kernel32.dll)
   mov    eax, [eax + 0x0c]        ; follow PPEB_LDR_DATA LoaderData
   mov    eax, [eax + 0x14]        ; follow LIST_ENTRY InMemoryOrderModuleList
   mov    eax, [eax]               ; follow Flink (first LDR_MODULE,
                                   ;  i.e. ntdll.dll)

   mov    eax, [eax]               ; follow Flink (second LDR_MODULE,
                                   ;  i.e. kernel32.dll or kernelbase.dll)
                                   ; TODO: handle case when kernelbase.dll
                                   ;  and not kernel32.dll
   mov    eax, [eax + 0x10]        ; PVOID BaseAddress (EAX is already at
                                   ;  offset 0x08, so just add 0x10, to get
                                   ;  to 0x18)
   mov    ecx, eax                 ; ECX <- kernel32.dll base address
   mov    dword [ebp - 0x04], ecx  ; store kernel32.dll base address

; parse PE format (offsets extracted with PEview)
   mov    eax, [eax + 0x3c]        ; RVA of the PE signature
   add    eax, ecx                 ; address of the PE signature
   
   mov    eax, [eax + 0x78]        ; RVA of the Export Table
   add    eax, ecx                 ; address of the Export Table
   mov    ebx, eax                 ; EBX <- Export Table address
   mov    dword [ebp - 0x08], ebx  ; store Export Table address

   mov    eax, [ebx + 0x24]        ; RVA of the Ordinal Table
   add    eax, ecx                 ; address of the Ordinal Table
   mov    dword [ebp - 0x0c], eax  ; store Ordinal Table address

   mov    eax, [ebx + 0x20]        ; RVA of the Name Pointer Table
   add    eax, ecx                 ; address of the Name Pointer Table
   mov    dword [ebp - 0x10], eax  ; store Name Pointer Table address

   mov    eax, [ebx + 0x1c]        ; RVA of the Address Table
   add    eax, ecx                 ; address of the Address Table
   mov    dword [ebp - 0x14], eax  ; store Address Table address

   mov    eax, [ebx + 0x14]        ; number of exported functions
   mov    dword [ebp - 0x18], eax  ; store the number of exported functions

; push zero terminated "LoadLibraryA"
   xor    eax, eax
   push   eax
   push   0x41797261               ; "aryA"
   push   0x7262694c               ; "Libr"
   push   0x64616f4c               ; "Load"
   mov    dword [ebp - 0x1c], esp

; push zero terminated "GetProcAddress"
   mov    ax, 0x7373               ; "ss"
   push   eax
   push   0x65726464               ; "ddre"
   push   0x41636f72               ; "rocA"
   push   0x50746547               ; "GetP"
   mov    dword [ebp - 0x20], esp

; find LoadLibraryA function address
   xor    eax, eax                 ; used as counter (position)
   cld                             ; strings processed from left to right
loadlibrarya_search:
   xor    ecx, ecx
   mov    esi, [ebp - 0x1c]        ; ESI <- "LoadLibraryA\x00"
   mov    edi, [ebp - 0x10]        ; EDI <- address of the Name Pointer Table

   mov    edi, [edi + eax * 4]     ; entries in the table are 4 bytes long
   add    edi, [ebp - 0x04]        ; add RVA of the entry
   add    cx, 13                   ; length(LoadLibraryA\x00) = 13
   repe cmpsb
   jz     short loadlibrarya_found

   inc    eax                      ; next entry
   cmp    eax, [ebp - 0x18]        ; check if it's the last entry
   jb     short loadlibrarya_search
   
   jmp    short loadlibrarya_end   ; went past last entry end didn't find it

loadlibrarya_found:
   mov    ebx, [ebp - 0x0c]        ; address of the Ordinal Table
   mov    ecx, [ebp - 0x14]        ; address of the Address Table
   mov    ax, [ebx + eax * 2]      ; ordinal number
   mov    eax, [ecx + eax * 4]     ; RVA of the function
   add    eax, [ebp - 0x04]        ; EAX <- address of LoadLibraryA
   mov    dword [ebp - 0x24], eax  ; store the address of LoadLibraryA

   jmp    short getprocaddress_search_init

loadlibrarya_end:
   nop                             ; TODO handle "not found" case better
   jmp    short fail_end

; find GetProcAddress function address
getprocaddress_search_init:
   xor    eax, eax                 ; used as counter (position)
   cld
getprocaddress_search:
   xor    ecx, ecx
   mov    esi, [ebp - 0x20]        ; ESI <- "GetProcAddress\x00"
   mov    edi, [ebp - 0x10]        ; EDI <- address of the Name Pointer Table

   mov    edi, [edi + eax * 4]     ; entries in the table are 4 bytes long
   add    edi, [ebp - 0x04]        ; add RVA of the entry
   add    cx, 15                   ; length(GetProcAddress\x00) = 15
   repe cmpsb
   jz     short getprocaddress_found

   inc    eax                      ; next entry
   cmp    eax, [ebp - 0x18]        ; check if it's the last entry
   jb     short getprocaddress_search
   
   jmp    short getprocaddress_end

getprocaddress_found:
   mov    ebx, [ebp - 0x0c]        ; address of the Ordinal Table
   mov    ecx, [ebp - 0x14]        ; address of the Address Table
   mov    ax, [ebx + eax * 2]      ; ordinal number
   mov    eax, [ecx + eax * 4]     ; RVA of the function
   add    eax, [ebp - 0x04]        ; EAX <- address of GetProcAddress
   mov    dword [ebp - 0x28], eax  ; store the address of GetProcAddress

   xor    eax, eax                 ; set 0 as the final return value
   jmp    short the_end

getprocaddress_end:
   nop                             ; TODO handle "not found" case better
   jmp    short fail_end

fail_end:
   xor    eax, eax
   inc    eax                      ; set 1 as the final return value

the_end:
; clean allocated locals and restore EBP; leave is equivalent to:
;  mov    esp, ebp
;  pop    ebp
   leave

   ret

