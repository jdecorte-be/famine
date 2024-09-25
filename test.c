/*
 *  Simple shellcode tester for Windows. Takes in a raw shellcode
 *  file name as its only input. Otherwise executes the shellcode
 *  in the file named "shellcode", if any.
 *
 *  To compile you need "cl.exe" from Visual Studio. GCC compiles
 *  without issues but messes up the binary so it's impossible
 *  to run it correctly.
 *
 *  (C) 2016, 0xBADCA7
**/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <windows.h>

#define FILENAME_LEN 255

uint8_t main(int argc, char *argv[])
{

    char *filename = (char *)(calloc(FILENAME_LEN, sizeof(char)));

    if (argv[1] != NULL)
    {
        printf("Will be using \"%s\" as shellcode.\r\n", argv[1]);
        strncpy(filename, argv[1], FILENAME_LEN);
    }
    else
    {
        printf("No path to shellcode provided. Defaulting to \"./shellcode\"\r\n");
        strncpy(filename, "shellcode", FILENAME_LEN);

    }

    FILE *fp = fopen(filename, "rb");

    if (fp == NULL)
    {
        printf ("File could not be open, errno = %d\n", errno);
        return 1;
    }

    /* Print shellcode size */
    fseek(fp, 0, SEEK_END);
    uint64_t size = ftell(fp);
    printf("Size of %s: %"PRId64" bytes\r\n", filename, size);

    /* Read the shellcode in */
    fseek(fp, 0, SEEK_SET);
    char *shellcode = (char *)calloc(1, size);
    memset(shellcode, 0x90, size);

    uint64_t bytes_read = fread((void *)shellcode, 1, size, fp);
    if (bytes_read != size)
    {
        printf ("Couldn't read all the file, errno = %d\n", errno);
        return 1;
    }
    fclose(fp);
    printf("Read %"PRId64" bytes\r\n", bytes_read);

    /* Print out what we're running */
    /*
    for (uint8_t i = 0; i < bytes_read;)
    {
        printf("%02x ", (uint8_t) shellcode[i]);

        i++;

        if (i % 8 == 0)
        {
            printf("\r\n");
        }
    }
    */


    /* Mark memory as RWX */
    printf("\r\nPaused for debugger. Last chance before jumping to shellcode.\r\n");
    system("PAUSE");
    DWORD oldProtect;
    BOOL ret = VirtualProtect(shellcode, bytes_read, PAGE_EXECUTE_READWRITE, &oldProtect);

    if (!ret)
    {
        printf ("VirtualProtect failed ...\n");
        return EXIT_FAILURE;
    }

    /* Jump to shellcode */
    ((void (*)(void))shellcode)();

    return 0;
}