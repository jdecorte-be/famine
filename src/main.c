#include <stdio.h>
#include "winntdef.h"

int checkFormat(FILE *PEFile)
{

}

int main(int ac, char **av)
{
    if (ac != 2)
        return printf("Usage: %s [path of PE]\n", av[0]);


    FILE *PEFile;
    fopen_s(&PEFile, av[1], "rb");

    if (PEFile == NULL)
        return printf("Can't open file\n");

    int format = 
    checkFormat()

    if()


}