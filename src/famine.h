#ifdef _DEBUG
    #include <stdio.h>
    #define ERROR_SYS(x) fprintf(stderr, "Error: %s (Error code: %lu)\n", x, GetLastError())
#else
    #define ERROR_SYS(x)
#endif

#define SECTION_NAME_SIZE 8

#define FILL_STRING_WITH_BUF(string, buffer) \
	string.Length = sizeof(buffer); \
	string.MaximumLength = string.Length; \
	string.Buffer = (PCHAR)buffer


#define LDRLOADDLL_HASH					0xbdbf9c13
#define LDRGETPROCADDRESS_HASH			0x5ed941b5

#define CREATEFILEA_HASH        0x4fdaf6da  // Replace with actual hash
#define GETFILESIZE_HASH        0x701e12c6  // Replace with actual hash
#define CREATEFILEMAPPINGA_HASH 0x23f9cd0a  // Replace with actual hash
#define MAPVIEWOFFILE_HASH      0x757aef13  // Replace with actual hash
#define CLOSEHANDLE_HASH        0x528796c6  // Replace with actual hash


// function pointers ============================================================

typedef NTSTATUS(WINAPI* LDRLOADDLL)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);
typedef NTSTATUS(WINAPI* LDRGETPROCADDRESS)(HMODULE, PANSI_STRING, WORD, PVOID*);

// BOOL UnmapViewOfFile(
//   [in] LPCVOID lpBaseAddress
// );
typedef BOOL(WINAPI* UNMAPVIEWOFFILE)(LPCVOID lpBaseAddress);

// HANDLE CreateFileA(
//   [in]           LPCSTR                lpFileName,
//   [in]           DWORD                 dwDesiredAccess,
//   [in]           DWORD                 dwShareMode,
//   [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
//   [in]           DWORD                 dwCreationDisposition,
//   [in]           DWORD                 dwFlagsAndAttributes,
//   [in, optional] HANDLE                hTemplateFile
// );
typedef HANDLE(WINAPI* CREATEFILEA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

// BOOL CloseHandle(
//   [in] HANDLE hObject
// );
typedef BOOL(WINAPI* CLOSEHANDLE)(HANDLE);

// LPVOID MapViewOfFile(
//   [in] HANDLE hFileMappingObject,
//   [in] DWORD  dwDesiredAccess,
//   [in] DWORD  dwFileOffsetHigh,
//   [in] DWORD  dwFileOffsetLow,
//   [in] SIZE_T dwNumberOfBytesToMap
// );
typedef LPVOID(WINAPI* MAPVIEWOFFILE)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);

// DWORD GetFileSize(
//   [in]            HANDLE  hFile,
//   [out, optional] LPDWORD lpFileSizeHigh
// );
typedef DWORD(WINAPI* GETFILESIZE)(HANDLE, LPDWORD);

// LPVOID MapViewOfFile(
//   [in] HANDLE hFileMappingObject,
//   [in] DWORD  dwDesiredAccess,
//   [in] DWORD  dwFileOffsetHigh,
//   [in] DWORD  dwFileOffsetLow,
//   [in] SIZE_T dwNumberOfBytesToMap
// );
typedef LPVOID(WINAPI* MAPVIEWOFFILE)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);

// HANDLE CreateFileMappingA(
//   [in]           HANDLE                hFile,
//   [in, optional] LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
//   [in]           DWORD                 flProtect,
//   [in]           DWORD                 dwMaximumSizeHigh,
//   [in]           DWORD                 dwMaximumSizeLow,
//   [in, optional] LPCSTR                lpName
// );
typedef HANDLE(WINAPI* CREATEFILEMAPPINGA)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
