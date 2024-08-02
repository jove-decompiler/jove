#define CALLBACK    __stdcall

#define WINAPI      __stdcall

#define NULL  ((void*)0)

typedef unsigned long ULONG, *PULONG;

typedef void                                   *LPVOID;

typedef int             BOOL,       *PBOOL,    *LPBOOL;

typedef unsigned long   DWORD,      *PDWORD,   *LPDWORD;

typedef unsigned int  ULONG_PTR, *PULONG_PTR;

#define NTAPI __stdcall

#define VOID void

typedef VOID           *PVOID;

#define DECLARE_HANDLE(a) typedef struct a##__ { int unused; } *a

#define	DLL_PROCESS_DETACH	0

#define	DLL_PROCESS_ATTACH	1

#define	DLL_THREAD_ATTACH	2

#define	DLL_THREAD_DETACH	3

typedef VOID (CALLBACK *PIMAGE_TLS_CALLBACK)(
	LPVOID DllHandle,DWORD Reason,LPVOID Reserved
);

typedef struct _IMAGE_TLS_DIRECTORY32 {
    DWORD   StartAddressOfRawData;
    DWORD   EndAddressOfRawData;
    DWORD   AddressOfIndex;
    DWORD   AddressOfCallBacks;
    DWORD   SizeOfZeroFill;
    DWORD   Characteristics;
} IMAGE_TLS_DIRECTORY32, *PIMAGE_TLS_DIRECTORY32;

typedef IMAGE_TLS_DIRECTORY32           IMAGE_TLS_DIRECTORY;

DECLARE_HANDLE(HINSTANCE);

typedef HINSTANCE HMODULE;
