#      define __int64 long long

#  define DECLSPEC_ALIGN(x) __attribute__((aligned(x)))

#define CALLBACK    __stdcall

#define WINAPI      __stdcall

#define NULL  ((void*)0)

typedef unsigned long ULONG, *PULONG;

typedef void                                   *LPVOID;

typedef int             BOOL,       *PBOOL,    *LPBOOL;

typedef unsigned long   DWORD,      *PDWORD,   *LPDWORD;

#define NTAPI __stdcall

#define VOID void

typedef VOID           *PVOID;

typedef unsigned __int64 DECLSPEC_ALIGN(8) ULONGLONG,  *PULONGLONG;

#define DECLARE_HANDLE(a) typedef struct a##__ { int unused; } *a

#define	DLL_PROCESS_DETACH	0

#define	DLL_PROCESS_ATTACH	1

#define	DLL_THREAD_ATTACH	2

#define	DLL_THREAD_DETACH	3

typedef VOID (CALLBACK *PIMAGE_TLS_CALLBACK)(
	LPVOID DllHandle,DWORD Reason,LPVOID Reserved
);

typedef struct _IMAGE_TLS_DIRECTORY64 {
    ULONGLONG   StartAddressOfRawData;
    ULONGLONG   EndAddressOfRawData;
    ULONGLONG   AddressOfIndex;
    ULONGLONG   AddressOfCallBacks;
    DWORD       SizeOfZeroFill;
    DWORD       Characteristics;
} IMAGE_TLS_DIRECTORY64, *PIMAGE_TLS_DIRECTORY64;

typedef IMAGE_TLS_DIRECTORY64           IMAGE_TLS_DIRECTORY;

DECLARE_HANDLE(HINSTANCE);

typedef HINSTANCE HMODULE;
