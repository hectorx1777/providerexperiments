# Windows Credential Providers Experiments

Research and authorized-assessment tooling that demonstrates two classic Windows authentication hooking paths:

1. **Network Provider DLL** (MPR / `NPLogonNotify`) — runs in the logon process
2. **LSA Security Support Provider (SSP)** — loaded into `lsass.exe` via `AddSecurityPackageA`

A small **SSP loader** executable registers the SSP DLL at runtime.

> **Use only on systems you own or have explicit written permission to test.**  
> Loading custom code into LSASS or intercepting credentials can crash the system, violate policy, and may be illegal without authorization.

---

## Repository layout

```
providerexperiments/
├── README.md
<<<<<<< HEAD
├── LICENSE
├── securityaddon/
│   ├── SecurityAddon.sln
│   └── SecurityAddon/              → SecurityAddon.dll (SSP)
├── testingProvider/
│   └── TestingProvider/            → source only (TestingProvider.c + .def)
└── LoadingofSSPClassic/
    ├── LoadingofSSPClassic.sln
    └── LoadingofSSPClassic/        → LoadingofSSPClassic.exe (SSP loader)
```

| Component | Solution | Output |
|-----------|----------|--------|
| SSP DLL | `securityaddon/SecurityAddon.sln` | `SecurityAddon.dll` |
| Network provider | `testingProvider/TestingProvider/` | `TestingProvider.dll` (build with `cl` — no VS project) |
| SSP loader | `LoadingofSSPClassic/LoadingofSSPClassic.sln` | `LoadingofSSPClassic.exe` |
=======
├── network-provider/
│   └── TestingProviderAdv.c      
│   └── TestingProviderAdv.def
│   └── TestingProvider.c         # simpler baseline
├── ssp/
│   └── SecuritzProvidercat/      # Visual Studio solution
└── ssp-loader/
    └── LoadingofSSP/             # Visual Studio solution
        ├── LoadingofSSP/         # refactored loader (LoadingofSSPnewshit.cpp)
        └── LoadingofSSPClassic/  # classic monolithic loader
```

Current source locations on disk (before merge):

| Component | Path |
|-----------|------|
| Network provider | `nppspy/nppspy/TestingProviderAdv.c` |
| SSP DLL | `SecurityAddon` |
| SSP loader (classic) | `SSPLOADINGTEST/LoadingofSSP/LoadingofSSPClassic/` |
>>>>>>> 18a76b8823a8e72c9198702d2923315ece969bab

---

## Overview

```mermaid
flowchart LR
    subgraph logon [Interactive logon]
<<<<<<< HEAD
        NP[TestingProvider.dll]
=======
        NP[TestingProviderAdv.dll]
>>>>>>> 18a76b8823a8e72c9198702d2923315ece969bab
        NP -->|NPLogonNotify| NPLog[C:\Windows\Tasks\temp40.txt]
    end

    subgraph lsass [LSASS]
        SSP[SecurityAddon.dll]
        SSP -->|SpAcceptCredentials| SSPLog[c:\windows\Temp\logged-pw.txt]
    end

    Loader[LoadingofSSPClassic.exe] -->|AddSecurityPackageA| SSP
```

| Piece | Role | MITRE |
|-------|------|-------|
<<<<<<< HEAD
| `TestingProvider.dll` | MPR network provider; hooks interactive logon | T1556.008 |
=======
| `TestingProviderAdv.dll` | MPR network provider; hooks interactive logon | T1556.008 |
>>>>>>> 18a76b8823a8e72c9198702d2923315ece969bab
| `SecurityAddon.dll` | LSA SSP; receives credentials inside LSASS | T1547.005 |
| `LoadingofSSPClassic.exe` | User-mode loader; calls `AddSecurityPackageA` | — |

The **network provider** and **SSP** are independent. You can deploy either or both. The loader is only needed for the SSP path.

---

<<<<<<< HEAD
## 1. Network Provider — `TestingProvider`

**Source:** `testingProvider/TestingProvider/` (`TestingProvider.c` + `TestingProvider.def`) — no Visual Studio project.
=======
## 1. Network Provider — `TestingProviderAdv`

**File:** `TestingProviderAdv.c` (+ `TestingProviderAdv.def`)  
>>>>>>> 18a76b8823a8e72c9198702d2923315ece969bab

### What it does

- Registers as a network provider.
- Implements `NPLogonNotify` and writes username/password from `MSV1_0_INTERACTIVE_LOGON` to:
  - `C:\Windows\Tasks\temp40.txt`
- Resolves `kernel32` APIs at runtime via **DJB2 hashing** (no plain API name strings in `.rdata`).
- Calls a random subset of resolved APIs on each logon (benign jitter).
- Exports a plausible NP surface (`NPGetCaps`, `NPAddConnection`, …) plus **decoy WinAPI-named stubs** in the export table (`.def` forwards).

### Build

Build from a **x64 Native Tools** prompt:

```bat
<<<<<<< HEAD
cd testingProvider\TestingProvider
cl /nologo /O2 /LD TestingProvider.c /link /DEF:TestingProvider.def Mpr.lib /OUT:TestingProvider.dll
```

Output: `TestingProvider.dll`
=======
cl /nologo /O2 /LD TestingProviderAdv.c /link /DEF:TestingProviderAdv.def /OUT:TestingProviderAdv.dll
```

Output: `TestingProviderAdv.dll`
>>>>>>> 18a76b8823a8e72c9198702d2923315ece969bab

### Install (registry)

Copy the DLL to System32 (or another path and update `ProviderPath`):

```bat
<<<<<<< HEAD
copy TestingProvider\x64\Release\TestingProvider.dll %SystemRoot%\System32\TestingProvider.dll
=======
copy TestingProviderAdv.dll %SystemRoot%\System32\TestingProviderAdv.dll
>>>>>>> 18a76b8823a8e72c9198702d2923315ece969bab
```

```reg
$NetworkProviderName = "TestProvider"

New-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\$NetworkProviderName"  
New-Item -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\$NetworkProviderName\\NetworkProvider"  
New-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\$NetworkProviderName\\NetworkProvider" -Name "Class" -Value 2  
New-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\$NetworkProviderName\\NetworkProvider" -Name "Name" -Value \$NetworkProviderName  
New-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\$NetworkProviderName\\NetworkProvider" -Name "ProviderPath" -PropertyType ExpandString -Value "%SystemRoot%\\System32\$NetworkProviderName.dll"

$NetworkProviderPath = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" -Name ProviderOrder $NetworkProviderOrder = $NetworkProviderPath.ProviderOrder + ",$NetworkProviderName"  
Set-ItemProperty -Path \$NetworkProviderPath.PSPath -Name ProviderOrder -Value \$NetworkProviderOrder
```

Reboot or relogibn the Workstation service for the provider to load on logon

**Delete**
Delete the dll from system32\Networkprovider.dll

---

## 2. SSP DLL — `SecurityAddon`

**Project:** `securityaddon/SecurityAddon.sln` (Visual Studio 2022, **x64 Release**)

### What it does

- Exports `SpLsaModeInitialize` (required LSA SSP entry).
- Package name reported to LSA: **Company Log Module** (`SpGetInfo`).
- `SpAcceptCredentials` logs `account@domain:password` to:
  - `c:\windows\Temp\logged-pw.txt`
- Uses **LSA heap** (`AllocateLsaHeap` / `FreeLsaHeap`) — no CRT/STL inside callbacks.
- Copies `UNICODE_STRING` fields by **Length** (not null-terminated assumptions).
- **30 WinAPI `_exp` decoy exports** (export-table padding only; not called from LSA callbacks).
- Module definition: `SecurityAddon.def` (keeps exports under `/OPT:REF`).


Expect **31 exports**: `SpLsaModeInitialize` + 30 `*_exp` functions.

### Deploy before loading

The loader expects the SSP at:

```
C:\Temp\SecurityAddon.dll
```

Either copy/rename after build:

```bat
mkdir C:\Temp 2>nul
copy securityaddon\SecurityAddon\x64\Release\SecurityAddon.dll C:\Temp\SecurityAddon.dll
```

Or change the XOR-encoded path in the loader (`pathkatze` / `g_encPackagePath`) to match your filename.

> **Warning:** A bad SSP DLL can crash **LSASS** and force a reboot. Test on a VM snapshot first.

---

## 3. SSP Loader — `LoadingofSSPClassic`

**Project:** `LoadingofSSPClassic/LoadingofSSPClassic.sln` (Visual Studio 2022, **x64 Release**)


### What the  loader does

1. Optional benign noise (`keineaufruhr` loops, WinAPI `_exp` export wrappers).
2. Decodes XOR-embedded strings (`doTheMath3G`, key `{ 0x67, 0xDD, 0xFE }`):
   - SSP path → `C:\Temp\SecurityAddon.dll`
   - Module name → `sspicli.dll` (reference only; active path uses PEB hash lookup)
3. Resolves **ntdll**, **kernel32**, **sspicli.dll** via **Jenkins hash** (`GMH` / `GPAH`) — no plain `GetProcAddress("AddSecurityPackageA")` in the hot path.
4. Finds `call r12` gadget in ntdll (`\x41\xFF\xD4`).
5. Invokes `AddSecurityPackageA` through **`ChangeRetAddress`** (`patching.asm`) — return-address spoofed call.

### Run

```bat
LoadingofSSPClassic.exe
```

Run from an **elevated** context if required by your environment. The loader expects `sspicli.dll` to already be mapped (normally true when `Secur32.lib` is linked). On success, `AddSecurityPackageA` registers the SSP into LSASS.

After loading, trigger an interactive logon and check `c:\windows\Temp\logged-pw.txt`.

### Changing the SSP path
edit `pathkatze[]` in `LoadingofSSP.cpp`.  
Re-encode with 3-byte rolling XOR (`0x67`, `0xDD`, `0xFE`).

---

## End-to-end SSP workflow

1. Build `SecurityAddon.dll` (Release x64).
2. Copy to `C:\Temp\SecurityAddon.dll`.
3. Build and run `LoadingofSSPClassic.exe`.
4. Log on interactively (or unlock).
5. Read `c:\windows\Temp\logged-pw.txt`.

SSP registration is **volatile** — it does not survive LSASS restart/reboot the way a registry-installed SSP package would.

---

## End-to-end network provider workflow

<<<<<<< HEAD
1. Build `TestingProvider.dll`.
=======
1. Build `TestingProviderAdv.dll`.
>>>>>>> 18a76b8823a8e72c9198702d2923315ece969bab
2. Install registry keys (see above).
3. Reboot or restart services.
4. Interactive logon → check `C:\Windows\Tasks\temp40.txt`.

---

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| LSASS crash / forced reboot | SSP bug (bad `UNICODE_STRING` handling, CRT in callbacks, etc.) |
| Loader exits immediately (refactored build) | Sandbox gate (`SSP_ENABLE_SANDBOX_GATE`) or silent Release (`SSP_DEBUG=0`) |
| `sspicli.dll not loaded` | Process has no SSPI imports; call `InitSecurityInterfaceA()` first or load `sspicli.dll` explicitly |
| No SSP log file | Package not registered, wrong DLL path, or no logon event yet |
| No NP log file | Provider not in `ProviderOrder`, wrong architecture (must be x64), or not an interactive logon |

**Event Viewer:** Application log → filter `lsass.exe` / faulting module for SSP crashes.


---

## License / disclaimer

For **authorized security research and red-team assessments** only. The authors are not responsible for misuse. Ensure you comply with local laws and engagement rules before deploying any component.
