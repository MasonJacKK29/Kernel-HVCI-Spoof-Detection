// ============================================================================
//  Core Isolation Spoof Detector  (standalone, open-source)
//  Made by MasonJacK.
//  License: MIT  —  free to use in any anti-cheat / EDR / forensic tool.
//
//  WHAT IT DETECTS
//  ---------------
//  Windows "Core Isolation > Memory Integrity" is HVCI (Hypervisor-enforced
//  Code Integrity). It runs inside the Hyper-V hypervisor and refuses to load
//  unsigned kernel drivers. Cheats that need a BYOVD (Bring Your Own Vulnerable
//  Driver) or a manually-mapped unsigned driver must first defeat HVCI. A common
//  evasion is to disable HVCI, load the driver, then HOOK the kernel query
//  (NtQuerySystemInformation, class SystemCodeIntegrityInformation) so that the
//  operating system keeps reporting "HVCI is active" to any anti-cheat that asks.
//
//  THE GROUND TRUTH: CPUID
//  -----------------------
//  HVCI mathematically REQUIRES the Hyper-V hypervisor to be running. Whether a
//  hypervisor is present is exposed by the CPUID instruction — a raw CPU
//  instruction that executes on the physical core and CANNOT be intercepted or
//  faked from user mode. So:
//
//        kernel says "HVCI ON"  +  CPUID says "no hypervisor"  =  SPOOF
//
//  That paradox is impossible on a genuine system and is the strongest, lowest
//  false-positive signal that NtQuerySystemInformation has been tampered with.
//
//  This tool also reports supporting evidence (registry state, BCD hypervisor
//  launch type, and a WMI fallback) so an analyst sees the full picture.
//
//  BUILD:  build.bat        (or: cl /EHsc /O2 main.cpp)
//  RUN:    run as Administrator.
//  EXIT:   0 = CLEAN, 1 = DISABLED / WARNING, 2 = SPOOF / SEVERE.
// ============================================================================

#define _WIN32_DCOM          // required by some SDKs for CoInitializeEx
#include <windows.h>
#include <intrin.h>
#include <wbemidl.h>
#include <comdef.h>
#include <cstdio>
#include <cstdint>
#include <string>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// ---- SystemCodeIntegrityInformation (class 103) --------------------------
typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION;

#ifndef CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED 0x400
#endif
static const ULONG kSystemCodeIntegrityInformation = 103;

// Use LONG instead of NTSTATUS to avoid pulling in <winternl.h> (which would
// redeclare NtQuerySystemInformation with a conflicting signature). NTSTATUS is
// just a typedef for LONG; success is 0 (STATUS_SUCCESS).
typedef LONG (NTAPI *fnNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

// ============================================================================
//  Console presentation helpers (colors + boxed layout + smart pause)
// ============================================================================
static bool g_color = false;

static const char* CReset() { return g_color ? "\x1b[0m"  : ""; }
static const char* CDim()   { return g_color ? "\x1b[90m" : ""; }
static const char* CCyan()  { return g_color ? "\x1b[96m" : ""; }
static const char* CGreen() { return g_color ? "\x1b[92m" : ""; }
static const char* CYellow(){ return g_color ? "\x1b[93m" : ""; }
static const char* CRed()   { return g_color ? "\x1b[91m" : ""; }
static const char* CBold()  { return g_color ? "\x1b[1m"  : ""; }

static void EnableColor() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode)) {
        if (SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
            g_color = true;
    }
}

// Full-width rule (ASCII, portable across code pages).
static void Rule() {
    printf("  %s+----------------------------------------------------------+%s\n",
           CDim(), CReset());
}

// If the program owns a freshly-spawned console (double-click), wait so the
// window does not vanish. If launched from an existing cmd/terminal, return
// immediately (no annoying pause for scripted / piped use).
static bool OwnsFreshConsole() {
    DWORD pids[3];
    DWORD n = GetConsoleProcessList(pids, 3);
    return n <= 1;
}

static int Finish(int code) {
    if (OwnsFreshConsole()) {
        printf("\n  %sPress Enter to exit...%s", CDim(), CReset());
        (void)getchar();
    }
    return code;
}

static bool IsElevated() {
    BOOL elevated = FALSE;
    HANDLE tok = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION te{};
        DWORD cb = sizeof(te);
        if (GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &cb))
            elevated = te.TokenIsElevated;
        CloseHandle(tok);
    }
    return elevated != FALSE;
}

// ========================================================================
//  1) Kernel HVCI state — NtQuerySystemInformation(103)   [ground truth #1]
// ========================================================================
static bool QueryKernelHvci(bool *queryOk) {
    *queryOk = false;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;

    auto NtQuerySystemInformation =
        reinterpret_cast<fnNtQuerySystemInformation>(
            GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!NtQuerySystemInformation) return false;

    SYSTEM_CODEINTEGRITY_INFORMATION ci{};
    ci.Length = sizeof(ci);
    LONG st = NtQuerySystemInformation(
        kSystemCodeIntegrityInformation, &ci, sizeof(ci), nullptr);
    if (st != 0) return false;

    *queryOk = true;
    return (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0;
}

// ========================================================================
//  2) CPUID hypervisor-present bit — CPUID(EAX=1).ECX[31]  [ground truth #2]
// ========================================================================
static bool CpuidHypervisorPresent() {
    int regs[4] = {0, 0, 0, 0};
    __cpuid(regs, 1);
    return (static_cast<unsigned int>(regs[2]) & (1u << 31)) != 0;
}

// ========================================================================
//  3) Registry — HypervisorEnforcedCodeIntegrity (Enabled / Locked)
// ========================================================================
struct RegState {
    bool  keyPresent = false;
    bool  enabledPresent = false;
    bool  lockedPresent = false;
    DWORD enabled = 0;
    DWORD locked = 0;
};

static RegState ReadRegistry() {
    RegState r;
    const char *path =
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\"
        "HypervisorEnforcedCodeIntegrity";
    HKEY hk = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return r;
    r.keyPresent = true;

    DWORD sz = sizeof(DWORD);
    if (RegQueryValueExA(hk, "Enabled", nullptr, nullptr,
                         reinterpret_cast<LPBYTE>(&r.enabled), &sz) == ERROR_SUCCESS)
        r.enabledPresent = true;

    sz = sizeof(DWORD);
    if (RegQueryValueExA(hk, "Locked", nullptr, nullptr,
                         reinterpret_cast<LPBYTE>(&r.locked), &sz) == ERROR_SUCCESS)
        r.lockedPresent = true;

    RegCloseKey(hk);
    return r;
}

// ========================================================================
//  4) BCD — hypervisorlaunchtype = off
// ========================================================================
static bool BcdHypervisorOff() {
    HKEY hObjects = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "BCD00000000\\Objects", 0,
                      KEY_ENUMERATE_SUB_KEYS | KEY_READ, &hObjects) != ERROR_SUCCESS)
        return false;

    bool off = false;
    char guid[128];
    DWORD idx = 0;
    for (;;) {
        DWORD nameLen = sizeof(guid);
        if (RegEnumKeyExA(hObjects, idx++, guid, &nameLen,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;

        std::string elemPath = std::string(guid) + "\\Elements\\25000021";
        HKEY hElem = nullptr;
        if (RegOpenKeyExA(hObjects, elemPath.c_str(), 0, KEY_READ, &hElem) == ERROR_SUCCESS) {
            BYTE val[16] = {0};
            DWORD vsz = sizeof(val), vtype = 0;
            LONG rv = RegQueryValueExA(hElem, "Element", nullptr, &vtype, val, &vsz);
            RegCloseKey(hElem);
            if (rv == ERROR_SUCCESS && vtype == REG_BINARY && vsz >= 1 && val[0] == 0x00) {
                off = true;
                break;
            }
        }
    }
    RegCloseKey(hObjects);
    return off;
}

// ========================================================================
//  5) WMI fallback — Win32_DeviceGuard.VirtualizationBasedSecurityStatus
//       0 = off, 1 = configured but not running, 2 = running.
// ========================================================================
static void WmiVbsStatus(bool *ok, bool *running) {
    *ok = false;
    *running = false;

    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool inited = SUCCEEDED(hrInit) || hrInit == RPC_E_CHANGED_MODE;
    if (!inited) return;

    CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                         RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                         nullptr, EOAC_NONE, nullptr);

    IWbemLocator *loc = nullptr;
    if (SUCCEEDED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                   IID_IWbemLocator, reinterpret_cast<void**>(&loc)))) {
        IWbemServices *svc = nullptr;
        if (SUCCEEDED(loc->ConnectServer(
                _bstr_t(L"ROOT\\Microsoft\\Windows\\DeviceGuard"),
                nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc))) {
            CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                              RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                              nullptr, EOAC_NONE);
            IEnumWbemClassObject *en = nullptr;
            if (SUCCEEDED(svc->ExecQuery(
                    _bstr_t(L"WQL"),
                    _bstr_t(L"SELECT * FROM Win32_DeviceGuard"),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    nullptr, &en))) {
                IWbemClassObject *obj = nullptr;
                ULONG got = 0;
                if (SUCCEEDED(en->Next(WBEM_INFINITE, 1, &obj, &got)) && got > 0 && obj) {
                    VARIANT v; VariantInit(&v);
                    if (SUCCEEDED(obj->Get(L"VirtualizationBasedSecurityStatus",
                                           0, &v, nullptr, nullptr))) {
                        if (v.vt == VT_I4 || v.vt == VT_UI4) {
                            *ok = true;
                            *running = (static_cast<uint32_t>(v.uintVal) == 2);
                        }
                    }
                    VariantClear(&v);
                    obj->Release();
                }
                en->Release();
            }
            svc->Release();
        }
        loc->Release();
    }
    if (SUCCEEDED(hrInit)) CoUninitialize();
}

// small helper: print one "label : value" row with a colored value
static void Field(const char* label, const char* color, const char* value) {
    printf("  %s%-32s%s %s%s%s\n", CDim(), label, CReset(), color, value, CReset());
}

// ========================================================================
//  main
// ========================================================================
int main() {
    EnableColor();
    SetConsoleTitleA("Core Isolation Spoof Detector - by MasonJacK");

    printf("\n");
    Rule();
    printf("  %s|%s   %s%sCore Isolation (HVCI) Spoof Detector%s                  %s|%s\n",
           CDim(), CReset(), CBold(), CCyan(), CReset(), CDim(), CReset());
    printf("  %s|%s   %skernel HVCI state  vs.  CPUID hypervisor bit%s          %s|%s\n",
           CDim(), CReset(), CDim(), CReset(), CDim(), CReset());
    printf("  %s|%s   %sMade by MasonJacK  -  MIT licensed%s                    %s|%s\n",
           CDim(), CReset(), CDim(), CReset(), CDim(), CReset());
    Rule();
    printf("\n");

    if (!IsElevated())
        printf("  %s[!] Not elevated. Run as Administrator for full accuracy.%s\n\n",
               CYellow(), CReset());

    // ---- gather ---------------------------------------------------------
    bool queryOk = false;
    bool kernelHvci = QueryKernelHvci(&queryOk);
    bool hyperv = CpuidHypervisorPresent();
    RegState reg = ReadRegistry();
    bool bcdOff = BcdHypervisorOff();

    // ---- report ---------------------------------------------------------
    printf("  %sSYSTEM STATE%s\n", CBold(), CReset());
    Field("Kernel HVCI (NtQuerySysInfo 103)",
          queryOk ? (kernelHvci ? CGreen() : CYellow()) : CRed(),
          queryOk ? (kernelHvci ? "ACTIVE" : "inactive") : "query FAILED");
    Field("CPUID hypervisor present",
          hyperv ? CGreen() : CYellow(),
          hyperv ? "present" : "ABSENT");
    if (reg.keyPresent) {
        char buf[96];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "Enabled=%s  Locked=%s",
                    reg.enabledPresent ? (reg.enabled ? "1" : "0") : "(none)",
                    reg.lockedPresent  ? (reg.locked  ? "1" : "0") : "(none)");
        Field("Registry HVCI scenario",
              (reg.lockedPresent && reg.locked == 0) ? CRed() : CDim(), buf);
    } else {
        Field("Registry HVCI scenario", CYellow(), "key MISSING");
    }
    Field("BCD hypervisorlaunchtype",
          bcdOff ? CYellow() : CGreen(),
          bcdOff ? "OFF" : "on/default");

    printf("\n");
    printf("  %sFINDINGS%s\n", CBold(), CReset());

    int exitCode = 0; // 0 clean, 1 warning, 2 severe

    // ---- 1) THE SPOOF ---------------------------------------------------
    if (queryOk && kernelHvci && !hyperv) {
        printf("  %s%s[SEVERE] Core Isolation SPOOF detected.%s\n", CBold(), CRed(), CReset());
        printf("  %s         Kernel reports HVCI ACTIVE, but CPUID shows NO hypervisor.%s\n", CDim(), CReset());
        printf("  %s         HVCI cannot run without Hyper-V -> NtQuerySystemInformation%s\n", CDim(), CReset());
        printf("  %s         is hooked at the kernel level (BYOVD / mapped driver).%s\n", CDim(), CReset());
        printf("\n");
        Rule();
        printf("  Verdict: %s%sSEVERE (spoof)%s\n", CBold(), CRed(), CReset());
        Rule();
        return Finish(2);
    }

    // ---- 2) Registry Locked=0 ------------------------------------------
    if (reg.lockedPresent && reg.locked == 0) {
        printf("  %s[SEVERE] HVCI 'Locked' value is 0 (unlock cheat trace).%s\n", CRed(), CReset());
        printf("  %s         HVCI can be turned off without a reboot; persistent trace%s\n", CDim(), CReset());
        printf("  %s         even if the kernel still reports HVCI on.%s\n", CDim(), CReset());
        exitCode = 2;
    }

    // ---- 3) BCD hypervisor off -----------------------------------------
    if (bcdOff) {
        printf("  %s[WARNING] BCD hypervisorlaunchtype = off.%s\n", CYellow(), CReset());
        printf("  %s          Hypervisor disabled at boot, so HVCI is inactive.%s\n", CDim(), CReset());
        if (exitCode < 1) exitCode = 1;
    }

    // ---- 4) Genuinely active & clean -----------------------------------
    if (queryOk && kernelHvci && hyperv && exitCode == 0) {
        printf("  %s[CLEAN] HVCI active and consistent with hypervisor presence.%s\n", CGreen(), CReset());
        printf("\n");
        Rule();
        printf("  Verdict: %s%sCLEAN%s\n", CBold(), CGreen(), CReset());
        Rule();
        return Finish(0);
    }

    // ---- 5) Kernel inactive: spoof-mismatch vs plain disabled ----------
    if (queryOk && !kernelHvci) {
        if (reg.keyPresent && reg.enabledPresent && reg.enabled == 1) {
            printf("  %s[WARNING] Registry Enabled=1 but kernel HVCI is NOT active.%s\n", CYellow(), CReset());
            printf("  %s          Spoof mismatch (e.g. hypervisor disabled behind the setting).%s\n", CDim(), CReset());
        } else if (reg.keyPresent) {
            printf("  %s[WARNING] HVCI is disabled (registry Enabled=0/absent, kernel inactive).%s\n", CYellow(), CReset());
        } else {
            bool wmiOk = false, vbsRunning = false;
            WmiVbsStatus(&wmiOk, &vbsRunning);
            if (wmiOk && !vbsRunning) {
                printf("  %s[WARNING] Registry key removed; WMI reports VBS NOT running.%s\n", CYellow(), CReset());
                printf("  %s          Core Isolation disabled (key deletion is itself suspicious).%s\n", CDim(), CReset());
            } else if (wmiOk && vbsRunning) {
                printf("  %s[INFO] Registry key removed but WMI reports VBS running.%s\n", CDim(), CReset());
            } else {
                printf("  %s[WARNING] HVCI inactive and state could not be confirmed via WMI.%s\n", CYellow(), CReset());
            }
        }
        if (exitCode < 1) exitCode = 1;
    }

    // ---- 6) Kernel query itself failed ---------------------------------
    if (!queryOk && exitCode == 0) {
        printf("  %s[WARNING] Kernel HVCI query failed; state undetermined.%s\n", CYellow(), CReset());
        exitCode = 1;
    }

    printf("\n");
    Rule();
    printf("  Verdict: %s%s%s%s\n",
           CBold(),
           exitCode == 2 ? CRed() : exitCode == 1 ? CYellow() : CGreen(),
           exitCode == 2 ? "SEVERE (spoof / unlock trace)"
         : exitCode == 1 ? "WARNING (HVCI disabled or unverifiable)"
         :                 "CLEAN",
           CReset());
    Rule();
    return Finish(exitCode);
}
