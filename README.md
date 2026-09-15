# Core Isolation Spoof Detector

A tiny, dependency-free Windows tool that detects **HVCI / Core Isolation
(Memory Integrity) spoofing** — a technique cheats and rootkits use to load
unsigned kernel drivers (BYOVD) while still telling anti-cheats that Memory
Integrity is switched on.

Made by **MasonJacK**. MIT licensed. Drop it into any anti-cheat, EDR, or
forensic pipeline.

## The idea in one line

> The kernel says **HVCI is ON**, but `CPUID` says **there is no hypervisor**.
> That is impossible on a real system — so the kernel query is lying.

HVCI (Hypervisor-enforced Code Integrity) can only run inside the Hyper-V
hypervisor. Whether a hypervisor is present is reported by the **`CPUID`
instruction**, which runs directly on the CPU and cannot be hooked from user
mode. Meanwhile, anti-cheats usually read HVCI state from
`NtQuerySystemInformation(SystemCodeIntegrityInformation)` — which a malicious
kernel driver *can* hook. Cross-checking the two turns a hookable software query
into a hardware-anchored, near-zero-false-positive signal.

## What it checks

| Layer | Source | Meaning |
|-------|--------|---------|
| Kernel HVCI state | `NtQuerySystemInformation(103)` bit `0x400` | What the OS *claims* |
| Hypervisor present | `CPUID(1).ECX[31]` | Hardware ground truth |
| **Spoof** | kernel=ON **and** CPUID=absent | `NtQuerySystemInformation` hooked → **SEVERE** |
| Unlock trace | Registry `...\HypervisorEnforcedCodeIntegrity\Locked = 0` | HVCI can be turned off without reboot → **SEVERE** |
| Boot config | BCD `hypervisorlaunchtype = off` | Hypervisor disabled at boot → WARNING |
| Fallback | WMI `Win32_DeviceGuard.VirtualizationBasedSecurityStatus` | Used if the registry key was deleted |

## Build

Requires Visual Studio 2019+ with the *Desktop development with C++* workload.

```
build.bat
```

or manually:

```
cl /std:c++17 /O2 /EHsc /MT main.cpp /link advapi32.lib wbemuuid.lib ole32.lib oleaut32.lib
```

## Run

Run **as Administrator** (needed for the kernel query and HKLM reads):

```
coreiso_check.exe
```

Double-clicking the exe is fine — it detects a freshly-spawned console and
waits for Enter so the window does not vanish. Launching from an existing
`cmd` / PowerShell / CI pipeline does **not** pause (the pause only triggers
when the exe owns its console).

Output is a colored, boxed report (falls back to plain text on terminals that
do not support ANSI virtual terminal sequences).

Exit codes:

- `0` — CLEAN (HVCI active and consistent, or genuinely/expectedly off with no trace)
- `1` — WARNING (HVCI disabled, or state could not be verified)
- `2` — SEVERE (spoof paradox or HVCI-unlock trace)

## Notes & limitations

- The CPUID cross-check assumes a bare-metal host. **Inside a legitimate VM**
  the hypervisor bit is set, so the spoof paradox simply won't fire there — it
  never produces a false positive from virtualization, it just can't use that
  particular signal. The registry/BCD/WMI layers still apply.
- A determined attacker running their *own* hypervisor below the OS could fake
  CPUID too; defeating that requires a remote attestation / TPM measured-boot
  approach, which is out of scope for a single user-mode binary.
- This is a **detection** tool, not a fix. It reports state; it does not modify
  the system.

## License

MIT — see [LICENSE](LICENSE).
