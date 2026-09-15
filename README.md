# Kernel-HVCI-Spoof-Detection
Detects Windows Core Isolation / HVCI spoofing by cross-checking the kernel's HVCI status against the CPUID hypervisor-present bit. If the OS says HVCI is on but the CPU says no hypervisor is running, NtQuerySystemInformation is hooked.
