# csrstat-NG - Enhanced System Integrity Protection Status Tool

An enhanced version of Pike R. Alpha's original csrstat tool with improved accuracy, better formatting, and comprehensive third-party kext analysis.

## Features

- ✅ **Accurate SIP Flag Analysis** - Shows proper binary bit states (0/1) 
- ✅ **Apple Source Code Accurate** - Definitions match Apple's official XNU kernel implementation
- ✅ **Enhanced Flag Descriptions** - Proper categorization of always-enforced, retail-enforced, and internal-only flags
- ✅ **Third-Party Kext Analysis** - Comprehensive analysis for any third-party kext loading requirements
- ✅ **csrutil Command Reference** - Shows exact csrutil commands for each protection
- ✅ **Clean Output Formatting** - Properly aligned columns for easy reading

## Compilation

```bash
# Standard compilation
cc csrstat.c -o csrstat

# If you encounter SDK issues on ARM64 systems:
cc -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk csrstat.c -o csrstat

# Cross-compile for specific architecture:
cc -arch x86_64 -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk csrstat.c -o csrstat-x86_64
cc -arch arm64 -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk csrstat.c -o csrstat-arm64

# Universal binary (works on both Intel and Apple Silicon):
cc -arch arm64 -arch x86_64 -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk csrstat.c -o csrstat-universal
```

## Usage

```bash
./csrstat
```

## Sample Output

```
csrstat v2.0 Copyright (c) 2015-2017 by Pike R. Alpha, 2017-2025 by Joss Brown, 2021-2025 by Startergo
Enhanced with accurate SIP analysis based on Khronokernel research
Reference: https://github.com/khronokernel/What-is-SIP

✅ Successfully queried SIP status via csr_get_active_config()
System Integrity Protection value: (0x0000006f)
System Integrity Protection status: disabled (Recovery Mode)
Configuration Method: Recovery Mode 'csrutil disable'
Note: This is the standard disabled configuration on retail hardware

Current Configuration:
        Kext Signing                    1 (disabled)    [--without kext]
        Filesystem Protections          1 (disabled)    [--without fs]
        Debugging Restrictions          1 (disabled)    [--without debug]
        Kernel Debugging Restrictions   1 (disabled)    [included with debug]
        Apple Internal                  0 (enabled)     [--no-internal/retail enforced]
        DTrace Restrictions             1 (disabled)    [--without dtrace]
        NVRAM Protections               1 (disabled)    [--without nvram]
        Device Configuration            0 (enabled)     [always enforced]
        BaseSystem Verification         0 (enabled)     [always enforced]
        Unapproved Kexts Restrictions   0 (enabled)     [internal only]
        Executable Policy               0 (enabled)     [internal only]
        Unauthenticated Root            0 (enabled)     [authenticated-root disable]

======================================================
Enhanced SIP Capability Analysis:
======================================================
🔐 Root Filesystem Modification: ✅ ALLOWED
🔧 Unsigned Kext Loading: ✅ ALLOWED  
🐛 Kernel Debugging: ✅ ALLOWED
💾 NVRAM/Device Tree Modification: ✅ ALLOWED
🍎 Apple Internal Status: ✅ NORMAL (expected on retail hardware)

======================================================
Third-Party Kext Loading Analysis:
======================================================
⚠️  SIP Status: PARTIAL - Untrusted kexts allowed (0x0000006f)
✅ Signed third-party kexts: ALLOWED
✅ Kext loading: SHOULD WORK (if properly signed)

📋 Recommended SIP Configurations for Third-Party Kexts:
   • SECURE:     csrutil enable --without kext      (0x00000001)
   • BALANCED:   csrutil enable --without kext --without debug (0x00000005)
   • PERMISSIVE: csrutil disable                     (0x0000006f on retail hardware)
```

## Key Improvements

### Accurate Flag Representation
- Shows binary bit states (0/1) instead of confusing bit values (1, 2, 4, 8, etc.)
- Proper "enabled/disabled" status for each protection

### Apple Source Accurate
- Flag definitions match Apple's official XNU kernel source
- Proper categorization of always-enforced flags
- Retail vs. development device distinctions

### Enhanced Descriptions
- `[always enforced]` - Cannot be disabled (Device Configuration, BaseSystem Verification)
- `[--no-internal/retail enforced]` - Available on dev machines, enforced on retail
- `[internal only]` - Not exposed in public csrutil interface
- `[included with debug]` - Bundled with other debug flags

### Universal Kext Analysis
- Works with any third-party kext (not just specific drivers)
- Comprehensive loading analysis based on SIP configuration
- Clear recommendations for different security levels

## Technical Notes

### CSR Configuration Storage by Architecture

Based on Apple's XNU kernel source analysis:

- **Intel Systems**: Configuration stored in NVRAM variable `csr-active-config` and read via boot arguments
- **Apple Silicon**: Configuration read via `lp-sip0` entry in the Device Tree (`lp-sip1`, `lp-sip2` for additional flags) under `/chosen/asmb` - **NO NVRAM usage**

The kernel code shows this clearly:
```c
// Apple Silicon - Device Tree lookup
if (SecureDTLookupEntry(0, "/chosen/asmb", &entry) == kSuccess &&
    _csr_get_dt_uint64(&entry, "lp-sip0", &uint64_value)) {
    csr_config = (uint32_t)uint64_value;    // Currently only 32 bits used.
    config_active = true;
}
```

### Dynamic Kernel Behavior

The kernel includes sophisticated logic that dynamically enables `CSR_ALLOW_KERNEL_DEBUGGER` when other debugging flags are present:

```c
// From XNU kernel source
if ((config & (CSR_ALLOW_UNTRUSTED_KEXTS | CSR_ALLOW_APPLE_INTERNAL)) != 0) {
    config |= CSR_ALLOW_KERNEL_DEBUGGER;
}
```

This explains why kernel debugging appears enabled even when not explicitly set.

### Apple Internal Bit Handling

On retail hardware, the kernel automatically strips the Apple Internal bit:

```c
if (!_csr_is_iuou_or_iuos_device()) {
    csr_config &= ~CSR_ALLOW_APPLE_INTERNAL;
}
```

### Active Configuration Reading

csrstat reads the active SIP configuration directly from the kernel via syscall (`csr_get_active_config`), not from the stored configuration sources. The stored values (NVRAM on Intel, Device Tree on Apple Silicon) are only applied during boot and after a reboot.

## Version History

- **v2.0** (2025) - Enhanced accuracy, generic kext analysis, Apple source alignment
- **v1.x** (2021) - Startergo's Big Sur compatibility updates
- **v1.x** (2017-2018) - Joss Brown enhancements
- **v1.0** (2015-2017) - Pike R. Alpha original version

## Credits

- **Original Author**: Pike R. Alpha (2015-2017)
- **Enhanced by**: Joss Brown (2017-2018)  
- **Further Enhanced by**: Startergo (2021-2025)
- **Kernel Source Research**: Analysis based on Apple's XNU kernel implementation
- **SIP Research Reference**: [Khronokernel's SIP Documentation](https://github.com/khronokernel/What-is-SIP)
- **Apple XNU Reference**: [Darwin XNU Kernel Source](https://github.com/apple-oss-distributions/xnu)

## License

This tool is provided as-is for educational and diagnostic purposes.
