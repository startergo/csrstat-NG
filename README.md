<<<<<<< HEAD
# csrstat-NG - Enhanced System Integrity Protection Status Tool

An enhanced version of Pike R. Alpha's original csrstat tool with improved accuracy, better formatting, and comprehensive third-party kext analysis.

## Features

- ✅ **Accurate SIP Flag Analysis** - Shows proper binary bit states (0/1) instead of bit values
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
```

## Usage

# csrstat-NG - Enhanced System Integrity Protection Status Tool

An enhanced version of Pike R. Alpha's original csrstat tool with improved accuracy, better formatting, and comprehensive third-party kext analysis.

## Features

- ✅ **Accurate SIP Flag Analysis** - Shows proper binary bit states (0/1) instead of bit values
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
```

## Usage

```bash
./csrstat
```

## Sample Output

```
csrstat v2.0 Copyright (c) 2015-2017 by Pike R. Alpha, 2017-2025 by Joss Brown, 2021-2025 by Startergo
System Integrity Protection value: (0x0000006f)
System Integrity Protection status: disabled

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
Third-Party Kext Loading Analysis:
======================================================
⚠️  SIP Status: PARTIAL - Untrusted kexts allowed (0x0000006f)
✅ Signed third-party kexts: ALLOWED
✅ Kext loading: SHOULD WORK (if properly signed)

🔍 Additional Boot Arguments for Unsigned Kexts:
   kext-dev-mode=1  (allows loading of unsigned/untrusted kexts)

📋 Recommended SIP Configurations for Third-Party Kexts:
   • SECURE:     csrutil enable --without kext      (0x00000001)
   • BALANCED:   csrutil enable --without kext --without debug (0x00000005)
   • PERMISSIVE: csrutil disable                     (0x0000006f/0x0000007f)
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

Please note that csrstat reads the active SIP configuration directly from the kernel via syscall, not from the NVRAM variable (csr-active-config), as it should. The NVRAM variable is only applied after a reboot.

## Version History

- **v2.0** (2025) - Enhanced accuracy, generic kext analysis, Apple source alignment
- **v1.x** (2021) - Startergo's Big Sur compatibility updates
- **v1.x** (2017-2018) - Joss Brown enhancements
- **v1.0** (2015-2017) - Pike R. Alpha original version

## Credits

- **Original Author**: Pike R. Alpha (2015-2017)
- **Enhanced by**: Joss Brown (2017-2018)  
- **Further Enhanced by**: Startergo (2021-2025)
- **Apple XNU Reference**: [Darwin XNU Kernel Source](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/csr.h)

## License

This tool is provided as-is for educational and diagnostic purposes.

## Sample Output

```
csrstat v2.0 Copyright (c) 2015-2017 by Pike R. Alpha, 2017-2025 by Joss Brown, 2021-2025 by Startergo
System Integrity Protection value: (0x0000006f)
System Integrity Protection status: disabled

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
Third-Party Kext Loading Analysis:
======================================================
⚠️  SIP Status: PARTIAL - Untrusted kexts allowed (0x0000006f)
✅ Signed third-party kexts: ALLOWED
✅ Kext loading: SHOULD WORK (if properly signed)

🔍 Additional Boot Arguments for Unsigned Kexts:
   kext-dev-mode=1  (allows loading of unsigned/untrusted kexts)

📋 Recommended SIP Configurations for Third-Party Kexts:
   • SECURE:     csrutil enable --without kext      (0x00000001)
   • BALANCED:   csrutil enable --without kext --without debug (0x00000005)
   • PERMISSIVE: csrutil disable                     (0x0000006f/0x0000007f)
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

Please note that csrstat reads the active SIP configuration directly from the kernel via syscall, not from the NVRAM variable (csr-active-config), as it should. The NVRAM variable is only applied after a reboot.

## Version History

- **v2.0** (2025) - Enhanced accuracy, generic kext analysis, Apple source alignment
- **v1.x** (2021) - Startergo's Big Sur compatibility updates
- **v1.x** (2017-2018) - Joss Brown enhancements
- **v1.0** (2015-2017) - Pike R. Alpha original version

## Credits

- **Original Author**: Pike R. Alpha (2015-2017)
- **Enhanced by**: Joss Brown (2017-2018)  
- **Further Enhanced by**: Startergo (2021-2025)
- **Apple XNU Reference**: [Darwin XNU Kernel Source](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/csr.h)

## License

This tool is provided as-is for educational and diagnostic purposes.
=======
Update of Pike R. Alpha's original `csrstat` CLI with support for Big Sur's XNU v7195.121.3

You can run the csrstat tool by entering:
```
./csrstat
```
Here's an example of the output (latest version):
```
csrstat v2.0 Copyright (c) 2015-2017 by Pike R. Alpha, 2017-2018 by Joss Brown, 2021 by Startergo
System Integrity Protection value: (0x00000a6f) System Integrity Protection status: disabled

Current Configuration:
	Kext Signing			1 (disabled)	[--without kext]	CSR_ALLOW_UNTRUSTED_KEXTS
	Filesystem Protections		1 (disabled)	[--without fs]		CSR_ALLOW_UNRESTRICTED_FS
	Debugging Restrictions		1 (disabled)	[--without debug]	CSR_ALLOW_TASK_FOR_PID
	Kernel Debugging Restrictions	1 (disabled)	<n/a>			CSR_ALLOW_KERNEL_DEBUGGER
	Apple Internal			0 (disabled)	[--no-internal]		CSR_ALLOW_APPLE_INTERNAL
	DTrace Restrictions		1 (disabled)	[--without dtrace]	CSR_ALLOW_UNRESTRICTED_DTRACE
	NVRAM Protections		1 (disabled)	[--without nvram]	CSR_ALLOW_UNRESTRICTED_NVRAM
	Device Configuration		0 (disabled)	<n/a>			CSR_ALLOW_DEVICE_CONFIGURATION
	BaseSystem Verification		0 (disabled)	[--without basesystem]	CSR_ALLOW_ANY_RECOVERY_OS
	Unapproved Kexts Restrictions	1 (disabled)	<n/a>			CSR_ALLOW_UNAPPROVED_KEXTS
	Executable Policy		0 (enabled)	<n/a>			CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE
	Unauthenticated Root		1 (disabled)	[authenticated-root disable]	CSR_ALLOW_UNAUTHENTICATED_ROOT

Boot into Recovery Mode and modify with: 'csrutil enable [arguments]' or 'csrutil authenticated-root disable'
<Note: some flags are not accessible using the csrutil CLI.>
```
Please note that csrstat ignores the NVRAM variable (csr-active-config), as it should, because that is only valid after a reboot.
>>>>>>> 3419a5bb2f4ed643560e3a4d498b1d9727577306
