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
