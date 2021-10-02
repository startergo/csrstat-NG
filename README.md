Update of Pike R. Alpha's original `csrstat` CLI with support for Big Sur's XNU v7195.121.3

You can run the csrstat tool by entering:
```
./csrstat
```
Here's an example of the output (latest version):
```
csrstat v2.0 Copyright (c) 2015-2017 by Pike R. Alpha, 2017-2018 by Joss Brown 2021 by Startergo
System Integrity Protection status: enabled (0x00000000)

Current Configuration:
	Apple Internal			0 (disabled)	[--no-internal]			CSR_ALLOW_APPLE_INTERNAL
	Kext Signing			0 (enabled)	[--without kext]		CSR_ALLOW_UNTRUSTED_KEXTS
	Debugging Restrictions		0 (enabled)	[--without debug]		CSR_ALLOW_TASK_FOR_PID
	Filesystem Protections		0 (enabled)	[--without fs]			CSR_ALLOW_UNRESTRICTED_FS
	Kernel Debugging Restrictions	0 (enabled)	<n/a>				CSR_ALLOW_KERNEL_DEBUGGER
	DTrace Restrictions		0 (enabled)	[--without dtrace]		CSR_ALLOW_UNRESTRICTED_DTRACE
	NVRAM Protections		0 (enabled)	[--without nvram]		CSR_ALLOW_UNRESTRICTED_NVRAM
	Device Configuration		0 (disabled)	<n/a>				CSR_ALLOW_DEVICE_CONFIGURATION
	BaseSystem Verification		0 (enabled)	[--without basesystem]		CSR_ALLOW_ANY_RECOVERY_OS
	Unapproved Kexts Restrictions	0 (enabled)	<n/a>				CSR_ALLOW_UNAPPROVED_KEXTS
	Executable Policy		0 (enabled)	<n/a>				CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE
	Unauthenticated Root            0 (enabled)     [authenticated-root disable] 	CSR_ALLOW_UNAUTHENTICATED_ROOT

Boot into Recovery Mode and modify with: 'csrutil enable [arguments]'
<Note: some flags are not accessible using the csrutil CLI.>
```
Please note that csrstat ignores the NVRAM variable (csr-active-config), as it should, because that is only valid after a reboot.
