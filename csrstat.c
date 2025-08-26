/*
 * Created: 23 August 2015
 * Name...: csrstat.c
 * Author.: Pike R. Alpha
 * Edited.: 30 September 2021
 * Author.: Startergo
 * Purpose: Command line tool for Big Sur to get the active SIP status.
 *
 * Compile with: cc csrstat.c -o csrstat
 *
 * Updates:
 *			-added full flags to output
 *			-added csrutil arguments to output
 *			-added CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE (xnu-4903.221.2)
 *			-added CSR_ALLOW_UNAUTHENTICATED_ROOT (xnu-7195.50.7.100.1)
 * See also: https://github.com/apple/darwin-xnu/blob/8f02f2a044b9bb1ad951987ef5bab20ec9486310/bsd/sys/csr.h
 */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <strings.h>

typedef uint32_t csr_config_t;

char *text = NULL;
double gVersion = 2.0;
csr_config_t config = 0;

/* Rootless configuration flags */
#define CSR_ALLOW_UNTRUSTED_KEXTS		(1 << 0)	// 1
#define CSR_ALLOW_UNRESTRICTED_FS		(1 << 1)	// 2
#define CSR_ALLOW_TASK_FOR_PID			(1 << 2)	// 4
#define CSR_ALLOW_KERNEL_DEBUGGER		(1 << 3)	// 8
#define CSR_ALLOW_APPLE_INTERNAL		(1 << 4)	// 16
#define CSR_ALLOW_UNRESTRICTED_DTRACE		(1 << 5)	// 32 
#define CSR_ALLOW_UNRESTRICTED_NVRAM		(1 << 6)	// 64
#define CSR_ALLOW_DEVICE_CONFIGURATION		(1 << 7)	// 128
#define CSR_ALLOW_ANY_RECOVERY_OS		(1 << 8)	// 256
#define CSR_ALLOW_UNAPPROVED_KEXTS		(1 << 9)	// 512
#define CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE	(1 << 10)	// 1024
#define CSR_ALLOW_UNAUTHENTICATED_ROOT          (1 << 11)       // 2048

#define CSR_VALID_FLAGS (CSR_ALLOW_UNTRUSTED_KEXTS | \
	CSR_ALLOW_UNRESTRICTED_FS | \
	CSR_ALLOW_TASK_FOR_PID | \
	CSR_ALLOW_KERNEL_DEBUGGER | \
	CSR_ALLOW_APPLE_INTERNAL | \
	CSR_ALLOW_UNRESTRICTED_DTRACE | \
	CSR_ALLOW_UNRESTRICTED_NVRAM  | \
	CSR_ALLOW_DEVICE_CONFIGURATION | \
	CSR_ALLOW_ANY_RECOVERY_OS | \
	CSR_ALLOW_UNAPPROVED_KEXTS | \
	CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE | \
	CSR_ALLOW_UNAUTHENTICATED_ROOT)

#define CSR_ALWAYS_ENFORCED_FLAGS (CSR_ALLOW_DEVICE_CONFIGURATION | CSR_ALLOW_ANY_RECOVERY_OS)

	/* Flags set by `csrutil disable`. 0x0000007F */
#define CSR_DISABLE_FLAGS (CSR_ALLOW_UNTRUSTED_KEXTS | \
	CSR_ALLOW_UNRESTRICTED_FS | \
	CSR_ALLOW_TASK_FOR_PID | \
	CSR_ALLOW_KERNEL_DEBUGGER | \
	CSR_ALLOW_APPLE_INTERNAL | \
	CSR_ALLOW_UNRESTRICTED_DTRACE | \
	CSR_ALLOW_UNRESTRICTED_NVRAM)

/* Flags set by `csrutil disable` at boot on Apple public devices. 0x0000006f */
#define CSR_DISABLE_FLAGS_APPLE (CSR_ALLOW_UNTRUSTED_KEXTS | \
	CSR_ALLOW_UNRESTRICTED_FS | \
	CSR_ALLOW_TASK_FOR_PID | \
	CSR_ALLOW_KERNEL_DEBUGGER | \
	CSR_ALLOW_UNRESTRICTED_DTRACE | \
	CSR_ALLOW_UNRESTRICTED_NVRAM)

/* Flags set by `0x0000026f`. */
#define CSR_DISABLE_FLAGS_26F (CSR_ALLOW_UNTRUSTED_KEXTS | \
	CSR_ALLOW_UNRESTRICTED_FS | \
	CSR_ALLOW_TASK_FOR_PID | \
	CSR_ALLOW_KERNEL_DEBUGGER | \
	CSR_ALLOW_UNRESTRICTED_DTRACE | \
	CSR_ALLOW_UNRESTRICTED_NVRAM | \
	CSR_ALLOW_UNAPPROVED_KEXTS)

/* Flags set by `0x00000A6f`. */
#define CSR_DISABLE_FLAGS_A6F (CSR_ALLOW_UNTRUSTED_KEXTS | \
	CSR_ALLOW_UNRESTRICTED_FS | \
	CSR_ALLOW_TASK_FOR_PID | \
	CSR_ALLOW_KERNEL_DEBUGGER | \
	CSR_ALLOW_UNRESTRICTED_DTRACE | \
	CSR_ALLOW_UNRESTRICTED_NVRAM | \
	CSR_ALLOW_UNAPPROVED_KEXTS  | \
	CSR_ALLOW_UNAUTHENTICATED_ROOT)

/* Syscalls - using weak linking for compatibility */
extern int csr_check(csr_config_t mask) __attribute__((weak));
extern int csr_get_active_config(csr_config_t *config) __attribute__((weak));

// CSR syscall wrapper with fallback
int get_csr_config(csr_config_t *config) {
    if (csr_get_active_config != NULL) {
        return csr_get_active_config(config);
    } else {
        // Fallback - assume SIP is enabled if we can't get the config
        *config = 0;
        return -1;
    }
}

//==============================================================================

char * _csr_check(int aMask, bool show_protection_status)
{
	uint32_t bit_value = (config & aMask);
	bool bit_set = bit_value ? true : false;

	if (show_protection_status)
	{
		// We want to show whether the PROTECTION is enabled or disabled
		// If the CSR_ALLOW_* bit is SET, then the protection is DISABLED
		// If the CSR_ALLOW_* bit is NOT SET, then the protection is ENABLED
		if (bit_set)
		{
			sprintf(text, "1 (disabled)");
		}
		else
		{
			sprintf(text, "0 (enabled)");
		}
	}
	else
	{
		// We want to show whether the ALLOW flag is set or not
		if (bit_set)
		{
			sprintf(text, "1 (allowed)");
		}
		else
		{
			sprintf(text, "0 (blocked)");
		}
	}

	return text;
}

//==============================================================================

int main(int argc, const char * argv[])
{
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	text = malloc(32);  // Increased buffer size to prevent overflow
	bzero(text, 32);
	
	// Syscall
	get_csr_config(&config);

	printf("csrstat v%.1f Copyright (c) 2015-2017 by Pike R. Alpha, 2017-%d by Joss Brown, 2021-%d by Startergo\n", gVersion, (tm.tm_year + 1900), (tm.tm_year + 1900));
	//
	// Current 'csrutil disable' values:
	// - Internal/Dev systems: 0x7F (CSR_DISABLE_FLAGS)
	// - Public Apple devices: 0x6F (CSR_DISABLE_FLAGS_APPLE)
	// - Custom configurations: Various combinations
	//
	printf("System Integrity Protection value: (0x%08x)\n", config);

	if (config == 0)
	{
		printf("System Integrity Protection status: enabled\n");
	}
	else if (config == CSR_DISABLE_FLAGS_APPLE)
	{
		printf("System Integrity Protection status: disabled\n");
	}
	else if (config == CSR_DISABLE_FLAGS)
	{
		printf("System Integrity Protection status: disabled (Apple Internal)\n");
	}
	else if (config == CSR_DISABLE_FLAGS_26F)
	{
		printf("System Integrity Protection status: disabled\n");	
	}
	else if (config == CSR_DISABLE_FLAGS_A6F)
	{
		printf("System Integrity Protection status: disabled\n");	
	}
	else 
	{
		printf("System Integrity Protection status: unknown (Custom Configuration)\n");
	}

	printf("\n\nCurrent Configuration:\n");


	printf("\tKext Signing                    %s\t[--without kext]\n", _csr_check(CSR_ALLOW_UNTRUSTED_KEXTS, true));
	printf("\tFilesystem Protections          %s\t[--without fs]\n", _csr_check(CSR_ALLOW_UNRESTRICTED_FS, true));
	printf("\tDebugging Restrictions          %s\t[--without debug]\n", _csr_check(CSR_ALLOW_TASK_FOR_PID, true));
	printf("\tKernel Debugging Restrictions   %s\t[included with debug]\n", _csr_check(CSR_ALLOW_KERNEL_DEBUGGER, true));
	printf("\tApple Internal                  %s\t[--no-internal/retail enforced]\n", _csr_check(CSR_ALLOW_APPLE_INTERNAL, true));
	printf("\tDTrace Restrictions             %s\t[--without dtrace]\n", _csr_check(CSR_ALLOW_UNRESTRICTED_DTRACE, true));
	printf("\tNVRAM Protections               %s\t[--without nvram]\n", _csr_check(CSR_ALLOW_UNRESTRICTED_NVRAM, true));
	printf("\tDevice Configuration            %s\t[always enforced]\n", _csr_check(CSR_ALLOW_DEVICE_CONFIGURATION, true));
	printf("\tBaseSystem Verification         %s\t[always enforced]\n", _csr_check(CSR_ALLOW_ANY_RECOVERY_OS, true));
	printf("\tUnapproved Kexts Restrictions   %s\t[internal only]\n", _csr_check(CSR_ALLOW_UNAPPROVED_KEXTS, true));
	printf("\tExecutable Policy               %s\t[internal only]\n", _csr_check(CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE, true));
	printf("\tUnauthenticated Root            %s\t[authenticated-root disable]\n", _csr_check(CSR_ALLOW_UNAUTHENTICATED_ROOT, true));
	printf("\nBoot into Recovery Mode and modify with: 'csrutil enable [arguments]' or 'csrutil authenticated-root disable'\n");
	printf("<Note: some flags are not accessible using the csrutil CLI.>\n");
	
	// Third-party Kext Loading Analysis
	printf("\n======================================================\n");
	printf("Third-Party Kext Loading Analysis:\n");
	printf("======================================================\n");
	
	bool kext_signing_disabled = (config & CSR_ALLOW_UNTRUSTED_KEXTS);
	bool unapproved_kexts_allowed = (config & CSR_ALLOW_UNAPPROVED_KEXTS);
	
	if (config == 0) {
		printf("❌ SIP Status: FULLY ENABLED (0x%08x)\n", config);
		printf("❌ Third-party kexts: BLOCKED\n");
		printf("❌ Kext loading: WILL FAIL\n");
		printf("\n🔧 SOLUTION: Boot into Recovery Mode and run:\n");
		printf("   csrutil enable --without kext\n");
		printf("   (This sets csr-active-config to 0x00000001)\n");
	}
	else if (kext_signing_disabled && !unapproved_kexts_allowed) {
		printf("⚠️  SIP Status: PARTIAL - Untrusted kexts allowed (0x%08x)\n", config);
		printf("✅ Signed third-party kexts: ALLOWED\n");  
		printf("✅ Kext loading: SHOULD WORK (if properly signed)\n");
	}
	else if (kext_signing_disabled && unapproved_kexts_allowed) {
		printf("✅ SIP Status: KEXT-FRIENDLY (0x%08x)\n", config);
		printf("✅ All third-party kexts: ALLOWED\n");
		printf("✅ Kext loading: SHOULD WORK\n");
	}
	else if (!kext_signing_disabled && unapproved_kexts_allowed) {
		printf("⚠️  SIP Status: UNUSUAL CONFIGURATION (0x%08x)\n", config);
		printf("⚠️  Unapproved kexts allowed but signing still enforced\n");
		printf("❓ Kext loading: MAY WORK (depends on signature)\n");
	}
	else {
		printf("❌ SIP Status: RESTRICTIVE (0x%08x)\n", config);
		printf("❌ Third-party kexts: LIMITED OR BLOCKED\n");
		printf("❌ Kext loading: MAY FAIL\n");
	}
	
	printf("\n🔍 Additional Boot Arguments for Unsigned Kexts:\n");
	printf("   kext-dev-mode=1  (allows loading of unsigned/untrusted kexts)\n");
	printf("   Check with: nvram boot-args\n");
	
	printf("\n📋 Recommended SIP Configurations for Third-Party Kexts:\n");
	printf("   • SECURE:     csrutil enable --without kext      (0x00000001)\n");
	printf("   • BALANCED:   csrutil enable --without kext --without debug (0x00000005)\n");
	printf("   • PERMISSIVE: csrutil disable                     (0x0000006f/0x0000007f)\n");

	if (config && (config & CSR_ALLOW_APPLE_INTERNAL))
	{
		printf("\nApple Internal. This is an unsupported configuration, likely to break in the future and leave your machine in an unknown state.\n");
	}
	if (text)
	{
		free(text);
	}
	exit(-1);
}
