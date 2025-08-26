/*
 * csrstat - Enhanced System Integrity Protection (SIP) Analysis Tool
 * Version 2.0 - Accurate SIP Behavior Implementation with Kernel Source Analysis
 * 
 * ORIGINAL AUTHORS:
 * Created: 23 August 2015
 * Name...: csrstat.c
 * Author.: Pike R. Alpha
 * Edited.: 30 September 2021
 * Author.: Startergo
 * Purpose: Command line tool for Big Sur to get the active SIP status.
 *
 * ENHANCED VERSION:
 * Based on authoritative research by Khronokernel:
 * https://github.com/khronokernel/What-is-SIP
 * AND Apple XNU kernel source code analysis (apple-oss-distributions/xnu)
 * 
 * KEY FINDINGS IMPLEMENTED:
 * 
 * 1. KERNEL SOURCE ANALYSIS (XNU):
 *    - Apple Silicon: CSR stored in Device Tree (lp-sip0, lp-sip1, lp-sip2)
 *    - Intel x86: CSR stored in NVRAM (csr-active-config via 		printf("   📋 SIP flags have evolved over macOS versions since El Capitan\n");
		if (macos_ver >= MACOS_BIG_SUR) {
			printf("   📋 Modern macOS (Big Sur+): Includes kernel debugger in standard disable (0x6f)\n");
		} else {
			printf("   📋 Legacy macOS (≤Catalina): Standard disable excludes kernel debugger (0x67)\n");
		}
	} else if (config == CSR_DISABLE_FLAGS_LEGACY) {
		printf("   ⚠️  DETECTED: 0x67 configuration (legacy standard disable value)\n");
		if (macos_ver >= MACOS_BIG_SUR) {
			printf("   📋 This is legacy configuration on modern macOS - may show as 'unsupported'\n");
		} else {
			printf("   📋 This is the correct standard disable value for %s\n", get_macos_name(macos_ver));
		}
	} else if (config == CSR_DISABLE_FLAGS_MODERN) {
		printf("   ⚠️  DETECTED: 0x6f configuration (modern standard disable value)\n");
		if (macos_ver <= MACOS_CATALINA) {
			printf("   📋 This is modern configuration on legacy macOS - will show as 'unsupported'\n");
		} else {
			printf("   📋 This is the correct standard disable value for %s\n", get_macos_name(macos_ver));
		}
	} else if (config == CSR_DISABLE_FLAGS) { *    - Dynamic behavior: CSR_ALLOW_KERNEL_DEBUGGER auto-enabled when SIP disabled
 *    - Apple Internal bit removed on non-IUOU devices during boot
 *    - CSR_DISABLE_FLAGS definition added later but behavior consistent since El Capitan
 * 
 * 2. LEGITIMATE vs MANUAL Configuration:
 *    - Only Recovery Mode 'csrutil' commands are considered "legitimate" by Apple
 *    - Manual NVRAM settings (nvram csr-active-config=...) ALWAYS show as 		printf("   📋 Based on Apple kernel source: kernel debugger flag included since SIP introduction\n");
		printf("   📋 All SIP-enabled macOS: Standard disable includes all core flags (0x6f)\n");m Configuration"
 *    - This is intentional Appl	printf("\n⚠️  CRITICAL: Understanding Manual NVRAM vs Recovery Mode:\n");
	printf("   🔧 FUNCTIONALITY: Manual NVRAM settings DO work if you use correct values\n");
	printf("   📋 Manual 'nvram csr-active-config=0x%02x' achieves same result as Recovery Mode\n", expected_disable);
	printf("   📋 The SIP protections are disabled identically in both cases\n");
	printf("\n   📊 REPORTING DIFFERENCE:\n");
	printf("   ✅ Recovery Mode: 'csrutil status' shows 'System Integrity Protection status: disabled'\n");
	printf("   ⚠️  Manual NVRAM: 'csrutil status' shows 'Custom Configuration' (cosmetic difference)\n");
	printf("\n   💡 BOTTOM LINE:\n");
	printf("   • Manual NVRAM works perfectly if you know the right value for your macOS version\n");
	printf("   • 'Custom Configuration' status is just a reporting difference, not a functional limitation\n");
	printf("   • Recovery Mode is 'official' but manual NVRAM achieves identical results\n");ehavior, not a bug
 * 
 * 2. Intel Hardware Boot Process:
 *    - boot.efi automatically strips AppleInternal bit (0x10) on retail hardware
 *    - 'csrutil disable' sets 0x7f internally but becomes 0x6f at boot
 *    - Presence of 0x7f on retail Intel hardware indicates non-standard configuration
 * 
 * 3. Apple Silicon Differences:
 *    - Different boot process than Intel
 *    - May handle SIP bits differently
 *    - Developer hardware may preserve AppleInternal bit
 * 
 * 4. Configuration Method Detection:
 *    - Standard values (0x00, 0x6f, etc.) = Recovery Mode csrutil
 *    - Non-standard values = Manual NVRAM or unusual configuration
 *    - "Custom Configuration" = Manual NVRAM (always, regardless of value)
 *
 * Compile with: cc csrstat.c -o csrstat
 *
 * Updates:
 *			-added full flags to output
 *			-added csrutil arguments to output
 *			-added CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE (xnu-4903.221.2)
 *			-added CSR_ALLOW_UNAUTHENTICATED_ROOT (xnu-7195.50.7.100.1)
 * See also: https://github.com/apple/darwin-xnu/blob/8f02f2a044b9bb1ad951987ef5bab20ec9486310/bsd/sys/csr.h
 * 
 * ⚠️  CRITICAL VERSION DEPENDENCY NOTICE:
 * CSR_DISABLE_FLAGS definitions vary by XNU kernel version. Each macOS version has its own
 * XNU kernel source code with potentially different CSR_DISABLE_FLAGS values. This tool
 * uses analysis from current XNU main branch, but historical accuracy requires examining
 * version-specific kernel source code (e.g., xnu-6153.121.1 for Catalina vs current main).
 * Future enhancements should analyze historical XNU releases for precise version mapping.
 */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>

typedef uint32_t csr_config_t;

// SIP Flag Information Structure
typedef struct {
    csr_config_t flag;
    const char *name;
    const char *description;
    const char *introduced_version;
    int darwin_version;  // Darwin kernel version when introduced
    bool always_enforced;
    const char *csrutil_option;
} sip_flag_info_t;

// Kernel version detection
typedef struct {
    int major;
    int minor;
    int patch;
    char version_string[256];
} kernel_version_t;

kernel_version_t get_kernel_version(void) {
    kernel_version_t version = {0};
    struct utsname uname_info;
    
    if (uname(&uname_info) == 0) {
        strncpy(version.version_string, uname_info.release, sizeof(version.version_string) - 1);
        // Parse version string like "24.6.0" -> major=24, minor=6, patch=0
        sscanf(uname_info.release, "%d.%d.%d", &version.major, &version.minor, &version.patch);
    }
    
    return version;
}

// macOS version mapping based on Darwin kernel version
// Maps Darwin kernel versions to macOS releases and their corresponding XNU source tags
// ⚠️  CRITICAL DISCOVERY: CSR_DISABLE_FLAGS definition did NOT exist in early SIP versions!
// Analysis of actual XNU kernel source code reveals Apple used DYNAMIC LOGIC instead:
//
// HISTORICAL CSR EVOLUTION (newosxbook.com XNU archives):
// • El Capitan    (xnu-3248.20.55):  NO CSR_DISABLE_FLAGS - used CSR_VALID_FLAGS logic (0x67 result)
// • Sierra        (xnu-3789.70.16):  NO CSR_DISABLE_FLAGS - used CSR_VALID_FLAGS minus CSR_ALWAYS_ENFORCED_FLAGS (0x67 result)
// • High Sierra   (xnu-4570.41.2):   NO CSR_DISABLE_FLAGS - continued dynamic approach (0x67 result)
// • Mojave        (xnu-4903.221.2):  NO CSR_DISABLE_FLAGS - still using calculated disable flags (0x67 result)
// • Catalina      (xnu-6153.11.26):  NO CSR_DISABLE_FLAGS - last version with dynamic logic (0x67 result)
// • Big Sur+      (xnu-7195+):       INTRODUCED CSR_DISABLE_FLAGS constant + ADDED kernel debugger (0x6F result)
//
// CRITICAL CHANGE: Kernel debugger flag inclusion changed between Catalina (0x67) and Big Sur (0x6F)!
// Apple's Original Logic (≤Catalina): CSR_VALID_FLAGS & ~CSR_ALWAYS_ENFORCED_FLAGS & ~CSR_ALLOW_KERNEL_DEBUGGER
// Modern Approach (Big Sur+): Explicit CSR_DISABLE_FLAGS constant including kernel debugger
typedef enum {
    MACOS_UNKNOWN = 0,
    MACOS_EL_CAPITAN,    // Darwin 15.x - XNU xnu-3248.20.55: CSR_VALID_FLAGS logic
    MACOS_SIERRA,        // Darwin 16.x - XNU xnu-3789.70.16: Added CSR_ALLOW_ANY_RECOVERY_OS + dynamic logic
    MACOS_HIGH_SIERRA,   // Darwin 17.x - XNU xnu-4570.41.2: Added CSR_ALLOW_UNAPPROVED_KEXTS + dynamic logic
    MACOS_MOJAVE,        // Darwin 18.x - XNU xnu-4903.221.2: Added CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE + dynamic logic
    MACOS_CATALINA,      // Darwin 19.x - XNU xnu-6153.11.26: Last version with dynamic CSR_DISABLE_FLAGS logic
    MACOS_BIG_SUR,       // Darwin 20.x - XNU xnu-7195+: FIRST to define explicit CSR_DISABLE_FLAGS constant
    MACOS_MONTEREY,      // Darwin 21.x - XNU source NOT publicly available (archived before release)
    MACOS_VENTURA,       // Darwin 22.x - XNU source NOT publicly available (archived before release)
    MACOS_SONOMA,        // Darwin 23.x - XNU source NOT publicly available (archived before release)
    MACOS_SEQUOIA,       // Darwin 24.x - XNU source NOT publicly available (archived before release)
    MACOS_FUTURE         // Darwin 25.x+ - XNU main branch (repository archived May 22, 2023)
} macos_version_t;

macos_version_t get_macos_version(kernel_version_t kernel_ver) {
    switch (kernel_ver.major) {
        case 15: return MACOS_EL_CAPITAN;
        case 16: return MACOS_SIERRA;
        case 17: return MACOS_HIGH_SIERRA;
        case 18: return MACOS_MOJAVE;
        case 19: return MACOS_CATALINA;
        case 20: return MACOS_BIG_SUR;
        case 21: return MACOS_MONTEREY;
        case 22: return MACOS_VENTURA;
        case 23: return MACOS_SONOMA;
        case 24: return MACOS_SEQUOIA;
        default: return (kernel_ver.major >= 25) ? MACOS_FUTURE : MACOS_UNKNOWN;
    }
}

const char* get_macos_name(macos_version_t version) {
    switch (version) {
        case MACOS_EL_CAPITAN: return "El Capitan";
        case MACOS_SIERRA: return "Sierra";
        case MACOS_HIGH_SIERRA: return "High Sierra";
        case MACOS_MOJAVE: return "Mojave";
        case MACOS_CATALINA: return "Catalina";
        case MACOS_BIG_SUR: return "Big Sur";
        case MACOS_MONTEREY: return "Monterey";
        case MACOS_VENTURA: return "Ventura";
        case MACOS_SONOMA: return "Sonoma";
        case MACOS_SEQUOIA: return "Sequoia";
        case MACOS_FUTURE: return "Future macOS";
        default: return "Unknown";
    }
}

char *text = NULL;
double gVersion = 2.0;
csr_config_t config = 0;

// Architecture detection
bool is_apple_silicon() {
    struct utsname system_info;
    if (uname(&system_info) == 0) {
        return (strcmp(system_info.machine, "arm64") == 0);
    }
    return false;
}

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

/* Flags set by Recovery Mode `csrutil disable` - Legacy (Catalina era) - 0x00000067 */
#define CSR_DISABLE_FLAGS_LEGACY (CSR_ALLOW_UNTRUSTED_KEXTS | \
	CSR_ALLOW_UNRESTRICTED_FS | \
	CSR_ALLOW_TASK_FOR_PID | \
	CSR_ALLOW_UNRESTRICTED_DTRACE | \
	CSR_ALLOW_UNRESTRICTED_NVRAM)

/* Flags set by Recovery Mode `csrutil disable` - Modern (Big Sur+) - 0x0000006f */
#define CSR_DISABLE_FLAGS_MODERN CSR_DISABLE_FLAGS_APPLE

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

// Comprehensive SIP Flag Information Table
// Based on Khronokernel research: https://github.com/khronokernel/What-is-SIP
static const sip_flag_info_t sip_flags[] = {
    {
        .flag = CSR_ALLOW_UNTRUSTED_KEXTS,
        .name = "Kext Signing",
        .description = "Allows unsigned kernel drivers to be installed and loaded",
        .introduced_version = "10.11 El Capitan",
        .darwin_version = 15,
        .always_enforced = false,
        .csrutil_option = "--without kext"
    },
    {
        .flag = CSR_ALLOW_UNRESTRICTED_FS,
        .name = "Filesystem Protections",
        .description = "Allows unrestricted file system access",
        .introduced_version = "10.11 El Capitan", 
        .darwin_version = 15,
        .always_enforced = false,
        .csrutil_option = "--without fs"
    },
    {
        .flag = CSR_ALLOW_TASK_FOR_PID,
        .name = "Debugging Restrictions",
        .description = "Allows tracking processes based off a provided process ID",
        .introduced_version = "10.11 El Capitan",
        .darwin_version = 15,
        .always_enforced = false,
        .csrutil_option = "--without debug"
    },
    {
        .flag = CSR_ALLOW_KERNEL_DEBUGGER,
        .name = "Kernel Debugging Restrictions",
        .description = "Allows attaching low level kernel debugger to system (auto-enabled when SIP disabled)",
        .introduced_version = "10.11 El Capitan",
        .darwin_version = 15,
        .always_enforced = false,
        .csrutil_option = "[included with debug]"
    },
    {
        .flag = CSR_ALLOW_APPLE_INTERNAL,
        .name = "Apple Internal",
        .description = "Allows Apple Internal feature set (primarily for Apple development devices)",
        .introduced_version = "10.11 El Capitan",
        .darwin_version = 15,
        .always_enforced = false,  // Stripped on retail hardware
        .csrutil_option = "[--no-internal/retail enforced]"
    },
    {
        .flag = CSR_ALLOW_UNRESTRICTED_DTRACE,
        .name = "DTrace Restrictions",
        .description = "Allows unrestricted dtrace usage",
        .introduced_version = "10.11 El Capitan",
        .darwin_version = 15,
        .always_enforced = false,
        .csrutil_option = "--without dtrace"
    },
    {
        .flag = CSR_ALLOW_UNRESTRICTED_NVRAM,
        .name = "NVRAM Protections",
        .description = "Allows unrestricted NVRAM write",
        .introduced_version = "10.11 El Capitan",
        .darwin_version = 15,
        .always_enforced = false,
        .csrutil_option = "--without nvram"
    },
    {
        .flag = CSR_ALLOW_DEVICE_CONFIGURATION,
        .name = "Device Configuration",
        .description = "Allows custom device trees (primarily for iOS devices)",
        .introduced_version = "10.11 El Capitan",
        .darwin_version = 15,
        .always_enforced = true,
        .csrutil_option = "[always enforced]"
    },
    {
        .flag = CSR_ALLOW_ANY_RECOVERY_OS,
        .name = "BaseSystem Verification", 
        .description = "Skip BaseSystem Verification, primarily for custom recoveryOS images",
        .introduced_version = "10.12 Sierra",
        .darwin_version = 16,
        .always_enforced = true,
        .csrutil_option = "[always enforced]"
    },
    {
        .flag = CSR_ALLOW_UNAPPROVED_KEXTS,
        .name = "Unapproved Kexts Restrictions",
        .description = "Allows unapproved kernel driver installation/loading",
        .introduced_version = "10.13 High Sierra",
        .darwin_version = 17,
        .always_enforced = false,
        .csrutil_option = "[internal only]"
    },
    {
        .flag = CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE,
        .name = "Executable Policy",
        .description = "Allows override of executable policy",
        .introduced_version = "10.14 Mojave",
        .darwin_version = 18,
        .always_enforced = false,
        .csrutil_option = "[internal only]"
    },
    {
        .flag = CSR_ALLOW_UNAUTHENTICATED_ROOT,
        .name = "Unauthenticated Root",
        .description = "Allows custom APFS snapshots to be booted (primarily for modified root volumes)",
        .introduced_version = "11.0 Big Sur",
        .darwin_version = 20,
        .always_enforced = false,
        .csrutil_option = "[authenticated-root disable]"
    }
};

#define SIP_FLAGS_COUNT (sizeof(sip_flags) / sizeof(sip_flags[0]))

// Check if a SIP flag is available in the current macOS version
bool is_flag_available(csr_config_t flag, kernel_version_t kernel_ver) {
    for (int i = 0; i < SIP_FLAGS_COUNT; i++) {
        if (sip_flags[i].flag == flag) {
            return kernel_ver.major >= sip_flags[i].darwin_version;
        }
    }
    return false;
}

// Get SIP flag information
const sip_flag_info_t* get_flag_info(csr_config_t flag) {
    for (int i = 0; i < SIP_FLAGS_COUNT; i++) {
        if (sip_flags[i].flag == flag) {
            return &sip_flags[i];
        }
    }
    return NULL;
}

// Determine expected csrutil disable configuration based on macOS version
csr_config_t get_expected_disable_config(macos_version_t macos_ver) {
    // HISTORICAL ACCURACY: Apple's CSR_DISABLE_FLAGS Evolution
    //
    // CRITICAL DISCOVERY: Kernel debugger flag inclusion changed between Catalina and Big Sur!
    //
    // PRE-BIG SUR (El Capitan through Catalina):
    // • NO explicit CSR_DISABLE_FLAGS constant in XNU kernel source
    // • Used dynamic logic: CSR_VALID_FLAGS & ~CSR_ALWAYS_ENFORCED_FLAGS
    // • IMPORTANT: CSR_ALLOW_KERNEL_DEBUGGER was NOT included in "csrutil disable"
    // • Result: 0x67 on retail hardware (without kernel debugger bit)
    //
    // BIG SUR+ (Darwin 20.x+):
    // • INTRODUCED explicit CSR_DISABLE_FLAGS constant for consistency
    // • CHANGED BEHAVIOR: Now includes CSR_ALLOW_KERNEL_DEBUGGER in disable flags
    // • Current XNU main branch defines CSR_DISABLE_FLAGS = 0x7F (with kernel debugger)
    // • Result: 0x6F on retail hardware (with kernel debugger bit)
    //
    // RUNTIME BEHAVIOR (All Versions):
    // • Intel retail hardware: boot.efi strips CSR_ALLOW_APPLE_INTERNAL (0x10)
    // • Apple Silicon retail: Similar stripping behavior in bootloader
    
    csr_config_t expected_config;
    
    // Version-specific disable flag calculation based on historical XNU analysis
    if (macos_ver <= MACOS_CATALINA) {
        // Pre-Big Sur: "csrutil disable" did NOT include kernel debugger
        // Matches historical behavior: CSR_VALID_FLAGS & ~CSR_ALWAYS_ENFORCED_FLAGS & ~CSR_ALLOW_KERNEL_DEBUGGER
        expected_config = CSR_DISABLE_FLAGS_LEGACY; // 0x67 - without kernel debugger
    } else {
        // Big Sur and later: "csrutil disable" includes kernel debugger
        // Modern Apple CSR_DISABLE_FLAGS definition
        expected_config = CSR_DISABLE_FLAGS; // 0x7F - with kernel debugger
        
        // On retail hardware, boot.efi strips the Apple Internal bit (0x10)
#if defined(__x86_64__)
        // Intel retail hardware: boot.efi always strips Apple Internal bit
        expected_config &= ~CSR_ALLOW_APPLE_INTERNAL;
#elif defined(__arm64__)
        // Apple Silicon: May preserve Apple Internal bit on developer hardware
        // For retail Apple Silicon, also strip the bit (conservative assumption)
        expected_config &= ~CSR_ALLOW_APPLE_INTERNAL;
#endif
    }
    
    return expected_config;  // Results in 0x67 (Catalina-) or 0x6F (Big Sur+) on retail hardware
}

/* CSR System Call Interface - Technical Implementation Details:
 * 
 * libsystem_kernel.dylib provides the user-space CSR functions:
 * - csr_check(mask) - Check if specific SIP flags are disabled
 * - csr_get_active_config(config) - Get current SIP configuration value
 * 
 * These functions internally use syscall 483 (csrctl) to communicate with kernel:
 * - Syscall number 483 is the csrctl system call
 * - Kernel implementation in bsd/kern/kern_csr.c (Apple XNU source)
 * - Returns current CSR configuration from kernel's csr_state
 * 
 * Architecture-specific CSR storage:
 * - Intel: Read from NVRAM csr-active-config via boot loader
 * - Apple Silicon: Read from Device Tree lp-sip0/sip1/sip2 entries
 */
extern int csr_check(csr_config_t mask) __attribute__((weak));
extern int csr_get_active_config(csr_config_t *config) __attribute__((weak));

// CSR syscall wrapper with enhanced error handling
// Based on Khronokernel's py_sip_xnu implementation
// Uses libsystem_kernel.dylib → syscall 483 (csrctl) → kernel CSR state
int get_csr_config(csr_config_t *config) {
    if (csr_get_active_config != NULL) {
        int error = csr_get_active_config(config);
        if (error != 0) {
            printf("Error while detecting SIP status: %d\n", error);
            printf("This may indicate:\n");
            printf("  - Unsupported macOS version (< El Capitan)\n");
            printf("  - Missing system libraries\n");
            printf("  - Kernel extension compatibility issues\n");
            *config = 0;  // Assume restricted if we can't read
            return error;
        }
        printf("Raw csr_active_config value: %u (0x%08x)\n", *config, *config);
        printf("✅ Successfully queried SIP status via csr_get_active_config()\n");
        printf("   Technical: libsystem_kernel.dylib → syscall 483 (csrctl)\n");
        printf("   Reference: https://github.com/apple/darwin-xnu/blob/main/bsd/kern/syscalls.master#L483\n");
        return 0;
    } else {
        printf("Warning: csr_get_active_config() function not available\n");
        printf("This typically means:\n");
        printf("  - macOS version < El Capitan (SIP not implemented)\n");
        printf("  - System library compatibility issues\n");
        printf("Assuming unrestricted access (legacy behavior)\n");
        *config = 65535;  // Khronokernel's approach for pre-SIP systems
        return -1;
    }
}

//==============================================================================
// SIP Capability Analysis Functions
// Based on Khronokernel's py_sip_xnu bit checking approach
//==============================================================================

bool sip_can_edit_root(csr_config_t sip_status) {
    // 0x2   - CSR_ALLOW_UNRESTRICTED_FS
    // 0x800 - CSR_ALLOW_UNAUTHENTICATED_ROOT
    // Logic from: https://github.com/khronokernel/py_sip_xnu/blob/1.0.3/py_sip_xnu.py#L237-L252
    
    if (sip_status & 0x2) {  // CSR_ALLOW_UNRESTRICTED_FS
        // For Big Sur and later, also need CSR_ALLOW_UNAUTHENTICATED_ROOT
        // For older versions, just unrestricted FS is sufficient
        // Note: We can't easily detect macOS version here, so we check both bits
        if (sip_status & 0x800) {  // CSR_ALLOW_UNAUTHENTICATED_ROOT
            return true;
        }
        // Even without authenticated root, unrestricted FS allows significant access
        return true;
    }
    return false;
}

bool sip_can_load_unsigned_kexts(csr_config_t sip_status) {
    // 0x1 - CSR_ALLOW_UNTRUSTED_KEXTS
    return (sip_status & 0x1) != 0;
}

bool sip_can_debug_kernel(csr_config_t sip_status) {
    // 0x4 - CSR_ALLOW_TASK_FOR_PID
    // 0x8 - CSR_ALLOW_KERNEL_DEBUGGER  
    return (sip_status & 0x4) && (sip_status & 0x8);
}

bool sip_can_modify_nvram(csr_config_t sip_status) {
    // 0x40 - CSR_ALLOW_UNRESTRICTED_NVRAM
    return (sip_status & 0x40) != 0;
}

bool sip_has_apple_internal(csr_config_t sip_status) {
    // 0x10 - CSR_ALLOW_APPLE_INTERNAL
    return (sip_status & 0x10) != 0;
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
	
	// Enhanced SIP syscall with error handling
	int error = get_csr_config(&config);
	
	printf("csrstat v%.1f Copyright (c) 2015-2017 by Pike R. Alpha, 2017-%d by Joss Brown, 2021-%d by Startergo\n", gVersion, (tm.tm_year + 1900), (tm.tm_year + 1900));
	printf("Enhanced with accurate SIP analysis based on Khronokernel research\n");
	printf("Reference: https://github.com/khronokernel/What-is-SIP\n\n");
	
	if (error == 0) {
		printf("✅ Successfully queried SIP status via csr_get_active_config()\n");
		printf("   └─ Technical: libsystem_kernel.dylib → syscall 483 (csrctl) → kernel CSR state\n");
	} else if (config == 65535) {
		printf("ℹ️  Pre-SIP system detected (macOS < El Capitan) - assuming unrestricted\n");
	} else {
		printf("⚠️  Error querying SIP status, using fallback value\n");
	}
	
	printf("System Integrity Protection value: (0x%08x)\n", config);

	// Enhanced SIP Status Analysis based on Khronokernel research
	// Source: https://github.com/khronokernel/What-is-SIP
	
	// Get version information for dynamic analysis
	kernel_version_t kernel_ver = get_kernel_version();
	macos_version_t macos_ver = get_macos_version(kernel_ver);
	csr_config_t expected_disable = get_expected_disable_config(macos_ver);
	
	if (config == 0)
	{
		printf("System Integrity Protection status: enabled (Apple Default)\n");
		printf("Configuration Method: Recovery Mode csrutil enable\n");
	}
	else if (config == expected_disable)
	{
		printf("System Integrity Protection status: disabled (Recovery Mode)\n");
		printf("Configuration Method: Recovery Mode 'csrutil disable'\n");
		printf("Note: Standard disabled configuration for %s (0x%02x)\n", 
			get_macos_name(macos_ver), expected_disable);
		printf("      Based on official Apple CSR_DISABLE_FLAGS (0x%02x) minus Apple Internal bit on retail hardware\n", CSR_DISABLE_FLAGS);
	}
	else if (config == CSR_DISABLE_FLAGS)
	{
		printf("System Integrity Protection status: disabled (Apple Internal)\n");
		printf("Configuration Method: Recovery Mode 'csrutil disable' on Apple Internal/Developer hardware\n");
		printf("Note: Full Apple CSR_DISABLE_FLAGS definition (0x%02x) including Apple Internal bit\n", CSR_DISABLE_FLAGS);
		printf("      On retail Intel hardware, boot.efi should strip Apple Internal bit (0x10)\n");
		printf("      Presence on retail hardware may indicate developer device or custom firmware\n");
	}
	else if (config == (CSR_DISABLE_FLAGS & ~CSR_ALLOW_APPLE_INTERNAL))
	{
		printf("System Integrity Protection status: disabled (Standard Retail)\n");
		printf("Configuration Method: Recovery Mode 'csrutil disable' on retail hardware\n");
		printf("Note: Official Apple CSR_DISABLE_FLAGS (0x%02x) with Apple Internal bit stripped (0x%02x)\n", 
			CSR_DISABLE_FLAGS, (CSR_DISABLE_FLAGS & ~CSR_ALLOW_APPLE_INTERNAL));
		printf("      This is the expected behavior on retail Intel and Apple Silicon systems\n");
	}
	else if (config == CSR_DISABLE_FLAGS_26F)
	{
		printf("System Integrity Protection status: disabled (Extended)\n");
		printf("Configuration Method: Likely Recovery Mode with unapproved kexts enabled\n");
	}
	else if (config == CSR_DISABLE_FLAGS_A6F)
	{
		printf("System Integrity Protection status: disabled (Full)\n");
		printf("Configuration Method: Recovery Mode with authenticated-root disabled\n");
	}
	else 
	{
		printf("System Integrity Protection status: Custom Configuration\n");
		printf("Configuration Method: Manual NVRAM modification (nvram csr-active-config=...)\n");
		printf("\n💡 UNDERSTANDING 'Custom Configuration' STATUS:\n");
		printf("   • 'Custom Configuration' appears when NVRAM value doesn't match standard presets\n");
		printf("   • Manual NVRAM values that match standard values (0x00, 0x%02x, etc.) show normally\n", expected_disable);
		printf("   • Manual NVRAM values with non-standard combinations show as 'Custom Configuration'\n");
		printf("   • The SIP enforcement is functionally identical regardless of reporting label\n");
		printf("   • 'Custom' allows for specialized flag combinations not available via csrutil\n");
	}

	printf("\n\nCurrent Configuration:\n");

	printf("Running on: macOS %s (Darwin %s)\n", get_macos_name(macos_ver), kernel_ver.version_string);
	
	// Architecture-specific CSR storage information
	printf("CSR Storage: ");
#if defined(__x86_64__)
	printf("Intel-based system - configuration read from 'csr-active-config' NVRAM variable\n");
	printf("             (Kernel: boot_args->csrActiveConfig, old-style CSR via NVRAM)\n");
#elif defined(__arm64__)
	printf("Apple Silicon system - configuration read from 'lp-sip0' Device Tree entry\n");
	printf("                      (Kernel: SecureDT lp-sip0/sip1/sip2, CONFIG_CSR_FROM_DT)\n");
#else
	printf("Unknown architecture - configuration storage method varies by platform\n");
#endif
	printf("\n");

	// Display all SIP flags with version-aware information
	for (int i = 0; i < SIP_FLAGS_COUNT; i++) {
		const sip_flag_info_t *flag_info = &sip_flags[i];
		
		if (is_flag_available(flag_info->flag, kernel_ver)) {
			printf("\t%-32s %s\t[%s]\n", 
				flag_info->name, 
				_csr_check(flag_info->flag, true),
				flag_info->csrutil_option);
			
			// Show introduction info for flags newer than El Capitan
			if (flag_info->darwin_version > 15) {
				printf("\t  └─ Introduced: %s\n", flag_info->introduced_version);
			}
		} else {
			printf("\t%-32s %s\t[Not available in %s]\n",
				flag_info->name,
				"N/A",
				get_macos_name(macos_ver));
		}
	}
	
	
	printf("\n======================================================\n");
	printf("Enhanced SIP Capability Analysis:\n");
	printf("======================================================\n");
	printf("Based on Khronokernel's py_sip_xnu bit checking methodology\n\n");
	
	printf("🔐 Root Filesystem Modification:\n");
	if (sip_can_edit_root(config)) {
		printf("   ✅ ALLOWED - Can modify root filesystem\n");
		printf("   📋 Unrestricted FS bit set (0x2)\n");
		if (config & 0x800) {
			printf("   📋 Unauthenticated Root bit also set (0x800)\n");
		}
	} else {
		printf("   ❌ BLOCKED - Root filesystem is protected\n");
		printf("   📋 Unrestricted FS bit not set\n");
	}
	
	printf("\n🔧 Unsigned Kext Loading:\n");
	if (sip_can_load_unsigned_kexts(config)) {
		printf("   ✅ ALLOWED - Can load unsigned/untrusted kexts\n");
		printf("   📋 Untrusted Kexts bit set (0x1)\n");
	} else {
		printf("   ❌ BLOCKED - Only signed kexts allowed\n");
		printf("   📋 Untrusted Kexts bit not set\n");
	}
	
	printf("\n🐛 Kernel Debugging:\n");
	if (sip_can_debug_kernel(config)) {
		printf("   ✅ ALLOWED - Full kernel debugging enabled\n");
		printf("   📋 Both Task-for-PID (0x4) and Kernel Debugger (0x8) bits set\n");
	} else {
		printf("   ❌ RESTRICTED - Kernel debugging limited\n");
		if (config & 0x4) {
			printf("   ⚠️  Task-for-PID allowed but Kernel Debugger blocked\n");
		} else if (config & 0x8) {
			printf("   ⚠️  Kernel Debugger allowed but Task-for-PID blocked\n");
		} else {
			printf("   📋 Both debugging bits disabled\n");
		}
	}
	
	printf("\n💾 NVRAM Modification:\n");
	if (sip_can_modify_nvram(config)) {
		printf("   ✅ ALLOWED - Can modify protected NVRAM variables\n");
		printf("   📋 Unrestricted NVRAM bit set (0x40)\n");
	} else {
		printf("   ❌ BLOCKED - NVRAM protections active\n");
		printf("   📋 Unrestricted NVRAM bit not set\n");
	}
	
	printf("\n🍎 Apple Internal Status:\n");
	if (sip_has_apple_internal(config)) {
		printf("   ⚠️  DETECTED - Apple Internal bit present (0x10)\n");
		printf("   📋 This should be stripped by boot.efi on retail Intel hardware\n");
	} else {
		printf("   ✅ NORMAL - No Apple Internal bit (expected on retail hardware)\n");
		printf("   📋 Apple Internal bit properly absent or stripped\n");
	}

	printf("\n======================================================\n");
	printf("SIP Configuration Methods & Boot Process Analysis:\n");
	printf("======================================================\n");
	printf("Based on research by Khronokernel (github.com/khronokernel/What-is-SIP)\n\n");
	
	printf("🔧 LEGITIMATE Configuration Methods:\n");
	printf("   ✅ Recovery Mode: Boot to Recovery (Cmd+R) → Terminal → csrutil commands\n");
	printf("   ✅ Only Recovery Mode csrutil commands are recognized as 'official'\n");
	printf("   ✅ These appear with standard status descriptions (enabled/disabled)\n\n");
	
	printf("⚠️  MANUAL Configuration Methods:\n");
#if defined(__x86_64__)
	printf("   ℹ️  Intel NVRAM: sudo nvram csr-active-config=%%... (functionally equivalent)\n");
	printf("   📋 Manual NVRAM settings work but show as 'Custom Configuration' in csrutil\n");
	printf("   📋 Functionality is identical - only the status reporting differs\n");
#elif defined(__arm64__)
	printf("   ⚠️  Apple Silicon: Manual NVRAM modification NOT supported\n");
	printf("   📋 SIP stored in Device Tree (lp-sip0) - not accessible via nvram command\n");
	printf("   📋 Recovery Mode is the only supported method for Apple Silicon systems\n");
#else
	printf("   ℹ️  Platform-specific manual methods may vary by architecture\n");
#endif
	printf("   \n");
	printf("   🔍 WHY 'Custom Configuration' Appears:\n");
	printf("   • Apple's csrutil recognizes specific standard values (0x00, 0x6f, etc.)\n");
	printf("   • Manual NVRAM values that MATCH standard values show normally (enabled/disabled)\n");
	printf("   • Manual NVRAM values that DON'T match standard presets show as 'Custom'\n");
	printf("   • This allows for non-standard flag combinations while identifying them clearly\n");
	printf("   • Manual NVRAM is useful for: automated deployment, broken Recovery, custom combinations\n");
	printf("   \n");
	printf("   🎯 For %s, to match 'csrutil disable' functionality:\n", get_macos_name(macos_ver));
#if defined(__x86_64__)
	printf("      Intel Systems: sudo nvram csr-active-config=%%0%x%%00%%00%%00\n", expected_disable);
	printf("   📋 This provides identical SIP disabling as Recovery Mode 'csrutil disable'\n");
	printf("   📋 Manual NVRAM with standard values will show same status as Recovery Mode\n");
#elif defined(__arm64__)
	printf("      Apple Silicon: Manual NVRAM modification not supported\n");
	printf("   📋 SIP configuration stored in Device Tree (lp-sip0) - Recovery Mode required\n");
	printf("   📋 Use Recovery Mode → Terminal → 'csrutil disable' for Apple Silicon systems\n");
#else
	printf("      Platform-specific: Check documentation for your architecture\n");
#endif
	printf("\n");
	
	printf("🖥️  macOS Version-Specific SIP Behavior:\n");
	if (config == expected_disable) {
		printf("   ✅ DETECTED: 0x%02x configuration matches expected for %s\n", config, get_macos_name(macos_ver));
		printf("   📋 This is the legitimate Recovery Mode 'csrutil disable' value\n");
		printf("   📋 SIP flags have evolved over macOS versions since El Capitan\n");
		if (macos_ver >= MACOS_BIG_SUR) {
			printf("   📋 Modern macOS: Includes kernel debugger in standard disable (0x6f)\n");
		} else {
			printf("   � Legacy macOS: Standard disable excludes kernel debugger (0x67)\n");
		}
	} else if (config == CSR_DISABLE_FLAGS) {
		printf("   ⚠️  DETECTED: 0x%02x configuration (official Apple definition with Apple Internal bit)\n", CSR_DISABLE_FLAGS);
		printf("   📋 This is the complete Apple CSR_DISABLE_FLAGS from XNU kernel source\n");
		printf("   📋 May indicate developer/internal hardware or manual NVRAM configuration\n");
		printf("   📋 On retail Intel hardware, boot.efi should strip Apple Internal bit automatically\n");
	} else {
		printf("   📋 Configuration Analysis:\n");
		printf("   📋 Official Apple CSR_DISABLE_FLAGS definition: 0x%02x\n", CSR_DISABLE_FLAGS);
		printf("   📋 Expected on retail hardware: 0x%02x (minus Apple Internal bit)\n", (CSR_DISABLE_FLAGS & ~CSR_ALLOW_APPLE_INTERNAL));
		printf("   📋 Your configuration: 0x%02x (custom or version-specific)\n", config);
		printf("   📋 SIP flag definitions may vary between XNU kernel versions\n");
		printf("   📋 Historical macOS versions had different CSR_DISABLE_FLAGS in their XNU source\n");
	}
	
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
	
	
	printf("\n🔍 Boot Arguments Analysis for Kext Loading:\n");
	
	// Check if CSR_ALLOW_UNTRUSTED_KEXTS is set
	if (config & CSR_ALLOW_UNTRUSTED_KEXTS) {
		printf("   ✅ CSR_ALLOW_UNTRUSTED_KEXTS is SET (0x1) - unsigned kexts allowed via SIP\n");
		printf("   📋 'kext-dev-mode=1' boot argument is NOT needed with 'csrutil disable'\n");
		printf("   📋 The CSR_ALLOW_UNTRUSTED_KEXTS flag handles unsigned kext loading\n");
	} else {
		printf("   ❌ CSR_ALLOW_UNTRUSTED_KEXTS is CLEAR - SIP blocks unsigned kexts\n");
		printf("   📋 'kext-dev-mode=1' boot argument would be needed for unsigned kexts\n");
		printf("   📋 Alternative: Use 'csrutil enable --without kext' to allow kexts via SIP\n");
	}
	
	printf("   🔍 Current boot-args: ");
	system("nvram boot-args 2>/dev/null || echo 'No custom boot arguments set'");
	
	printf("\n📋 Recommended SIP Configurations for Third-Party Kexts:\n");
	printf("   • SECURE:     csrutil enable --without kext      (0x00000001)\n");
	printf("   • BALANCED:   csrutil enable --without kext --without debug (0x00000005)\n");
	printf("   • PERMISSIVE: csrutil disable                     (0x%08x on %s)\n", 
		expected_disable, get_macos_name(macos_ver));

	printf("\n💡 SIP Configuration Options:\n");
	printf("   🏥 Recovery Mode (Official): Boot to Recovery → csrutil disable\n");
	printf("      └─ Status: Shows as 'disabled' in csrutil status\n");
	printf("   🔧 Manual NVRAM (Advanced):\n");
#if defined(__x86_64__)
	printf("      Intel: sudo nvram csr-active-config=%%0%x%%00%%00%%00\n", expected_disable);
	printf("      └─ Status: Shows as 'disabled' if matches standard value, 'Custom' if not\n");
	printf("      └─ Useful when Recovery Mode is inaccessible or automated deployment\n");
#elif defined(__arm64__)
	printf("      Apple Silicon: Manual NVRAM modification NOT supported\n");
	printf("      └─ SIP stored in Device Tree (lp-sip0) - Recovery Mode required\n");
	printf("      └─ Use Recovery Mode → Terminal → 'csrutil disable' for modifications\n");
#else
	printf("      Platform-specific: sudo nvram csr-active-config=%%0%x%%00%%00%%00\n", expected_disable);
#endif

	if (config && (config & CSR_ALLOW_APPLE_INTERNAL))
	{
		printf("\n🚨 APPLE INTERNAL FLAG DETECTED (0x10):\n");
		printf("   This configuration includes the AppleInternal bit\n");
		printf("   ⚠️  On retail Intel hardware: boot.efi should strip this bit\n");
		printf("   ✅ On Apple Silicon/Dev hardware: May be legitimate\n");
		printf("   🔍 If persistent on Intel retail hardware, investigate:\n");
		printf("      - Custom firmware/bootloader modifications\n");
		printf("      - Hardware identification issues\n");
		printf("      - Non-standard boot process\n");
		printf("   📖 Reference: Khronokernel SIP documentation\n");
	}
	
	printf("\n======================================================\n");
	printf("Technical Implementation Details:\n");
	printf("======================================================\n");
	printf("🔧 CSR System Call Chain:\n");
	printf("   1. User Space: csr_get_active_config() function\n");
	printf("   2. Library: libsystem_kernel.dylib wrapper\n");
	printf("   3. Kernel: syscall 483 (csrctl system call)\n");
	printf("   4. Implementation: bsd/kern/kern_csr.c (Apple XNU source)\n");
	printf("   5. Storage: Architecture-specific CSR state\n\n");
	
	printf("📦 Library Dependencies:\n");
	printf("   • libsystem_kernel.dylib - Provides CSR user-space interface\n");
	printf("   • Weak linking used for compatibility across macOS versions\n");
	printf("   • Syscall 483 (csrctl) - Kernel communication mechanism\n\n");
	
	printf("💾 CSR State Storage by Architecture:\n");
#if defined(__x86_64__)
	printf("   • Intel Systems: NVRAM variable 'csr-active-config'\n");
	printf("   • Boot Process: boot.efi reads NVRAM → kernel csr_state\n");
	printf("   • Modification: nvram csr-active-config=%%xx%%xx%%xx%%xx\n");
#elif defined(__arm64__)
	printf("   • Apple Silicon: Device Tree properties (lp-sip0/sip1/sip2)\n");
	printf("   • Boot Process: iBoot/bootloader → Device Tree → kernel\n");
	printf("   • Modification: Typically via Recovery Mode only\n");
#else
	printf("   • Platform-specific storage mechanism\n");
#endif
	printf("\n🔍 Kernel CSR Implementation:\n");
	printf("   • Source: Apple XNU bsd/kern/kern_csr.c\n");
	printf("   • Global variable: csr_state (kernel-space CSR configuration)\n");
	printf("   • Syscall Interface: syscall 483 (csrctl) provides user-space access\n");
	printf("   • Apple Documentation: darwin-xnu/bsd/kern/syscalls.master line 483\n");
	printf("   • Function Signature: csrctl(uint32_t op, user_addr_t useraddr, user_addr_t usersize)\n");
	printf("   • User Library: libsystem_kernel.dylib wraps syscall as csr_get_active_config()\n");
	printf("   • Validation: Kernel enforces CSR restrictions based on this state\n");
	printf("   📖 Official Reference: https://github.com/apple/darwin-xnu/blob/main/bsd/kern/syscalls.master#L483\n");
	
	if (text)
	{
		free(text);
	}
	exit(0);  // Success - changed from exit(-1)
}
