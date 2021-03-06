#ifndef post_h
#define post_h

#include <Foundation/Foundation.h>

@interface Post : NSObject

// General
- (bool)go;
// Kernel base/slide //
- (uint64_t)kernel_slide;
- (uint64_t)kernel_base;
// Checks
- (struct utsname)uname;
- (int)modelDigitsBeforeComma;
- (bool)isSupported;
- (bool)isUnsupported;
- (bool)isA12;
- (bool)isSupportedAndIsNotA12;
// Users
- (bool)isRoot;
- (bool)isMobile;
- (void)setUID:(uid_t)uid;
- (void)setUID:(uid_t)uid forProc:(uint64_t)proc;
- (void)setGID:(gid_t)gid;
- (void)setGID:(gid_t)gid forProc:(uint64_t)proc;
- (void)setUIDAndGID:(int)both;
- (void)setUIDAndGID:(int)both forProc:(uint64_t)proc;
- (void)root;
- (void)mobile;
// Sandbox
- (void)sandbox;
- (void)sandbox:(uint64_t)proc;
- (void)unsandbox;
- (void)unsandbox:(uint64_t)proc;
- (bool)isSandboxed;
- (bool)isSandboxed:(uint64_t)proc;
// Procs
- (uint64_t)allproc;
- (uint64_t)selfproc;
- (uint64_t)kernproc;
- (uint64_t)proc_for_pid:(pid_t)pid;
- (pid_t)pid_for_name:(NSString *)name;
- (void)respring;
// Save / Restore
- (void)save;
- (void)restore;

// Debugging
- (void)debug;

@end

#endif
