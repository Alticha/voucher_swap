#ifndef post_h
#define post_h

#include <Foundation/Foundation.h>

@interface Post : NSObject

// General
- (bool)go;
// Users
- (bool)isRoot;
- (bool)isMobile;
- (void)setUID:(uid_t)uid;
- (void)setGID:(gid_t)gid;
- (void)root;
- (void)mobile;
// Sandbox
- (void)sandbox;
- (void)unsandbox;
- (bool)isSandboxed;
// Procs
- (uint64_t)allproc;
- (uint64_t)selfproc;
- (uint64_t)kernproc;
- (uint64_t)proc_for_pid:(pid_t)pid;
- (pid_t)pid_for_name:(NSString *)name;
- (void)respring;

// Debugging
- (void)debug;

@end

#endif
