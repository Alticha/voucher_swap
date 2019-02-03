//
//  ViewController.m
//  voucher_swap
//
//  Created by Brandon Azad on 12/7/18.
//  Copyright © 2018 Brandon Azad. All rights reserved.
//

#import "ViewController.h"
#import "kernel_slide.h"
#import "voucher_swap.h"
#import "kernel_memory.h"
#include "post.h"
#include <sys/utsname.h>

@interface ViewController ()

@end

@implementation ViewController

- (bool)voucher_swap {
#define CHECK(a, b) if (a < b) { printf("non-16k devices are unsupported.\n"); return false; }
    if ([[UIDevice currentDevice].model isEqualToString:@"iPod touch"]) {
        return false;
    }
    struct utsname u;
    uname(&u);
    char read[257];
    int ii = 0;
    for (int i = 0; i < 256; i++) {
        char chr = u.machine[i];
        long num = chr - '0';
        if (num == -4 || num == 0) {
            break;
        }
        if (num >= 0 && num <= 9) {
            read[ii] = chr;
            ii++;
        }
    }
    read[ii + 1] = 0;
    int digits = atoi(read);
    if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPhone) {
        CHECK(digits, 6);
    } else if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
        CHECK(digits, 8);
    }
    voucher_swap();
    if (!MACH_PORT_VALID(kernel_task_port)) {
        printf("tfp0 is invalid?\n");
        return false;
    }
    return true;
#undef CHECK
}

- (void)failure {
	UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"failed" message:nil preferredStyle:UIAlertControllerStyleAlert];
        [self presentViewController:alert animated:YES completion:nil];
}

- (IBAction)go:(id)sender {
    /*
     If you're running this in a method like viewDidLoad you only need the following:
     --------------------------------------------------------------------------------
     Post *post = [[Post alloc] init];
     bool success = [self voucher_swap];
     if (success) {
        sleep(1);
        [post go];
     } else {
        assert(false);
     }
     */
    Post *post = [[Post alloc] init];
    static int progress = 0;
    if (progress == 2) {
        [post respring];
        return;
    }
    if (progress == 1) {
	return;
    }
    progress++;
    bool success = [self voucher_swap];
    if (success) {
        sleep(1);
        [post go];
        [sender setTitle:@"respring" forState:UIControlStateNormal];
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"success" message:[NSString stringWithFormat:@"tfp0: %i\nkernel base: 0x%llx\nuid: %i\ngid: %i\nunsandboxed: %i", kernel_task_port, kernel_slide + 0xFFFFFFF007004000, getuid(), getgid(), [post isSandboxed]] preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"done" style:UIAlertActionStyleCancel handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    } else {
        [self failure];
    }
    progress++;
}

- (void)viewDidLoad {
    [super viewDidLoad];
}

@end
