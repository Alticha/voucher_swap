#import "ViewController.h"
#import "kernel_slide.h"
#import "voucher_swap.h"
#import "kernel_memory.h"
#include "utilities.h"
#include "log.h"
#include <sys/utsname.h>
#define colourFromHex(hex, alphaVal) [UIColor colorWithRed:((float)((hex & 0xFF0000) >> 16))/255.0 green:((float)((hex & 0xFF00) >> 8))/255.0 blue:((float)(hex & 0xFF))/255.0 alpha:alphaVal]
#define bgDisabledColour colourFromHex(0xB8B8B8, 1.0)
#define setBgDisabledColour setBackgroundColor:bgDisabledColour
#define bgEnabledColour colourFromHex(0xFF9300, 1.0)
#define setBgEnabledColour setBackgroundColor:bgEnabledColour
#define mainThread(code) dispatch_async(dispatch_get_main_queue(), ^{ code; }); /* just to clean up the code a bit */

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UITextView *logs;
@property (weak, nonatomic) IBOutlet UIButton *exploitBtn;

@end

@implementation ViewController

// Variables //

extern NSString *LOGGED;
extern BOOL SHOULD_LOG;
Utilities *utils;

// Logging //

- (void)log:(NSString *)what {
    if (!SHOULD_LOG) return;
    LOGGED = [LOGGED stringByAppendingString:what];
    [self addLog];
}

- (void)slog:(NSString *)what {
    if (!SHOULD_LOG) return;
    [_logs setText:[@"" stringByAppendingString:[what stringByAppendingString:@""]]];
    [_logs scrollRangeToVisible:NSMakeRange(_logs.text.length - 1, 1)];
}

- (void)addLog {
    if (!SHOULD_LOG) return;
    mainThread([self slog:LOGGED]);
}

// voucher_swap //

- (void)failure {
    ERROR("Failed");
    [_exploitBtn setTitle:@"Failed" forState:UIControlStateDisabled];
	UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Failed" message:nil preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:alert animated:YES completion:nil];
}

- (IBAction)go:(id)sender {
    /*
     If you're running this in a method like viewDidLoad you only need the following:
     --------------------------------------------------------------------------------
     Utilities *u = [Utilities alloc];
     if ([u isUnsupported]) {
        ERROR("Your device is unsupported");
        assert(false);
        return;
     }
     voucher_swap();
     if (MACH_PORT_VALID(kernel_task_port)) {
        [u post];
     } else {
        assert(false);
     }
     */
    
    // Respring
    static bool complete = false;
    if (complete) {
        [utils respring];
        return;
    }
    
    // Update the GUI
    [_exploitBtn setEnabled:NO];
    [_exploitBtn setTitle:@"Please Wait..." forState:UIControlStateDisabled];
    [UIView animateWithDuration:0.5 animations:^{
        [self->_exploitBtn setBgDisabledColour];
    }];
    
    // Exploitation and post-exploitation
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Is the device supported?
        __block BOOL supported = true;
        if ([utils isUnsupported]) {
            mainThread(
                       ERROR("Non-16k devices are unsupported.");
                       [sender setTitle:@"Failed" forState:UIControlStateDisabled];
                       supported = false;
            );
        }
        if (!supported) {
            // Failed - unsupported
            mainThread([self failure]);
            return;
        }
        // Run voucher_swap
        voucher_swap();
        if (!MACH_PORT_VALID(kernel_task_port)) {
            // Failed - tfp0 is invalid
            mainThread([self failure]);
            return;
        }
        // Post exploitation
        [utils post];
        // Update the GUI
        mainThread(
                   [self->_exploitBtn setEnabled:YES];
                   [self->_exploitBtn setTitle:@"Respring" forState:UIControlStateNormal];
                   [UIView animateWithDuration:0.5 animations:^{
                       [self->_exploitBtn setBgEnabledColour];
                   }];
                   (LOG("%s", [NSString stringWithFormat:@"[+] Kernel task port: 0x%x\n[+] Kernel base: 0x%llx\n[+] User ID: %i\n[+] Group ID: %i\n[+] Is sandboxed: %@\n[+] Done!\n", kernel_task_port, [utils kernel_base], getuid(), getgid(), [utils isSandboxed] ? @"Yes" : @"No"].UTF8String));
                   // Become mobile ([U/G]ID: 501) so Xcode can stop the process
                   SHOULD_LOG = false;
                   [utils mobile];
                   SHOULD_LOG = true;
        );
        complete = true; // Respring check will now return true
    });
}

// Init //

- (void)viewDidLoad {
    [super viewDidLoad];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(addLog) name:@"LoggedToString" object:nil];
    utils = [Utilities alloc];
    
	INFO("Version %s", ((NSString *)[[NSBundle mainBundle].infoDictionary objectForKey:@"CFBundleShortVersionString"]).UTF8String);
    LOG("%s\n", ((NSString *)[[[NSBundle mainBundle].bundlePath componentsSeparatedByString:@"/"] objectAtIndex:5]).UTF8String);
    
    struct utsname u = [utils uname];
    bool isSupported = [utils isSupported];
    if (!isSupported) {
        ERROR("%s", [NSString stringWithFormat:@"%s is unsupported", u.machine].UTF8String);
        [_exploitBtn setEnabled:NO];
        [_exploitBtn setTitle:@"Unsupported" forState:UIControlStateDisabled];
        [_exploitBtn setBgDisabledColour];
        return;
    }
    
    INFO("%s", [NSString stringWithFormat:@"%s is a supported device", u.machine].UTF8String);
    INFO("Ready!");
}

// Other //

- (IBAction)credits:(id)sender {
    UIAlertController *controller = [UIAlertController alertControllerWithTitle:@"Credits" message:@"(@_)bazad: Exploit\n(@)Alticha(Dev): Modifications and post-exploitation:\n(@)Pwn20wnd: Exploit reliability improvements\n(@)sbingner: ArchiveFile and trust cache injection\n(@)xerub: patchfinder64" preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *action = [UIAlertAction actionWithTitle:@"Dismiss" style:UIAlertActionStyleCancel handler:nil];
    [controller addAction:action];
    [self presentViewController:controller animated:YES completion:nil];
}

@end

#undef mainThread
