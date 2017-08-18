#import <objc/runtime.h>
#import <notify.h>
#import <dlfcn.h>
#import <Security/Security.h>
#import <substrate.h>

extern const char *__progname;

#define DropBearDaemomPath "/Library/LaunchDaemons/dropbear.plist"

#define NSLog(...)

static BOOL isDropBearAlertEnabled()
{
	@autoreleasepool {
		NSDictionary *PrefsCheck = [[NSDictionary alloc] initWithContentsOfFile:@DropBearDaemomPath]?:@{};
		NSString* Program = PrefsCheck[@"Program"];
		if(Program && [Program isEqualToString:@"/usr/local/bin/dropbearAlertExecute"]) {
			return YES;
		}
		return NO;
	}
}

%ctor
{
	if(!isDropBearAlertEnabled()) {
		system("exec /usr/bin/DropbearAlertTool -i");
	}
}