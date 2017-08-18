#include <objc/runtime.h>
#include <dlfcn.h>
#include <sys/stat.h>
#import <notify.h>

#define DropBearDaemomPath "/Library/LaunchDaemons/dropbear.plist"

extern mach_port_t SBSSpringBoardServerPort();
// Firmware < 9.0
@interface SBSLocalNotificationClient : NSObject
+ (void)scheduleLocalNotification:(id)notification bundleIdentifier:(id)bundleIdentifier;
@end
// Firmware >= 9.0 & 10.0
@interface UNSNotificationScheduler : NSObject
- (id)initWithBundleIdentifier:(id)bundleIdentifier;
- (void)_addScheduledLocalNotifications:(NSArray *)notifications withCompletion:(id)completion;
@end

@interface Base64 : NSObject
+ (void) initialize;
+ (NSData*) decode:(const char*) string length:(NSInteger) inputLength;
+ (NSData*) decode:(NSString*) string;
@end
@implementation Base64
#define ArrayLength(x) (sizeof(x)/sizeof(*(x)))
static unsigned char encodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static unsigned char decodingTable[128];
+ (void) initialize
{
	if (self == [Base64 class]) {
		memset(decodingTable, 0, ArrayLength(decodingTable));
		for (NSInteger i = 0; i < ArrayLength(encodingTable); i++) {
			decodingTable[encodingTable[i]] = i;
		}
	}
}
+ (NSData*) decode:(const char*) string length:(NSInteger) inputLength
{
	if ((string == NULL) || (inputLength % 4 != 0)) {
		return nil;
	}
	while (inputLength > 0 && string[inputLength - 1] == '=') {
		inputLength--;
	}
	NSInteger outputLength = inputLength * 3 / 4;
	NSMutableData* data = [NSMutableData dataWithLength:outputLength];
	uint8_t* output = (uint8_t*)data.mutableBytes;
	NSInteger inputPoint = 0;
	NSInteger outputPoint = 0;
	while (inputPoint < inputLength) {
		unsigned char i0 = string[inputPoint++];
		unsigned char i1 = string[inputPoint++];
		unsigned char i2 = inputPoint < inputLength ? string[inputPoint++] : 'A'; /* 'A' will decode to \0 */
		unsigned char i3 = inputPoint < inputLength ? string[inputPoint++] : 'A';
		output[outputPoint++] = (decodingTable[i0] << 2) | (decodingTable[i1] >> 4);
		if (outputPoint < outputLength) {
			output[outputPoint++] = ((decodingTable[i1] & 0xf) << 4) | (decodingTable[i2] >> 2);
		}
		if (outputPoint < outputLength) {
			output[outputPoint++] = ((decodingTable[i2] & 0x3) << 6) | decodingTable[i3];
		}
	}
	return data;
}
+ (NSData*) decode:(NSString*) string
{
	return [self decode:[string cStringUsingEncoding:NSASCIIStringEncoding] length:string.length];
}
@end

__attribute__((constructor)) int main(int argc, char **argv, char **envp)
{
	setgid(0);
	setuid(0);
	if((chdir("/")) < 0) {
		exit(EXIT_FAILURE);
	}
	
	NSString* base64message = nil;
	BOOL flagInstall = NO;
	BOOL flagRemove = NO;
	if((argc > 1)) {
        if (!strcmp(argv[1], "-m") && (argc > 2)) {
			base64message = [NSString stringWithFormat:@"%s", argv[2]];
        } else if(!strcmp(argv[1], "-i")) {
			flagInstall = YES;
		} else if(!strcmp(argv[1], "-r")) {
			flagRemove = YES;
		}
    }
	
	if(flagInstall || flagRemove) {
		@autoreleasepool {
			NSMutableDictionary *PrefsCheck = [[NSMutableDictionary alloc] initWithContentsOfFile:@DropBearDaemomPath];
			if(!PrefsCheck) {
				exit(EXIT_FAILURE);
			}
			NSString* Program = PrefsCheck[@"Program"];
			if(Program && ![Program isEqualToString:@"/usr/local/bin/dropbearAlertExecute"]) {
				system([NSString stringWithFormat:@"printf \"%@\" >/usr/local/bin/dropbearAlertProgram", Program].UTF8String);
			}
			PrefsCheck[@"Program"] = @"/usr/local/bin/dropbearAlertExecute";
			if(flagRemove) {
				NSString* ProgramBackup = @"/usr/local/bin/dropbear";
				if(NSString* ProgramFile = [NSString stringWithContentsOfFile:@"/usr/local/bin/dropbearAlertProgram" encoding:NSUTF8StringEncoding error:NULL]) {
					ProgramBackup = ProgramFile;
				}
				PrefsCheck[@"Program"] = ProgramBackup;
			}
			[PrefsCheck writeToFile:@DropBearDaemomPath atomically:YES];
			chown(DropBearDaemomPath, 0, 0);
			chmod(DropBearDaemomPath, 0755);
			system("launchctl unload "DropBearDaemomPath);
			system("launchctl load "DropBearDaemomPath);
		}
	} else if(base64message!=nil) {
		@autoreleasepool {
		__block BOOL notificationHasCompleted = YES;
		NSData* dataMessageDec = [Base64 decode:base64message];
		NSString*body = [[NSString alloc] initWithData:dataMessageDec encoding:NSUTF8StringEncoding];
		if (body!=nil) {
			BOOL shouldDelay = NO;
			mach_port_t port;
			mach_port_t (*SBSSpringBoardServerPort)() = (mach_port_t (*)())dlsym(RTLD_DEFAULT, "SBSSpringBoardServerPort");
			while ((port = SBSSpringBoardServerPort()) == 0) {
				[NSThread sleepForTimeInterval:1.0];
				shouldDelay = YES;
			}
			if (shouldDelay) {
				[NSThread sleepForTimeInterval:20.0];
			}
			if (objc_getClass("UILocalNotification") != nil) {
				UILocalNotification *notification = [objc_getClass("UILocalNotification") new];
				[notification setAlertBody:[NSString stringWithFormat:@"%@", body]];
				[notification setHasAction:NO];
				[notification setAlertAction:nil];
				
				if ((kCFCoreFoundationVersionNumber < 1240.10)) {
					if(Class $SBSLocalNotificationClient = objc_getClass("SBSLocalNotificationClient")) {
						if([$SBSLocalNotificationClient respondsToSelector:@selector(scheduleLocalNotification:bundleIdentifier:)]) {
							[$SBSLocalNotificationClient scheduleLocalNotification:notification bundleIdentifier:@"com.julioverne.dropbearalert"];
						}							
					}
				} else {
					void *handle = dlopen("/System/Library/PrivateFrameworks/UserNotificationServices.framework/UserNotificationServices", RTLD_LAZY);
					if (handle != NULL) {
						Class $UNSNotificationScheduler = objc_getClass("UNSNotificationScheduler");
						if($UNSNotificationScheduler) {
							UNSNotificationScheduler* notificationScheduler = [[$UNSNotificationScheduler alloc] initWithBundleIdentifier:@"com.julioverne.dropbearalert"];
							if([notificationScheduler respondsToSelector:@selector(_addScheduledLocalNotifications:withCompletion:)]) {
								notificationHasCompleted = NO;
								[notificationScheduler _addScheduledLocalNotifications:@[notification] withCompletion:^(){
									notificationHasCompleted = YES;
								}];
							}
						}
						dlclose(handle);
					}
				}
			}
			CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0, true);
			while (!notificationHasCompleted) {
				CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0, true);
			}
		}
		}
	}
	
	exit(0);
}