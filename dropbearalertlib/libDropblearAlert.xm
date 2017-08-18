#import <objc/runtime.h>
#import <notify.h>
#import <dlfcn.h>
#import <Security/Security.h>
#import <substrate.h>
extern const char *__progname;

#import "dropbear_session.h"

#define NSLog(...)

#define PLIST_PATH_Settings "/var/mobile/Library/Preferences/com.julioverne.dropbearalert.plist"

@implementation NSString (dropbearAlert)
+ (NSString *)encodeBase64WithString:(NSString *)strData
{
    return [self encodeBase64WithData:[strData dataUsingEncoding:NSUTF8StringEncoding]];
}
+ (NSString*)encodeBase64WithData:(NSData*)theData
{
    const uint8_t* input = (const uint8_t*)[theData bytes];
    NSInteger length = [theData length];
    static char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    NSMutableData* data = [NSMutableData dataWithLength:((length + 2) / 3) * 4];
    uint8_t* output = (uint8_t*)data.mutableBytes;
    NSInteger i;
    for (i=0; i < length; i += 3) {
		NSInteger value = 0;
		NSInteger j;
		for (j = i; j < (i + 3); j++) {
			value <<= 8;
			if (j < length) {
				value |= (0xFF & input[j]);
			}
		}
		NSInteger theIndex = (i / 3) * 4;
		output[theIndex + 0] =			  table[(value >> 18) & 0x3F];
		output[theIndex + 1] =			  table[(value >> 12) & 0x3F];
		output[theIndex + 2] = (i + 1) < length ? table[(value >> 6)  & 0x3F] : '=';
		output[theIndex + 3] = (i + 2) < length ? table[(value >> 0)  & 0x3F] : '=';
    }
    return [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];
}
@end

static void sendAppBanner(NSString* messageBody)
{
	dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		system([NSString stringWithFormat:@"/usr/bin/DropbearAlertTool -m \"%@\"", [NSString encodeBase64WithString:messageBody]].UTF8String);
	});
}

static BOOL isEnableForKey(NSString* key)
{	
	@autoreleasepool {
		NSDictionary *DropbearAlertPrefs = [[[NSDictionary alloc] initWithContentsOfFile:@PLIST_PATH_Settings]?:[NSDictionary dictionary] copy];
		BOOL Enabled = (BOOL)[[DropbearAlertPrefs objectForKey:@"Enabled"]?:@YES boolValue];
		BOOL keyBOOL = (BOOL)[[DropbearAlertPrefs objectForKey:key]?:@YES boolValue];
		if(Enabled&&keyBOOL) {
			return YES;
		}
		return NO;
	}
}

static NSString* getFormatMessage()
{
	@autoreleasepool {
		NSDictionary *DropbearAlertPrefs = [[[NSDictionary alloc] initWithContentsOfFile:@PLIST_PATH_Settings]?:[NSDictionary dictionary] copy];
		return [DropbearAlertPrefs objectForKey:@"FormatMessage"]?:@"SSH: Login $#login_status, $#attempt user '$#username' from $#from_addr";
	}
}

#include <sys/types.h>
#include <grp.h>
#include <pwd.h>

static NSString* getMessageInfo(BOOL loginFailed, char* username, uid_t pw_uid, gid_t pw_gid, unsigned int failcount, char * addrstring)
{
	NSString* messageFormat = [getFormatMessage() copy];
	if([messageFormat rangeOfString:@"$#login_status"].location != NSNotFound) {
		messageFormat = [messageFormat stringByReplacingOccurrencesOfString:@"$#login_status" withString:loginFailed?@"Failed":@"Succeeded"];
	}
	if([messageFormat rangeOfString:@"$#attempt"].location != NSNotFound) {
		messageFormat = [messageFormat stringByReplacingOccurrencesOfString:@"$#attempt" withString:loginFailed?[NSString stringWithFormat:@"attempt %u", failcount+1]:@""];
	}
	if([messageFormat rangeOfString:@"$#group_level"].location != NSNotFound) {
		struct group *gr;
		gr = getgrgid(pw_gid);
		char* groupName = gr?gr->gr_name:NULL;
		messageFormat = [messageFormat stringByReplacingOccurrencesOfString:@"$#group_level" withString:[NSString stringWithFormat:@"%s", groupName?:"unknown"]];
	}
	if([messageFormat rangeOfString:@"$#user_level"].location != NSNotFound) {
		struct passwd *pw;
		pw = getpwuid(pw_uid);
		char* userName = pw?pw->pw_name:NULL;
		messageFormat = [messageFormat stringByReplacingOccurrencesOfString:@"$#user_level" withString:[NSString stringWithFormat:@"%s", userName?:"unknown"]];
	}
	if([messageFormat rangeOfString:@"$#from_addr"].location != NSNotFound) {
		messageFormat = [messageFormat stringByReplacingOccurrencesOfString:@"$#from_addr" withString:[NSString stringWithFormat:@"%s", addrstring?:"unknown"]];
	}
	if([messageFormat rangeOfString:@"$#username"].location != NSNotFound) {
		messageFormat = [messageFormat stringByReplacingOccurrencesOfString:@"$#username" withString:[NSString stringWithFormat:@"%s", username?:"unknown"]];
	}
	return messageFormat;
}

static void (*send_msg_userauth_failure_o)(int partial, int incrfail);
static void send_msg_userauth_failure_r(int partial, int incrfail)
{
	if(isEnableForKey(@"LoginFailed")&&incrfail) {
		struct sshsession * sesSym = (struct sshsession *)(dlsym(RTLD_DEFAULT, "ses"));
		struct serversession * svr_sesSym = (struct serversession *)(dlsym(RTLD_DEFAULT, "svr_ses"));
		sendAppBanner(getMessageInfo(YES, sesSym->authstate.username, sesSym->authstate.pw_uid, sesSym->authstate.pw_gid, sesSym->authstate.failcount, svr_sesSym->addrstring));
	}
	
	send_msg_userauth_failure_o(partial, incrfail);
}

static void (*send_msg_userauth_success_o)();
static void send_msg_userauth_success_r()
{
	if(isEnableForKey(@"LoginSucceeded")) {
		struct sshsession * sesSym = (struct sshsession *)(dlsym(RTLD_DEFAULT, "ses"));
		struct serversession * svr_sesSym = (struct serversession *)(dlsym(RTLD_DEFAULT, "svr_ses"));
		sendAppBanner(getMessageInfo(NO, sesSym->authstate.username, sesSym->authstate.pw_uid, sesSym->authstate.pw_gid, sesSym->authstate.failcount, svr_sesSym->addrstring));
	}
	
	send_msg_userauth_success_o();
}



%ctor
{
	MSHookFunction((void *)(dlsym(RTLD_DEFAULT, "send_msg_userauth_failure")), (void *)send_msg_userauth_failure_r, (void **)&send_msg_userauth_failure_o);
	MSHookFunction((void *)(dlsym(RTLD_DEFAULT, "send_msg_userauth_success")), (void *)send_msg_userauth_success_r, (void **)&send_msg_userauth_success_o);
}