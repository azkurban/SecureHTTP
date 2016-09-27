#import <Foundation/Foundation.h>

#import <Cordova/CDVPlugin.h>

@interface CordovaHttpPlugin : CDVPlugin

- (void)enableSSLPinning:(CDVInvokedUrlCommand*)command;
- (void)acceptAllCerts:(CDVInvokedUrlCommand*)command;
- (void)validateDomainName:(CDVInvokedUrlCommand*)command;
- (void)post:(CDVInvokedUrlCommand*)command;
- (void)postJson:(CDVInvokedUrlCommand*)command;
- (void)postJsonString:(CDVInvokedUrlCommand*)command;
- (void)get:(CDVInvokedUrlCommand*)command;
- (void)put:(CDVInvokedUrlCommand*)command;
- (void)putJson:(CDVInvokedUrlCommand*)command;
- (void)putJsonString:(CDVInvokedUrlCommand*)command;
- (void)delete:(CDVInvokedUrlCommand*)command;
- (void)uploadFile:(CDVInvokedUrlCommand*)command;
- (void)downloadFile:(CDVInvokedUrlCommand*)command;



// todo some staff


@end
