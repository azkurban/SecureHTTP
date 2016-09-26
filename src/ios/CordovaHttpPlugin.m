#import "CordovaHttpPlugin.h"
#import "CDVFile.h"
#import "TextResponseSerializer.h"
#import "AFHTTPSessionManager.h"

#define HEADER_DATE @"Date"
#define HEADER_CONTECT_MD5 @"Content-MD5"
#define HEADER_API @"X-Fara-ApiKey"
#define HEADER_SIGNATURE @"X-Fara-Signature"

#import "NSData+Base64.h"
#import <Security/Security.h>
#import <Security/SecItem.h>
#include <CommonCrypto/CommonDigest.h>

@interface CordovaHttpPlugin()

@property (nonatomic) NSData *p12Data;

- (void)setRequestHeaders:(NSDictionary*)headers forManager:(AFHTTPSessionManager*)manager;
- (void)setResults:(NSMutableDictionary*)dictionary withTask:(NSURLSessionTask*)task;

@end


@implementation CordovaHttpPlugin {
    AFSecurityPolicy *securityPolicy;
}

- (void)pluginInitialize {
    securityPolicy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeNone];
    NSString *p12 = @"MIIMiQIBAzCCDE8GCSqGSIb3DQEHAaCCDEAEggw8MIIMODCCBK8GCSqGSIb3DQEHBqCCBKAwggSc"
    "AgEAMIIElQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQINnpYArtGm/QCAggAgIIEaAJB645J"
    "ET0Hl+M4vrHWnaLk0X9HDsAWLemBAnfBglU0RtXrWzoOPgdT/FqEkIt05gUlidbg+9Tw03SsmLLq"
    "EMey4m0DG+3Bc/vbOb+f4dAjCoYo1tY09c4MghBxxrRKdttT1gd8SIJAB8on8QYveZPZnOSARcHF"
    "Wn2speLLnmo5JJji8sW+2REb4m4kdN0r+X2V+DtArHGoyGlo+Dt9UOHMGEyuYZ1yCDXHPIsr6J3b"
    "5gtUXMmc9/VMzwBPQmZb99rvcLD6n+NPVwJj7qcUI1vVdqxW+eAY/8gvDolsaZy6tH4z53JELnot"
    "BllvrUZc7jKz78yiFhbY0L2kmILZHzfFZVIGJyz4GKXbZq9FCWem+dOnDZCR5RX8OCbd4JrxnRd8"
    "R2gUbFxBI9IAYPb0k3wb9nO18IuUUsbJzIILGuCZfgjhZysMM43b2tY+tQiuuQ6gfCc+/BJnLrau"
    "FBR4Gkm2dDLdiFfTQf/wQeJtfdYWZSd3vyqP7zrWkcInMo6KhmzVhQXih+Jlte7c3vDrrIktZqmk"
    "uLjK2bgRF9lL8S65fOczviJhARXu4XIKHU/POJOg8Ke9QrWGzwP24UF403fG4/QK8sX1K8cGmuls"
    "F2cY4lYZuGjhUYy98vSMr+56u851ZcDrK2qmZHVtTVFMw/ZfwE6nkLZKhtKjPokFX261mS6p7yp3"
    "+fAN/LEEgHoAAMMP4M63BzsRT7QbMC35ryTaakHENUzZXlUvDhf2Ldf3C/96mBRurE6PtJarZgcQ"
    "2aZTzCqmcuyE5SR+zkUaavGrHqmYhZJC1+fDlHpS5LuvIuuXivys0UAlHHFFpeKutSWKKcKkIGUq"
    "zi2U4WPuOwrJr4P+y01P+qVWNdZiTP4HleM8wxSFW3oOPMvh5HeMau9ivqb0CpbZdVRQb2KNpjOr"
    "11HFCzXLiTwKqrsKvK/G9R9712n3hqMafWdxFdbQ+l9b7pGHOdC7nsZQ+9nabsIlVCe7ETopTt1J"
    "fkst2jCMTqGY0YQ3n0hhEtuA0YI0SdFGD2YluL/gwDPEB3gKX4eIX9qVSPK800AklL+CgA+9+wXy"
    "5kCs8610YoLW02vr/WcGs0TkRCjZBlS8pSDxYyWo0EOVTmg+gBUgquxY5CCxoed65ZAkg0Gwg/Pw"
    "FO2lknKQ4ruBr3XveXvCiXUSXTsbLNUYSM2SEiVJWzeBgpDoTFOhhMazkZGF/nn8JfontQYANCBF"
    "BP14oyJxXpyq6PoxfowJIK2lX3MWKzWk16JokSZIINTWJre2CqlAeozLMuIonQUwP+n1kLS9IZIv"
    "9j5fwhISAaj+7DRWRbvgXnIaiOT0yOV53Hqd9SssyEgwhOS9AEoK/YOTL9Htj/gUIdCZWkxspIFw"
    "tqIhzNSHnmgge+eQM0a0Dn896rJczG9kg/CzI1iV16nOTCGkyEM74zOGd9vikHup1RAz7Iui1lbq"
    "BruriAp4eq4cNujgCh83rjYMq0p361u4oT9R2FCZiXGcqB+rrEYc5DCCB4EGCSqGSIb3DQEHAaCC"
    "B3IEggduMIIHajCCB2YGCyqGSIb3DQEMCgECoIIHLjCCByowHAYKKoZIhvcNAQwBAzAOBAgWBcjo"
    "Jedo/wICCAAEggcIMvuVG16k1G42rfM5hxamYTUwo/RBS+KCiz1uhtiOh0XYOeVbphC/2HRvaa5f"
    "zKVj9VTE0HZ+gLnQtI1GKC7qVuwbKmlCyRPRlVkgOrJrBXy9eRsEoiD+Z6TlquRDR9Y1JjVBdVNi"
    "KTNuh/RtdnPjBkrqFKYprc4QmcY8zeZ30Sha8kU/AczHAASImQToKYx5nNdKqySGfh5h8u50/e1i"
    "G2HrQX7QDw6vj4iuevjbkAXk+pZWXGj951QodrxuXeJvg19KzE+GjBKipq/w0LNc0C7M43FPDG+M"
    "cqO6LCZ3uVv40hDPbUIzXazz+upao1/C7xNdJUtlm6eQ2UvT3DkP3tnfxAmyv2ZEeszVBpToOcSM"
    "g/Q8EBDxoc4iCOezV0hQttf8VRAXlHo3CfVaPZmelW/o2Lxh8pkqoNIwrOY2pzwLk251RZimkhmw"
    "bXCIUjHGNVZD0AETayuP5E0xFcOxustsFuFDCTf3tQVPEyuPuZRWeExX1ZacY/OaGXbOmuUKsJ6o"
    "uwj46WSy+14LSVT0UKnEO9+iX5OBfu9nB2HoiECnU9wbXbjlz+H5bE+uJ0NEjDwIzoOBaHmMJ2F8"
    "PR1Kkab3/0rBMq5JWghOaWXETAINTQmN81At8C3VRAQbvCOGpo8OFPBYGWIN0Q9y8HiQfaRIpYBc"
    "V9mYPxsqHD6MfKH5fVeCVeybw+rK1m6AsLfLS6kKbyz1zh3em0JJScCdd+FDQvX8VeCjXIaQPVtA"
    "hGKYK3NHbDLSFrjeA8/MK0SCnUlPz8eMmKJ4SKoCrPMDbAZkx6dCaupbj/Qi+Ce/q9wrFxv1bx1m"
    "mlUEUW1HfolqfwnOidyiVWBUH0Yq+V7s8Y5/wNvoBvZ0TjE08mEmnhMwbXfLYfJlH0eSUDctpFzC"
    "DVFW//h4Pvb2myvZsATesbOH2lSIAo/XVMZ5pnu+niyr0+pwY3oZCRmyx5f2RW1SDjAZ12rFw7U5"
    "KrInBRZbYZz7QAh7cWqOh6pAGUd+aAvxKO+uljCEv40HC4zrzGWHFReRtVlGeS+VstGbDsLnms1r"
    "YFNicvoKO0yoCkTn0q1Gw+aHz11bYsQU7K4CTymy4QEtCc6XW5aeNj8IN4dHBag7ZpiST5a5gt6K"
    "QqZ7khC4jJmqH2m6RuhbxE30aaORRj0XzxnJ6RqnjHM2kZhZMgO6MALKHd4dT50rjsq+gyFUVqmH"
    "isUArj3ehlaBWIQNktvbOp2OwYqMJSHaYPiR2yFvtb/ixFtC6Vi12NqMKeXKgsPCa4a9k4HWdK1n"
    "dPKZnwgbZRQoJj0DVHMZJGiHmnBpUvqfz97YDg7eOmjMAiu+6D75APEoaUG/7h+ApohxhAETgZj9"
    "PUqQHUuhEgjc+pAwGBzU1sRBi5GJb50ZZ7qOfNVvAO70ScO4HbE+VbRE32LUf8hn51ksMYLK6zig"
    "pqvYG0EZ8Wv4JjJ/qIRRtX/M9nE8L2QsL85R5qrekldR6g4pQ/+LZAik7ZvVeKoeMWnck+nMV78q"
    "pb3AMln9/S5zE+AaLMRM15KAM5BWO8nUVanvYsXMCiAadHZngjxA+DZxnJtQ4DcsmXTY3V6rG7NO"
    "Z2277BMMA7lU/b1l0v5qh/qN51aI+wVFi+BrBaZkxx8zYl6A2x8lfTU8DuLmGukMutRH4xDdtFcN"
    "Urz42pNCGmJDvRHkwMaSVovQvmU3tgo14bT/V59wFaOPMfv1CAu+IB7ULrwT0peOu2MsOW9ex+25"
    "f4jnofUMfJI/c7md4ttqfaZ6xRgbhd6xkVQ5dD50NdJ/r+neShzMaRfawcWDolGaf2NG4fYUycpb"
    "g/iNB1gfLTNnDa7Nk+eDpAOUONAfJjUbnaxzXxSDLi16hWfa8K4MiAv7BXEajc5xIuxc1Oj+3SM1"
    "c0ORMH13K+fKnyszHmv3j8188MAT1r7kORhobrfGMdeRkwD+6W21Sb44es15oM+kUwHFSbXPLCs0"
    "1XbuU1RZ46iDS11DHgqEL5s2Vh7A/9T8u15Ero3ysG0nrHampLoc2Bq2hAwugSM1oSljxC1M5oz4"
    "KwATbtveHBKk0kQiyqS3GSndqpIGuKFkIh6e8Wg/yjdytPB43VrHJehR9qC03gajtAveGMVZJWAo"
    "L94W4/njIasYvYhkNMVtpDQ1FgLlmQPquibqMnqiR5wGpJUfwbHE6tarDPAKfWDb2ePbjZtSTSBd"
    "uGTLweGYnfY+L2eRg0STlWu4y1IsIIpxbBec+3vuDk7jNovBC/Lu5CgI/BMAhPyB5bgwShIOK0rw"
    "nv3uu9K2gXFDmfs7uy2o3MrjNtJS/bLA/eUMfQGQ30IlvcqyHNo2EUE5t+kpGKm24KJ74RmqJ1iV"
    "B5PVjY4QkoyLM5EmMMSiSxWW+opfAqBFf86WNq5BZV+wjKuGvx6rLZlncjo5MSUwIwYJKoZIhvcN"
    "AQkVMRYEFBvYcs7aT0QS+4MMqe9gMcGObEVzMDEwITAJBgUrDgMCGgUABBSys3IuWyzJ5FXWbPGZ"
    "j16ks82iYAQIMTMVFjx8XRICAggA";
    self.p12Data = [NSData dataFromBase64String: p12];
}

#pragma mark - SHA256 with RSA signing

-(NSString *) canonicalRepresentation: (NSDictionary *) headers method: (NSString *) method url: (NSString *) url params: (NSString *) params {
    NSString *path = [url stringByReplacingOccurrencesOfString: @"http://92.62.44.150/sales-service-rest" withString: @"" options: NSCaseInsensitiveSearch range: NSMakeRange(0, url.length)];
    NSString *md5 = [headers objectForKey: HEADER_CONTECT_MD5];
    NSString *date = [headers objectForKey: HEADER_DATE];
    NSString *apiKey = [headers objectForKey: HEADER_API];
    NSString *requestParams = nil;
    if ([method isEqualToString: @"GET"]) {
        requestParams = params;
    }
    return [NSString stringWithFormat: @"%@\n%@\ncontent-md5: %@\ndate: %@\nx-fara-apikey: %@\n%@\n", method, path, md5, date, apiKey, requestParams?requestParams:@""];
}

SecKeyRef getPrivateKeyRef(NSData *p12Data) {
    
    NSMutableDictionary * options = [[NSMutableDictionary alloc] init];
    
    SecKeyRef privateKeyRef = NULL;
    
    //change to the actual password you used here
    [options setObject:@"123qwe" forKey:(id)kSecImportExportPassphrase];
    
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    
    OSStatus securityError = SecPKCS12Import((CFDataRef) p12Data,
                                             (CFDictionaryRef)options, &items);
    
    if (securityError == noErr && CFArrayGetCount(items) > 0) {
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        SecIdentityRef identityApp =
        (SecIdentityRef)CFDictionaryGetValue(identityDict,
                                             kSecImportItemIdentity);
        
        securityError = SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
        if (securityError != noErr) {
            privateKeyRef = NULL;
        }
    }
    CFRelease(items);
    return privateKeyRef;
}

NSData* PKCSSignBytesSHA256withRSA(NSData* plainData, SecKeyRef privateKey)
{
    size_t signedHashBytesSize = SecKeyGetBlockSize(privateKey);
    uint8_t* signedHashBytes = malloc(signedHashBytesSize);
    memset(signedHashBytes, 0x0, signedHashBytesSize);
    
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        return nil;
    }
    
    SecKeyRawSign(privateKey,
                  kSecPaddingPKCS1SHA256,
                  hashBytes,
                  hashBytesSize,
                  signedHashBytes,
                  &signedHashBytesSize);
    
    NSData* signedHash = [NSData dataWithBytes:signedHashBytes
                                        length:(NSUInteger)signedHashBytesSize];
    
    if (hashBytes)
        free(hashBytes);
    if (signedHashBytes)
        free(signedHashBytes);
    
    return signedHash;
}


- (void)setRequestHeaders:(NSDictionary*)headers forManager:(AFHTTPSessionManager*)manager {
    manager.requestSerializer = [AFHTTPRequestSerializer serializer];

    NSString *contentType = [headers objectForKey:@"Content-Type"];
    if([contentType isEqualToString:@"application/json"]){
        manager.requestSerializer = [AFJSONRequestSerializer serializer];
    } else {
        manager.requestSerializer = [AFHTTPRequestSerializer serializer];
    }

    [manager.requestSerializer.HTTPRequestHeaders enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        [manager.requestSerializer setValue:obj forHTTPHeaderField:key];
    }];
    [headers enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        [manager.requestSerializer setValue:obj forHTTPHeaderField:key];
    }];
}

- (void)setResults:(NSMutableDictionary*)dictionary withTask:(NSURLSessionTask*)task {
    if (task.response != nil) {
        NSHTTPURLResponse *response = (NSHTTPURLResponse *)task.response;
        [dictionary setObject:[NSNumber numberWithLong: (long)response.statusCode] forKey:@"status"];
        [dictionary setObject:response.allHeaderFields forKey:@"headers"];
    }
}

- (void)enableSSLPinning:(CDVInvokedUrlCommand*)command {
    bool enable = [[command.arguments objectAtIndex:0] boolValue];
    if (enable) {
        securityPolicy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];
    } else {
        securityPolicy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeNone];
    }
    
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)acceptAllCerts:(CDVInvokedUrlCommand*)command {
    CDVPluginResult* pluginResult = nil;
    bool allow = [[command.arguments objectAtIndex:0] boolValue];
    
    securityPolicy.allowInvalidCertificates = allow;
    
    pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)validateDomainName:(CDVInvokedUrlCommand*)command {
    CDVPluginResult* pluginResult = nil;
    bool validate = [[command.arguments objectAtIndex:0] boolValue];
    
    securityPolicy.validatesDomainName = validate;
    
    pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

#pragma mark - Methods

- (void) urlRequestWithMethod: (NSString *) method command: (CDVInvokedUrlCommand *) command {
    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    NSString *url = [command.arguments objectAtIndex:0];
    NSString *parameters = [command.arguments objectAtIndex:1];
    NSDictionary *headers = [command.arguments objectAtIndex:2];
    NSString *md5 = [headers objectForKey: HEADER_CONTECT_MD5];
    NSString *date = [headers objectForKey: HEADER_DATE];
    NSString *apiKey = [headers objectForKey: HEADER_API];
    
    NSString *canonicalRepresentation = [self canonicalRepresentation: headers method: method url: url params: parameters];
    NSData *signedData = PKCSSignBytesSHA256withRSA([canonicalRepresentation dataUsingEncoding: NSUTF8StringEncoding], getPrivateKeyRef(self.p12Data));
    NSString *xFataSignature = [signedData base64EncodedStringWithOptions: 0];
    
    NSError *serializationError = nil;
    NSMutableURLRequest *request = [manager.requestSerializer requestWithMethod: method URLString: url parameters: nil error:&serializationError];
    if (serializationError) {
        NSLog(@"Serialization error: %@", serializationError.localizedDescription);
        return;
    }
    [request setValue: @"en" forHTTPHeaderField: @"Accept-Language"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [request setValue: md5 forHTTPHeaderField: HEADER_CONTECT_MD5];
    [request setValue: date forHTTPHeaderField: HEADER_DATE];
    [request setValue: apiKey forHTTPHeaderField: HEADER_API];
    [request setValue: xFataSignature forHTTPHeaderField: HEADER_SIGNATURE];
    [request setHTTPBody: [parameters dataUsingEncoding: NSUTF8StringEncoding]];
    
    CordovaHttpPlugin* __weak weakSelf = self;
    __block NSURLSessionDataTask *dataTask = [manager dataTaskWithRequest:request
                                                           uploadProgress: nil
                                                         downloadProgress: nil
                                                        completionHandler:^(NSURLResponse * __unused response, id responseObject, NSError *error) {
                                                            if (error) {
                                                                NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
                                                                [self setResults: dictionary withTask: dataTask];
                                                                [dictionary setObject:[error localizedDescription] forKey:@"error"];
                                                                CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
                                                                [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                                                            }
                                                            else {
                                                                NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
                                                                [self setResults: dictionary withTask: dataTask];
                                                                [dictionary setObject:responseObject forKey:@"data"];
                                                                CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:dictionary];
                                                                [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                                                            }
                                                        }];
    [dataTask resume];
    
}

- (void)postJsonString:(CDVInvokedUrlCommand*)command {
    NSString *method = @"POST";
    [self urlRequestWithMethod: method command: command];
}

- (void)get:(CDVInvokedUrlCommand*)command {
    NSString *method = @"GET";
    [self urlRequestWithMethod: method command: command];
}

- (void)putJson:(CDVInvokedUrlCommand*)command {
    NSString *method = @"PUT";
    [self urlRequestWithMethod: method command: command];
}


- (void)post:(CDVInvokedUrlCommand*)command {
    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    manager.securityPolicy = securityPolicy;
    NSString *url = [command.arguments objectAtIndex:0];
    NSDictionary *parameters = [command.arguments objectAtIndex:1];
    NSDictionary *headers = [command.arguments objectAtIndex:2];
    [self setRequestHeaders: headers forManager: manager];
   
    CordovaHttpPlugin* __weak weakSelf = self;
    manager.responseSerializer = [TextResponseSerializer serializer];
    [manager POST:url parameters:parameters progress:nil success:^(NSURLSessionTask *task, id responseObject) {
        NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
        [self setResults: dictionary withTask: task];
        [dictionary setObject:responseObject forKey:@"data"];
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:dictionary];
        [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    } failure:^(NSURLSessionTask *task, NSError *error) {
        NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
        [self setResults: dictionary withTask: task];
        [dictionary setObject:[error localizedDescription] forKey:@"error"];
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
        [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)postJson:(CDVInvokedUrlCommand*)command {
   AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
   NSString *url = [command.arguments objectAtIndex:0];
   NSData *parameters = [command.arguments objectAtIndex:1];
   NSDictionary *headers = [command.arguments objectAtIndex:2];
    
   [headers setValue:@"application/json" forKey:@"Content-Type"]; //is not present in (void)post
   [self setRequestHeaders: headers forManager:manager];
   
   CordovaHttpPlugin* __weak weakSelf = self;
   manager.responseSerializer = [TextResponseSerializer serializer];
    [manager POST:url parameters:parameters progress:nil success:^(NSURLSessionTask *task, id responseObject) {
        NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
        [self setResults: dictionary withTask: task];
        [dictionary setObject:responseObject forKey:@"data"];
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:dictionary];
        [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    } failure:^(NSURLSessionTask *task, NSError *error) {
        NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
        [self setResults: dictionary withTask: task];
        [dictionary setObject:[error localizedDescription] forKey:@"error"];
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
        [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)put:(CDVInvokedUrlCommand*)command {
   AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
   NSString *url = [command.arguments objectAtIndex:0];
   NSDictionary *parameters = [command.arguments objectAtIndex:1];
   NSDictionary *headers = [command.arguments objectAtIndex:2];

   //[self setRequestHeaders: headers];
   [self setRequestHeaders: headers forManager:manager];

   CordovaHttpPlugin* __weak weakSelf = self;
   
   manager.responseSerializer = [TextResponseSerializer serializer];
   [manager PUT:url parameters:parameters success:^(NSURLSessionTask *task, id responseObject) {
      NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
      [self setResults: dictionary withTask: task];
      [dictionary setObject:responseObject forKey:@"data"];
      CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:dictionary];
      [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
   } failure:^(NSURLSessionTask *task, NSError *error) {
      NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
      [self setResults: dictionary withTask: task];
      [dictionary setObject:[error localizedDescription] forKey:@"error"];
      CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
      [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
   }];
}

- (void)delete:(CDVInvokedUrlCommand*)command {
   AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
   NSString *url = [command.arguments objectAtIndex:0];
   NSDictionary *parameters = [command.arguments objectAtIndex:1];
   NSDictionary *headers = [command.arguments objectAtIndex:2];
  [self setRequestHeaders: headers forManager:manager];
   
   CordovaHttpPlugin* __weak weakSelf = self;
   
   manager.responseSerializer = [TextResponseSerializer serializer];
   [manager DELETE:url parameters:parameters success:^(NSURLSessionTask *task, id responseObject) {
      NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
      [self setResults: dictionary withTask: task];
      [dictionary setObject:responseObject forKey:@"data"];
      CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:dictionary];
      [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
   } failure:^(NSURLSessionTask *task, NSError *error) {
      NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
      [self setResults: dictionary withTask: task];
      [dictionary setObject:[error localizedDescription] forKey:@"error"];
      CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
      [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
   }];
}

- (void)head:(CDVInvokedUrlCommand*)command {
    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    manager.securityPolicy = securityPolicy;
    NSString *url = [command.arguments objectAtIndex:0];
    NSDictionary *parameters = [command.arguments objectAtIndex:1];
    NSDictionary *headers = [command.arguments objectAtIndex:2];
    [self setRequestHeaders: headers forManager: manager];
    
    CordovaHttpPlugin* __weak weakSelf = self;
    
    manager.responseSerializer = [AFHTTPResponseSerializer serializer];
    [manager HEAD:url parameters:parameters success:^(NSURLSessionTask *task) {
        NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
        [self setResults: dictionary withTask: task];
        // no 'body' for HEAD request, omitting 'data'
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:dictionary];
        [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    } failure:^(NSURLSessionTask *task, NSError *error) {
        NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
        [self setResults: dictionary withTask: task];
        [dictionary setObject:[error localizedDescription] forKey:@"error"];
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
        [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)uploadFile:(CDVInvokedUrlCommand*)command {
    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    manager.securityPolicy = securityPolicy;
    NSString *url = [command.arguments objectAtIndex:0];
    NSDictionary *parameters = [command.arguments objectAtIndex:1];
    NSDictionary *headers = [command.arguments objectAtIndex:2];
    NSString *filePath = [command.arguments objectAtIndex: 3];
    NSString *name = [command.arguments objectAtIndex: 4];
    
    NSURL *fileURL = [NSURL URLWithString: filePath];
    
    [self setRequestHeaders: headers forManager: manager];
    
    CordovaHttpPlugin* __weak weakSelf = self;
    manager.responseSerializer = [TextResponseSerializer serializer];
    [manager POST:url parameters:parameters constructingBodyWithBlock:^(id<AFMultipartFormData> formData) {
        NSError *error;
        [formData appendPartWithFileURL:fileURL name:name error:&error];
        if (error) {
            NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
            [dictionary setObject:[NSNumber numberWithInt:500] forKey:@"status"];
            [dictionary setObject:@"Could not add file to post body." forKey:@"error"];
            CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
            [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
            return;
        }
    } progress:nil success:^(NSURLSessionTask *task, id responseObject) {
        NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
        [self setResults: dictionary withTask: task];
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:dictionary];
        [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    } failure:^(NSURLSessionTask *task, NSError *error) {
        NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
        [self setResults: dictionary withTask: task];
        [dictionary setObject:[error localizedDescription] forKey:@"error"];
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
        [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}


- (void)downloadFile:(CDVInvokedUrlCommand*)command {
    AFHTTPSessionManager *manager = [AFHTTPSessionManager manager];
    manager.securityPolicy = securityPolicy;
    NSString *url = [command.arguments objectAtIndex:0];
    NSDictionary *parameters = [command.arguments objectAtIndex:1];
    NSDictionary *headers = [command.arguments objectAtIndex:2];
    NSString *filePath = [command.arguments objectAtIndex: 3];
   
    [self setRequestHeaders: headers forManager: manager];
    
    if ([filePath hasPrefix:@"file://"]) {
        filePath = [filePath substringFromIndex:7];
    }
    
    CordovaHttpPlugin* __weak weakSelf = self;
    manager.responseSerializer = [AFHTTPResponseSerializer serializer];
    [manager GET:url parameters:parameters progress:nil success:^(NSURLSessionTask *task, id responseObject) {
        /*
         *
         * Licensed to the Apache Software Foundation (ASF) under one
         * or more contributor license agreements.  See the NOTICE file
         * distributed with this work for additional information
         * regarding copyright ownership.  The ASF licenses this file
         * to you under the Apache License, Version 2.0 (the
         * "License"); you may not use this file except in compliance
         * with the License.  You may obtain a copy of the License at
         *
         *   http://www.apache.org/licenses/LICENSE-2.0
         *
         * Unless required by applicable law or agreed to in writing,
         * software distributed under the License is distributed on an
         * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
         * KIND, either express or implied.  See the License for the
         * specific language governing permissions and limitations
         * under the License.
         *
         * Modified by Andrew Stephan for Sync OnSet
         *
        */
        // Download response is okay; begin streaming output to file
        NSString* parentPath = [filePath stringByDeletingLastPathComponent];
        
        // create parent directories if needed
        NSError *error;
        if ([[NSFileManager defaultManager] createDirectoryAtPath:parentPath withIntermediateDirectories:YES attributes:nil error:&error] == NO) {
            NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
            [dictionary setObject:[NSNumber numberWithInt:500] forKey:@"status"];
            if (error) {
                [dictionary setObject:[NSString stringWithFormat:@"Could not create path to save downloaded file: %@", [error localizedDescription]] forKey:@"error"];
            } else {
                [dictionary setObject:@"Could not create path to save downloaded file" forKey:@"error"];
            }
            CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
            [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
            return;
        }
        NSData *data = (NSData *)responseObject;
        if (![data writeToFile:filePath atomically:YES]) {
            NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
            [dictionary setObject:[NSNumber numberWithInt:500] forKey:@"status"];
            [dictionary setObject:@"Could not write the data to the given filePath." forKey:@"error"];
            CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
            [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
            return;
        }
   
        id filePlugin = [self.commandDelegate getCommandInstance:@"File"];
        NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
        [self setResults: dictionary withTask: task];
        [dictionary setObject:[filePlugin getDirectoryEntry:filePath isDirectory:NO] forKey:@"file"];
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:dictionary];
        [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    } failure:^(NSURLSessionTask *task, NSError *error) {
        NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
        [self setResults: dictionary withTask: task];
        [dictionary setObject:[error localizedDescription] forKey:@"error"];
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:dictionary];
        [weakSelf.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

@end
