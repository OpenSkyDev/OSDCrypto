/*!
 * OSDCrypto.m
 *
 * Copyright (c) 2014 OpenSky, LLC
 *
 * Created by Skylar Schipper on 2/7/14
 */

#import "OSDCrypto.h"
#import <CommonCrypto/CommonCrypto.h>

NS_INLINE NSString *OSD_BufferToString(unsigned char *buffer, size_t length) {
    NSMutableString *string = [NSMutableString stringWithCapacity:(length * 2)];
    for (NSUInteger idx = 0; idx < length; idx++) {
        [string appendFormat:@"%02X",buffer[idx]];
    }
    return [string copy];
}

@implementation OSDCrypto

+ (NSString *)MD5Data:(NSData *)data {
    if (!data) {
        return nil;
    }
    CC_LONG length = (CC_LONG)data.length;
    const void *cData = data.bytes;
    unsigned char *buffer = malloc(CC_MD5_DIGEST_LENGTH);
    CC_MD5(cData, length, buffer);
    NSString *string = OSD_BufferToString(buffer, CC_MD5_DIGEST_LENGTH);
    free(buffer);
    return string;
}
+ (NSString *)SHA1Data:(NSData *)data {
    if (!data) {
        return nil;
    }
    CC_LONG length = (CC_LONG)data.length;
    const void *cData = data.bytes;
    unsigned char *buffer = malloc(CC_SHA1_DIGEST_LENGTH);
    CC_SHA1(cData, length, buffer);
    NSString *string = OSD_BufferToString(buffer, CC_SHA1_DIGEST_LENGTH);
    free(buffer);
    return string;
}
+ (NSString *)SHA256Data:(NSData *)data {
    if (!data) {
        return nil;
    }
    CC_LONG length = (CC_LONG)data.length;
    const void *cData = data.bytes;
    unsigned char *buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256(cData, length, buffer);
    NSString *string = OSD_BufferToString(buffer, CC_SHA256_DIGEST_LENGTH);
    free(buffer);
    return string;
}
+ (NSString *)SHA512Data:(NSData *)data {
    if (!data) {
        return nil;
    }
    CC_LONG length = (CC_LONG)data.length;
    const void *cData = data.bytes;
    unsigned char *buffer = malloc(CC_SHA512_DIGEST_LENGTH);
    CC_SHA512(cData, length, buffer);
    NSString *string = OSD_BufferToString(buffer, CC_SHA512_DIGEST_LENGTH);
    free(buffer);
    return string;
}

@end

@implementation OSDCrypto (OSDCryptoConvenience)

+ (NSString *)randomHashOfType:(OSDCryptoHash)type {
    NSString *string = [[NSUUID UUID] UUIDString];
    return [self hashString:string type:type];
}
+ (NSString *)hashString:(NSString *)string type:(OSDCryptoHash)type {
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    switch (type) {
        case OSDCrypto_MD5:
            return [self MD5Data:data];
            break;
        case OSDCrypto_SHA1:
            return [self SHA1Data:data];
            break;
        case OSDCrypto_SHA256:
            return [self SHA256Data:data];
            break;
        case OSDCrypto_SHA512:
            return [self SHA512Data:data];
            break;
    }
    return nil;
}
+ (NSString *)hashString:(NSString *)string salt:(NSString *)salt type:(OSDCryptoHash)type {
    NSString *fullString = [NSString stringWithFormat:@"%@&%@",string,salt];
    return [self hashString:fullString type:type];
}

@end
