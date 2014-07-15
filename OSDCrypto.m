/*!
 * OSDCrypto.m
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 OpenSky Development
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
*/

#import "OSDCrypto.h"
#import <CommonCrypto/CommonCrypto.h>

@implementation OSDCrypto

+ (NSString *)MD5Data:(NSData *)data {
    return (__bridge_transfer id)OSDCryptoCreateHashForData((__bridge CFDataRef)data, OSDCryptoHashMD5);
}
+ (NSString *)SHA1Data:(NSData *)data {
    return (__bridge_transfer id)OSDCryptoCreateHashForData((__bridge CFDataRef)data, OSDCryptoHashSHA1);
}
+ (NSString *)SHA256Data:(NSData *)data {
    return (__bridge_transfer id)OSDCryptoCreateHashForData((__bridge CFDataRef)data, OSDCryptoHashSHA256);
}
+ (NSString *)SHA512Data:(NSData *)data {
    return (__bridge_transfer id)OSDCryptoCreateHashForData((__bridge CFDataRef)data, OSDCryptoHashSHA512);
}

@end

@implementation OSDCrypto (OSDCryptoConvenience)

+ (NSString *)randomHashOfType:(OSDCryptoHash)type {
    NSString *string = [[NSUUID UUID] UUIDString];
    return [self hashString:string type:type];
}
+ (NSString *)hashString:(NSString *)string type:(OSDCryptoHash)type {
    return (__bridge_transfer id)OSDCryptoCreateHashForData((__bridge CFDataRef)[string dataUsingEncoding:NSUTF8StringEncoding], type);
}
+ (NSString *)hashString:(NSString *)string salt:(NSString *)salt type:(OSDCryptoHash)type {
    NSString *fullString = [NSString stringWithFormat:@"%@&%@",string,salt];
    return [self hashString:fullString type:type];
}

@end

CFStringRef OSDCryptoCreateHashForData(CFDataRef data, OSDCryptoHash type) {
    const void *cData = CFDataGetBytePtr(data);
    CC_LONG dataLength = (CC_LONG)CFDataGetLength(data);
    switch (type) {
        case OSDCryptoHashMD5:
            return OSDCryptoCreateMD5Hash(cData, dataLength);
            break;
        case OSDCryptoHashSHA1:
            return OSDCryptoCreateSHA1Hash(cData, dataLength);
            break;
        case OSDCryptoHashSHA256:
            return OSDCryptoCreateSHA256Hash(cData, dataLength);
            break;
        case OSDCryptoHashSHA512:
            return OSDCryptoCreateSHA512Hash(cData, dataLength);
            break;
        default:
            break;
    }
    return NULL;
}

CFStringRef OSDCryptoCreateMD5Hash(const void *data, uint32_t length) {
    unsigned char *buffer = malloc(CC_MD5_DIGEST_LENGTH);
    CC_MD5(data, length, buffer);
    CFStringRef string = OSDCryptoCreateStringFromBuffer(buffer, CC_MD5_DIGEST_LENGTH);
    free(buffer);
    return string;
}

CFStringRef OSDCryptoCreateSHA1Hash(const void *data, uint32_t length) {
    unsigned char *buffer = malloc(CC_SHA1_DIGEST_LENGTH);
    CC_SHA1(data, length, buffer);
    CFStringRef string = OSDCryptoCreateStringFromBuffer(buffer, CC_SHA1_DIGEST_LENGTH);
    free(buffer);
    return string;
}

CFStringRef OSDCryptoCreateSHA256Hash(const void *data, uint32_t length) {
    unsigned char *buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256(data, length, buffer);
    CFStringRef string = OSDCryptoCreateStringFromBuffer(buffer, CC_SHA256_DIGEST_LENGTH);
    free(buffer);
    return string;
}

CFStringRef OSDCryptoCreateSHA512Hash(const void *data, uint32_t length) {
    unsigned char *buffer = malloc(CC_SHA512_DIGEST_LENGTH);
    CC_SHA512(data, length, buffer);
    CFStringRef string = OSDCryptoCreateStringFromBuffer(buffer, CC_SHA512_DIGEST_LENGTH);
    free(buffer);
    return string;
}

CFStringRef OSDCryptoCreateStringFromBuffer(unsigned char *buffer, size_t length) {
    CFMutableStringRef string = CFStringCreateMutable(kCFAllocatorDefault, 0);
    for (size_t idx = 0; idx < length; idx++) {
        CFStringAppendFormat(string, NULL, CFSTR("%02X"),buffer[idx]);
    }
    CFStringRef final = CFStringCreateCopy(kCFAllocatorDefault, string);
    CFRelease(string);
    return final;
}

CFStringRef OSDCryptoCreateHMACSHA1Hash(const void *data, uint32_t dataLength, const void *key, uint32_t keyLength) {
    unsigned char *buffer = malloc(CC_SHA1_DIGEST_LENGTH);
    CCHmac(kCCHmacAlgSHA1, key, keyLength, data, dataLength, buffer);
    CFStringRef string = OSDCryptoCreateStringFromBuffer(buffer, CC_SHA1_DIGEST_LENGTH);
    free(buffer);
    return string;
}

CFStringRef OSDCryptoCreateMD5HashForFile(CFURLRef fileURL) {
    CFReadStreamRef readStrem = CFReadStreamCreateWithFile(kCFAllocatorDefault, fileURL);
    if (readStrem == NULL) {
        return NULL;
    }
    if (!CFReadStreamOpen(readStrem)) {
        CFRelease(readStrem);
        return NULL;
    }
    
    CC_MD5_CTX hashCtx;
    CC_MD5_Init(&hashCtx);
    
    size_t readSize = 4096;
    
    BOOL hasMoreData = YES;
    UInt8 *buffer = malloc(readSize);
    while (hasMoreData) {
        CFIndex byteCount = CFReadStreamRead(readStrem, buffer, readSize);
        if (byteCount == -1) {
            break;
        }
        if (byteCount == 0) {
            hasMoreData = NO;
            continue;
        }
        CC_MD5_Update(&hashCtx, buffer, (CC_LONG)byteCount);
        memset(buffer, 0, readSize);
    }
    free(buffer);
    
    CFReadStreamClose(readStrem);
    CFRelease(readStrem);
    
    CFStringRef final = NULL;
    
    if (!hasMoreData) {
        void *finalBuffer = malloc(CC_MD5_DIGEST_LENGTH);
        
        CC_MD5_Final(finalBuffer, &hashCtx);
        
        final = OSDCryptoCreateStringFromBuffer(finalBuffer, CC_MD5_DIGEST_LENGTH);
        
        free(finalBuffer);
    }
    
    return final;
}
