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
#import "OSDCoreCrypto.h"
#import "OSDAESCrypto.h"

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

+ (NSData *)encryptData:(NSData *)data password:(NSString *)password salt:(NSData **)salt initializationVector:(NSData **)iv error:(NSError **)error {
    NSParameterAssert(data);
    NSParameterAssert(password);
    NSParameterAssert(salt);
    NSParameterAssert(iv);

    CFDataRef outSalt = NULL;
    CFDataRef outIV = NULL;
    CFErrorRef err = NULL;
    CFDataRef output = OSDAESCreateEncryptedData((__bridge CFDataRef)(data), (__bridge CFStringRef)password, &outSalt, &outIV, &err);

    if (salt && outSalt) {
        *salt = (__bridge_transfer NSData *)outSalt;
    }
    if (iv && outIV) {
        *iv = (__bridge_transfer NSData *)outIV;
    }
    if (error && err) {
        *error = (__bridge_transfer NSError *)err;
    }

    return (__bridge_transfer NSData *)output;
}

+ (NSData *)decryptData:(NSData *)data password:(NSString *)password salt:(NSData *)salt initializationVector:(NSData *)iv error:(NSError **)error {
    NSParameterAssert(data);
    NSParameterAssert(password);
    NSParameterAssert(salt);

    CFErrorRef err = NULL;
    CFStringRef pw = (__bridge CFStringRef)(password);
    CFDataRef st = (__bridge CFDataRef)(salt);
    CFDataRef r_iv = (__bridge CFDataRef)(iv);
    CFDataRef output = OSDAESCreateDecryptedData((__bridge CFDataRef)(data), pw, st, r_iv, &err);

    if (error && err) {
        *error = (__bridge_transfer NSError *)err;
    }

    return (__bridge_transfer NSData *)output;
}

@end

@implementation OSDCrypto (OSDCryptoConvenience)

+ (NSString *)randomHashOfType:(OSDCryptoHash)type {
    CFDataRef data = OSDCreateRandomData(256);
    NSString *string = (__bridge_transfer id)OSDCryptoCreateHashForData(data, type);
    CFRelease(data);
    return string;
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
    uint32_t dataLength = (uint32_t)CFDataGetLength(data);
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
