//
//  main.m
//  OSDCryptoApp
//
//  Created by Skylar Schipper on 7/15/14.
//  Copyright (c) 2014 OpenSky, LLC. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "OSDCrypto.h"
#import "OSDCoreCrypto.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        CFDataRef data = (__bridge CFDataRef)[@"test" dataUsingEncoding:NSUTF8StringEncoding];
        
        CFRelease(OSDCryptoCreateHashForData(data, OSDCryptoHashMD5));
        CFRelease(OSDCryptoCreateHashForData(data, OSDCryptoHashSHA1));
        CFRelease(OSDCryptoCreateHashForData(data, OSDCryptoHashSHA256));
        CFRelease(OSDCryptoCreateHashForData(data, OSDCryptoHashSHA256));
        
        NSData *sig = [@"test_sig" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *key = [@"test_key" dataUsingEncoding:NSUTF8StringEncoding];
        const void *cSig = sig.bytes;
        const void *cKey = key.bytes;
        uint32_t sLen = (uint32_t)sig.length;
        uint32_t kLen = (uint32_t)key.length;
        CFRelease(OSDCryptoCreateHMACSHA1Hash(cSig, sLen, cKey, kLen));
        
        NSString *path = [[[[[NSString stringWithFormat:@"%s",__FILE__] stringByReplacingOccurrencesOfString:@"main.m" withString:@""] stringByAppendingPathComponent:@".."] stringByAppendingPathComponent:@"OSDCrypto Tests"] stringByAppendingPathComponent:@"image.jpg"];
        if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
            NSLog(@"** CANT GET FILE AT %@",path);
        }
        
        CFURLRef URL = (__bridge CFURLRef)[NSURL fileURLWithPath:path];
        CFRelease(OSDCryptoCreateMD5HashForFile(URL));
    }
    return 0;
}

