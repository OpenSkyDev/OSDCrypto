//
//  OSDCrypto_Tests.m
//  OSDCrypto Tests
//
//  Created by Skylar Schipper on 7/15/14.
//  Copyright (c) 2014 OpenSky, LLC. All rights reserved.
//

@import XCTest;

#import "OSDCrypto.h"

@interface OSDCrypto_Tests : XCTestCase

@end

@implementation OSDCrypto_Tests

- (void)testMD5 {
    XCTAssertEqualObjects([OSDCrypto MD5Data:[@"test" dataUsingEncoding:NSUTF8StringEncoding]], @"098F6BCD4621D373CADE4E832627B4F6");
}
- (void)testSHA1 {
    XCTAssertEqualObjects([OSDCrypto SHA1Data:[@"test" dataUsingEncoding:NSUTF8StringEncoding]], @"A94A8FE5CCB19BA61C4C0873D391E987982FBBD3");
}
- (void)testSHA256 {
    XCTAssertEqualObjects([OSDCrypto SHA256Data:[@"test" dataUsingEncoding:NSUTF8StringEncoding]], @"9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08");
}
- (void)testSHA512 {
    XCTAssertEqualObjects([OSDCrypto SHA512Data:[@"test" dataUsingEncoding:NSUTF8StringEncoding]], @"EE26B0DD4AF7E749AA1A8EE3C10AE9923F618980772E473F8819A5D4940E0DB27AC185F8A0E1D5F84F88BC887FD67B143732C304CC5FA9AD8E6F57F50028A8FF");
}

- (void)testCMD5 {
    CFDataRef data = (__bridge CFDataRef)[@"test" dataUsingEncoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects((__bridge id)OSDCryptoCreateHashForData(data, OSDCryptoHashMD5), @"098F6BCD4621D373CADE4E832627B4F6");
}
- (void)testCSHA1 {
    CFDataRef data = (__bridge CFDataRef)[@"test" dataUsingEncoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects((__bridge id)OSDCryptoCreateHashForData(data, OSDCryptoHashSHA1), @"A94A8FE5CCB19BA61C4C0873D391E987982FBBD3");
}
- (void)testCSHA256 {
    CFDataRef data = (__bridge CFDataRef)[@"test" dataUsingEncoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects((__bridge id)OSDCryptoCreateHashForData(data, OSDCryptoHashSHA256), @"9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08");
}
- (void)testCSHA512 {
    CFDataRef data = (__bridge CFDataRef)[@"test" dataUsingEncoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects((__bridge id)OSDCryptoCreateHashForData(data, OSDCryptoHashSHA512), @"EE26B0DD4AF7E749AA1A8EE3C10AE9923F618980772E473F8819A5D4940E0DB27AC185F8A0E1D5F84F88BC887FD67B143732C304CC5FA9AD8E6F57F50028A8FF");
}

- (void)testHMACSHA1 {
    NSData *sig = [@"test_sig" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *key = [@"test_key" dataUsingEncoding:NSUTF8StringEncoding];
    
    const void *cSig = sig.bytes;
    const void *cKey = key.bytes;
    
    uint32_t sLen = (uint32_t)sig.length;
    uint32_t kLen = (uint32_t)key.length;
    
    CFStringRef str = OSDCryptoCreateHMACSHA1Hash(cSig, sLen, cKey, kLen);
    
    XCTAssertEqualObjects((__bridge id)str, @"181074CCCA336D75EE58DA2AF18737FD33C796D4");
    
    CFRelease(str);
}
- (void)testFileMD5 {
    NSURL *fileURL = [[NSBundle bundleForClass:[self class]] URLForResource:@"image" withExtension:@"jpg"];
    
    XCTAssertNotNil(fileURL);
    XCTAssertTrue([[NSFileManager defaultManager] fileExistsAtPath:[fileURL path]]);
    
    NSString *hash = (__bridge_transfer id)OSDCryptoCreateMD5HashForFile((__bridge CFURLRef)fileURL);
    
    XCTAssertNotNil(hash);
    XCTAssertEqualObjects(hash, @"3AE2480035561E159F78D5FF374804C1");
}

@end
