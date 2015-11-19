//
//  OSDCrypto_Tests.m
//  OSDCrypto Tests
//
//  Created by Skylar Schipper on 7/15/14.
//  Copyright (c) 2014 OpenSky, LLC. All rights reserved.
//

@import XCTest;

#import "OSDCrypto.h"
#import "OSDCoreCrypto.h"
#import "OSDAESCrypto.h"

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
- (void)testFileSHA1 {
    NSURL *fileURL = [[NSBundle bundleForClass:[self class]] URLForResource:@"image" withExtension:@"jpg"];

    XCTAssertNotNil(fileURL);
    XCTAssertTrue([[NSFileManager defaultManager] fileExistsAtPath:[fileURL path]]);

    NSString *hash = (__bridge_transfer id)OSDCryptoCreateSHA1HashForFile((__bridge CFURLRef)fileURL);

    XCTAssertNotNil(hash);
    XCTAssertEqualObjects(hash, @"6481A3B8D7F0A2F3F4FFE0E5BF10696B0046C7B1");
}

- (void)testRandomBytes {
    NSUInteger count = 1000;
    NSMutableSet *set = [NSMutableSet setWithCapacity:count];

    for (NSUInteger idx = 0; idx < count; idx++) {
        NSData *data = (__bridge_transfer NSData *)OSDCreateRandomData(32);
        XCTAssertNotNil(data);
        XCTAssertFalse([set containsObject:data]);
        [set addObject:data];
    }
}

- (void)testKeyGeneration {
    NSString *password = @"super-sekretz";
    NSData *salt = (__bridge_transfer NSData *)OSDCreateRandomData(128);

    NSData *gen_one = (__bridge_transfer NSData *)OSDAESCreateKey((__bridge CFStringRef)password, (__bridge CFDataRef)salt);
    NSData *gen_two = (__bridge_transfer NSData *)OSDAESCreateKey((__bridge CFStringRef)password, (__bridge CFDataRef)salt);

    XCTAssertEqualObjects(gen_one, gen_two);
}

- (void)testAESEncryption {
    NSData *message = [@"My super secret message" dataUsingEncoding:NSUTF8StringEncoding];
    CFStringRef password = CFSTR("super-sekretz-2");
    CFDataRef salt = NULL;
    CFDataRef iv = NULL;

    NSData *data = (__bridge_transfer NSData *)OSDAESCreateEncryptedData((__bridge CFDataRef)message, password, &salt, &iv, NULL);

    XCTAssertNotNil(data);

    NSData *inverse = (__bridge_transfer NSData *)OSDAESCreateDecryptedData((__bridge CFDataRef)data, password, salt, iv, NULL);

    XCTAssertNotNil(inverse);
    XCTAssertEqualObjects(message, inverse);

    CFRelease(salt);
    CFRelease(iv);
}

- (void)testAESEncryptionWrapers {
    NSData *message = [@"This is super sekret" dataUsingEncoding:NSUTF8StringEncoding];
    NSString *password = @"password-1";

    NSData *salt = nil;
    NSData *iv = nil;
    NSData *encrypted = [OSDCrypto encryptData:message password:password salt:&salt initializationVector:&iv error:NULL];

    XCTAssertNotNil(encrypted);

    NSData *decrypted = [OSDCrypto decryptData:encrypted password:password salt:salt initializationVector:iv error:NULL];

    XCTAssertNotNil(decrypted);
    XCTAssertEqualObjects(message, decrypted);
}

/*

 // This is broken currently

- (void)testAESFromDisk {
    NSString *password = @"1234567890abcdefghijklmnopqrstuvwxyz";

    NSData *info = [NSData dataWithContentsOfFile:[[[NSBundle bundleForClass:self.class] URLForResource:@"test" withExtension:@"dat"] path]];

    XCTAssertNotNil(info);

    NSDictionary *hash = [NSKeyedUnarchiver unarchiveObjectWithData:info];

    XCTAssertNotNil(hash);

    NSData *iv = hash[@"iv"];
    NSData *salt = hash[@"salt"];
    NSData *data = hash[@"data"];

    NSData *raw = [OSDCrypto decryptData:data password:password salt:salt initializationVector:iv error:NULL];

    XCTAssertNotNil(raw);

    NSArray *content = [NSKeyedUnarchiver unarchiveObjectWithData:raw];

    NSArray *valid = @[
                       @"1638D494-B91E-404B-9A62-4584C01A3B6F",
                       @"7B1DEAB5-ACC2-40B9-B444-65FA3B860BFE",
                       @"21AFA5A0-68F4-44DC-B9AB-D50AEB0028C2",
                       @"3CFF946F-98B7-4EFD-A570-851F0AAC01ED",
                       @"371C30F4-8D24-4FFF-B38F-4EFC2F401DB2",
                       @"58DCB357-C968-427D-8A40-4838EB74D348",
                       @"CEBD3FBA-5D6C-4602-9BFF-748FCAF7480E",
                       @"5829365C-8165-4C86-91A1-AC4E24A915F8",
                       @"0760B1AF-3AC6-4313-AEC5-DCCA0AB873D4",
                       @"E423109D-6361-48F5-AF6C-9FA06C1BEA88",
                       @"F2B86B13-F805-4B86-A2FA-79C76478DCD6",
                       @"87C2CAA6-2AB3-4C43-87C2-34523BDE3FE3",
                       @"ACCB9C94-D1AC-488C-A95D-87D28BB7B8D7",
                       @"7729D757-A14B-4D1C-964E-1B22EDE7A0CF",
                       @"2494ADE4-4BDA-442F-8215-3F06E6484616",
                       @"35800236-BD70-4F9D-B36B-552D8FEA03BE",
                       @"4DB09348-FD87-40D1-97D1-5E38D91F7945",
                       @"438C1930-8B58-427E-8077-5DE44B354FE2",
                       @"A993CD4B-35F0-4A3B-9046-996D16692743",
                       @"8605D7AA-93B2-46AC-A441-AE30EB875DFA",
                       @"9A823542-789F-4340-945A-4A57DBFCA5C4",
                       @"4F1F2068-F219-4ECB-824F-9766AAF7861A",
                       @"F1F50109-86CE-41CE-82BC-46B0267390D4",
                       @"7A509FE3-B75E-4172-A625-27B64359E832"
                       ];

    XCTAssertEqualObjects(content, valid);
}

 
 */

@end
