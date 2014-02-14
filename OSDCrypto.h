/*!
 * OSDCrypto.h
 *
 * Copyright (c) 2014 OpenSky, LLC
 *
 * Created by Skylar Schipper on 2/7/14
 */

#ifndef OSDCrypto_h
#define OSDCrypto_h

#import <Foundation/Foundation.h>

/*!
 *  Wraps CommonCrypto in some helper methods
 */
@interface OSDCrypto : NSObject

/*!
 *  MD5 the passed data
 *
 *  \param data The data to hash
 *
 *  \return The MD5 of the data
 */
+ (NSString *)MD5Data:(NSData *)data;
/*!
 *  SHA1 the passed data
 *
 *  \param data The data to hash
 *
 *  \return The SHA1 of the data
 */
+ (NSString *)SHA1Data:(NSData *)data;
/*!
 *  SHA256 the passed data
 *
 *  \param data The data to hash
 *
 *  \return The SHA256 of the data
 */
+ (NSString *)SHA256Data:(NSData *)data;
/*!
 *  SHA512 the passed data
 *
 *  \param data The data to hash
 *
 *  \return The SHA512 of the data
 */
+ (NSString *)SHA512Data:(NSData *)data;

@end

typedef NS_ENUM(NSInteger, OSDCryptoHash) {
    OSDCrypto_MD5    = 0,
    OSDCrypto_SHA1   = 1,
    OSDCrypto_SHA256 = 2,
    OSDCrypto_SHA512 = 3
};

@interface OSDCrypto (OSDCryptoConvenience)

+ (NSString *)randomHashOfType:(OSDCryptoHash)type;
+ (NSString *)hashString:(NSString *)string type:(OSDCryptoHash)type;
+ (NSString *)hashString:(NSString *)string salt:(NSString *)salt type:(OSDCryptoHash)type;

@end

#endif
