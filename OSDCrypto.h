/*!
 * OSDCrypto.h
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
