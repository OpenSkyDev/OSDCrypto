//
//  OSDCoreCrypto.h
//  OSDCryptoApp
//
//  Created by Skylar Schipper on 6/1/15.
//  Copyright (c) 2015 OpenSky, LLC. All rights reserved.
//

#ifndef OSDCrypto_OSDCoreCrypto_h
#define OSDCrypto_OSDCoreCrypto_h

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wauto-import"

#include <CoreFoundation/CoreFoundation.h>

#pragma clang diagnostic pop

CF_EXTERN_C_BEGIN

/**
 *  Create a MD5
 *
 *  (data, length)
 */
CFStringRef OSDCryptoCreateMD5Hash(const void *, uint32_t);

/**
 *  Create a SHA1
 *
 *  (data, length)
 */
CFStringRef OSDCryptoCreateSHA1Hash(const void *, uint32_t);

/**
 *  Create a SHA256
 *
 *  (data, length)
 */
CFStringRef OSDCryptoCreateSHA256Hash(const void *, uint32_t);

/**
 *  Create a SHA512
 *
 *  (data, length)
 */
CFStringRef OSDCryptoCreateSHA512Hash(const void *, uint32_t);

/**
 *  Create a HMAC-SHA1
 *
 *  (data, length, key, key-length)
 */
CFStringRef OSDCryptoCreateHMACSHA1Hash(const void *, uint32_t, const void *, uint32_t);

/**
 *  Create a CFStringRef of the hex digest.  Lenght of the sting (hard cap).
 *
 *  (buffer, length)
 */
CFStringRef OSDCryptoCreateStringFromBuffer(unsigned char *, size_t);

/**
 *  MD5 a file on the file system
 *
 *  (URL)
 */
CFStringRef OSDCryptoCreateMD5HashForFile(CFURLRef);

/**
 *  SHA1 a file on the file system
 *
 *  (URL)
 */
CFStringRef OSDCryptoCreateSHA1HashForFile(CFURLRef fileURL);

CF_EXPORT size_t const OSDCryptoFileHashBockSize;

CF_EXTERN_C_END

#endif 
