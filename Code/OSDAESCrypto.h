//
//  OSDAESCrypto.h
//  OSDCryptoApp
//
//  Created by Skylar Schipper on 6/1/15.
//  Copyright (c) 2015 OpenSky, LLC. All rights reserved.
//

#ifndef OSDCrypto_OSDAESCrypto_h
#define OSDCrypto_OSDAESCrypto_h

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wauto-import"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#pragma clang diagnostic pop

CF_EXTERN_C_BEGIN

/**
 *  Create a random blob of data.
 */
CFDataRef OSDCreateRandomData(CFIndex);

/**
 *  Create an AES key for the password and salt
 */
CFDataRef OSDAESCreateKey(CFStringRef, CFDataRef);

/**
 *  AES Encrypt Data
 *
 *  Uses a 256 bit key
 *
 *  @param data - The Data to encrypt.  (Required)
 *  @param password - The password used to generate the key.  (Required)
 *  @param (out) salt - Pointer to a data blob to store the salt used to generate the key.  (Required)
 *  @param (out) iv - The Initalization Vector pointer used to encrypt the data.  (Required)
 *  @param (out) error - An error pointer if the encrypt fails. (Optional)
 */
CFDataRef OSDAESCreateEncryptedData(CFDataRef, CFStringRef, CFDataRef *, CFDataRef *, CFErrorRef *);

/**
 *  AES Encrypt Data
 *
 *  @param data - The Data to encrypt.  (Required)
 *  @param password - The password used to generate the key.  (Required)
 *  @param salt - Salt that was used to create the key.  (Required)
 *  @param iv - The Initalization Vector used to encrypt the data.  (Required)
 *  @param (out) error - An error pointer if the encrypt fails. (Optional)
 */
CFDataRef OSDAESCreateDecryptedData(CFDataRef, CFStringRef, CFDataRef, CFDataRef, CFErrorRef *);

CF_EXPORT uint const kOSDAESKeyRounds;
CF_EXPORT CFIndex const kOSDAESSaltSize;

// MARK: - Errors
CF_EXPORT CFStringRef const OSDAESErrorDomain;

CF_EXPORT CFIndex const OSDAESError_FailedToCreateKey;
CF_EXPORT CFIndex const OSDAESError_CryptorStatus;

CF_EXTERN_C_END

#endif
