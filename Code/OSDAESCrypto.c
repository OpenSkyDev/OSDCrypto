//
//  OSDAESCrypto.c
//  OSDCryptoApp
//
//  Created by Skylar Schipper on 6/1/15.
//  Copyright (c) 2015 OpenSky, LLC. All rights reserved.
//

#include <CommonCrypto/CommonCrypto.h>

#include "OSDAESCrypto.h"

CFDataRef __OSDAESCreateData(CCOperation, CFDataRef, CFStringRef, CFDataRef *, CFDataRef *, CFErrorRef *);

uint const kOSDAESKeyRounds = 10000;
CFIndex const kOSDAESSaltSize = 8;
CFStringRef const OSDAESErrorDomain = CFSTR("OSDAESErrorDomain");

CFIndex const OSDAESError_FailedToCreateKey = 1;
CFIndex const OSDAESError_CryptorStatus = 2;

CFDataRef OSDCreateRandomData(CFIndex length) {
    uint8_t *buffer = malloc(length);

    int result = SecRandomCopyBytes(kSecRandomDefault, length, buffer);

    if (result != 0) {
        fprintf(stderr, "Failed to generate random data of lenght %ld\n",length);
        free(buffer);
        return NULL;
    }

    CFDataRef data = CFDataCreate(kCFAllocatorDefault, buffer, length);

    free(buffer);

    return data;
}

CFDataRef OSDAESCreateKey(CFStringRef password, CFDataRef salt) {
    const char *c_pw = CFStringGetCStringPtr(password, kCFStringEncodingUTF8);
    size_t pw_length = strlen(c_pw);
    const UInt8 *c_st = CFDataGetBytePtr(salt);
    size_t st_length = CFDataGetLength(salt);
    uint8_t *buffer = malloc(kCCKeySizeAES256);

    int result = CCKeyDerivationPBKDF(kCCPBKDF2, c_pw, pw_length, c_st, st_length, kCCPRFHmacAlgSHA512, kOSDAESKeyRounds, buffer, kCCKeySizeAES256);

    if (result != kCCSuccess) {
        fprintf(stderr, "FaIled to create key with status %d\n",result);
        free(buffer);
        return NULL;
    }

    CFDataRef data = CFDataCreate(kCFAllocatorDefault, buffer, kCCKeySizeAES256);

    free(buffer);

    return data;
}

CFDataRef OSDAESCreateEncryptedData(CFDataRef data, CFStringRef password, CFDataRef *salt, CFDataRef *iv, CFErrorRef *err) {
    assert(data);
    assert(password);
    assert(salt);
    assert(iv);

    return __OSDAESCreateData(kCCEncrypt, data, password, salt, iv, err);
}

CFDataRef OSDAESCreateDecryptedData(CFDataRef data, CFStringRef password, CFDataRef salt, CFDataRef iv, CFErrorRef *err) {
    assert(data);
    assert(password);
    assert(salt);

    return __OSDAESCreateData(kCCDecrypt, data, password, &salt, &iv, err);
}

CFDataRef __OSDAESCreateData(CCOperation opp, CFDataRef data, CFStringRef password, CFDataRef *ioSalt, CFDataRef *ioIV, CFErrorRef *err) {
    size_t b_size = CFDataGetLength(data) + kCCBlockSizeAES128;
    size_t real_size = 0;

    if (opp == kCCEncrypt) {
        *ioIV = OSDCreateRandomData(kCCBlockSizeAES128);
        *ioSalt = OSDCreateRandomData(kOSDAESSaltSize);
    } else {
        assert(*ioSalt);
    }

    CFDataRef key = OSDAESCreateKey(password, *ioSalt);

    if (!key) {
        if (opp == kCCEncrypt) {
            CFRelease(*ioIV);
            CFRelease(*ioSalt);
            *ioIV = NULL;
            *ioSalt = NULL;
        }
        if (err != NULL) {
            *err = CFErrorCreate(kCFAllocatorDefault, OSDAESErrorDomain, OSDAESError_FailedToCreateKey, NULL);
        }
        return NULL;
    }

    const void *ivPtr = (void *)CFDataGetBytePtr(*ioIV);
    void *buffer = calloc(b_size, sizeof(char));

    const void *in_data = CFDataGetBytePtr(data);
    size_t in_data_size = CFDataGetLength(data);

    CCCryptorStatus status = CCCrypt(opp, kCCAlgorithmAES, kCCOptionPKCS7Padding | kCCOptionECBMode, key, kCCKeySizeAES256, ivPtr, in_data, in_data_size, buffer, b_size, &real_size);

    if (status != kCCSuccess) {
        if (opp == kCCEncrypt) {
            CFRelease(*ioIV);
            CFRelease(*ioSalt);
            *ioIV = NULL;
            *ioSalt = NULL;
        }
        if (opp == kCCEncrypt) {
            fprintf(stderr, "Failed to encrypt data with status %d\n",status);
        } else {
            fprintf(stderr, "Failed to decrypt data with status %d\n",status);
        }

        free(buffer);

        if (err != NULL) {
            *err = CFErrorCreate(kCFAllocatorDefault, OSDAESErrorDomain, OSDAESError_CryptorStatus, NULL);
        }

        return NULL;
    }

    CFDataRef final = CFDataCreate(kCFAllocatorDefault, buffer, real_size);
    
    free(buffer);
    
    return final;
}
