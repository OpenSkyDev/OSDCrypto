//
//  OSDCoreCrypto.c
//  OSDCryptoApp
//
//  Created by Skylar Schipper on 6/1/15.
//  Copyright (c) 2015 OpenSky, LLC. All rights reserved.
//

#include <CommonCrypto/CommonCrypto.h>

#include "OSDCoreCrypto.h"

size_t const OSDCryptoFileHashBockSize = 4096;

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
    CFMutableStringRef string = CFStringCreateMutable(kCFAllocatorDefault, (length * 2));
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

    boolean_t hasMoreData = true;
    UInt8 *buffer = malloc(OSDCryptoFileHashBockSize);
    while (hasMoreData) {
        CFIndex byteCount = CFReadStreamRead(readStrem, buffer, OSDCryptoFileHashBockSize);
        if (byteCount == -1) {
            break;
        }
        if (byteCount == 0) {
            hasMoreData = false;
            continue;
        }
        CC_MD5_Update(&hashCtx, buffer, (CC_LONG)byteCount);
        memset(buffer, 0, OSDCryptoFileHashBockSize);
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

CFStringRef OSDCryptoCreateSHA1HashForFile(CFURLRef fileURL) {
    CFReadStreamRef readStrem = CFReadStreamCreateWithFile(kCFAllocatorDefault, fileURL);
    if (readStrem == NULL) {
        return NULL;
    }
    if (!CFReadStreamOpen(readStrem)) {
        CFRelease(readStrem);
        return NULL;
    }

    CC_SHA1_CTX ctx;
    CC_SHA1_Init(&ctx);

    boolean_t has_more_data = true;
    UInt8 *f_buffer = malloc(OSDCryptoFileHashBockSize);
    while (has_more_data) {
        CFIndex count = CFReadStreamRead(readStrem, f_buffer, OSDCryptoFileHashBockSize);
        if (count <= 0) {
            has_more_data = false;
            break;
        }

        CC_SHA1_Update(&ctx, f_buffer, (CC_LONG)count);

        memset(f_buffer, 0, OSDCryptoFileHashBockSize);
    }

    free(f_buffer);

    CFReadStreamClose(readStrem);
    CFRelease(readStrem);

    CFStringRef final = NULL;

    if (!has_more_data) {
        void *finalBuffer = malloc(CC_SHA1_DIGEST_LENGTH);

        CC_SHA1_Final(finalBuffer, &ctx);

        final = OSDCryptoCreateStringFromBuffer(finalBuffer, CC_SHA1_DIGEST_LENGTH);

        free(finalBuffer);
    }

    return final;
}
