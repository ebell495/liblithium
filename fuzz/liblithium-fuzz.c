#include <lithium/gimli_aead.h>
#include <lithium/gimli_hash.h>
#include <lithium/sign.h>
#include <lithium/x25519.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

lith_sign_state sign_state;
gimli_hash_state hash_state;
gimli_state g_state;

uint8_t hashOut[256];

uint8_t scalar[X25519_LEN];
uint8_t point[X25519_LEN];
uint8_t challenge[X25519_LEN];
uint8_t response[X25519_LEN];
uint8_t x25519Out[X25519_LEN];

uint8_t sig[LITH_SIGN_LEN];
uint8_t secret_key[LITH_SIGN_SECRET_KEY_LEN];
uint8_t public_key[LITH_SIGN_PUBLIC_KEY_LEN];
uint8_t prehash[LITH_SIGN_PREHASH_LEN];

uint8_t nonce[GIMLI_AEAD_NONCE_LEN];
uint8_t key[GIMLI_AEAD_KEY_LEN];

uint8_t outputs[8196];

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size > 0)
    {
        uint8_t opt = Data[0];
        const uint8_t *newData = Data + 1;
        size_t newSize = Size - 1;

        switch (opt)
        {
        case 0:
            gimli_hash_init(&hash_state);
            gimli_hash_update(&hash_state, newData, newSize);
            gimli_hash_final(&hash_state, hashOut, GIMLI_HASH_DEFAULT_LEN);
            break;
        case 1:
            lith_sign_init(&sign_state);
            lith_sign_update(&sign_state, newData, newSize);
            break;
        case 2:
            if (newSize > X25519_LEN * 2)
            {
                memcpy(scalar, newData, X25519_LEN);
                memcpy(point, newData + X25519_LEN, X25519_LEN);
                x25519(x25519Out, scalar, point);
            }
            break;
        case 3:
            if (newSize > LITH_SIGN_SECRET_KEY_LEN)
            {
                memcpy(secret_key, newData, LITH_SIGN_SECRET_KEY_LEN);
                lith_sign_init(&sign_state);
                lith_sign_update(&sign_state,
                                 newData + LITH_SIGN_SECRET_KEY_LEN,
                                 newSize - LITH_SIGN_SECRET_KEY_LEN);
                lith_sign_final_create(&sign_state, sig, secret_key);
            }
            break;
        case 4:
            if (newSize > LITH_SIGN_PUBLIC_KEY_LEN)
            {
                memcpy(public_key, newData, LITH_SIGN_PUBLIC_KEY_LEN);
                lith_sign_init(&sign_state);
                lith_sign_update(&sign_state,
                                 newData + LITH_SIGN_PUBLIC_KEY_LEN,
                                 newSize - LITH_SIGN_PUBLIC_KEY_LEN);
                lith_sign_final_verify(&sign_state, sig, public_key);
            }
            break;
        case 5:
            if (newSize > X25519_LEN * 4)
            {
                memcpy(scalar, newData, X25519_LEN);
                memcpy(point, newData + X25519_LEN, X25519_LEN);
                memcpy(challenge, newData + X25519_LEN * 2, X25519_LEN);
                memcpy(response, newData + X25519_LEN * 3, X25519_LEN);

                x25519_verify(response, challenge, scalar, point);
            }
            break;
        case 6:
            if (newSize > LITH_SIGN_PREHASH_LEN)
            {
                memcpy(prehash, newData, LITH_SIGN_PREHASH_LEN);
                lith_sign_init(&sign_state);
                lith_sign_update(&sign_state, newData + LITH_SIGN_PREHASH_LEN,
                                 newSize - LITH_SIGN_PREHASH_LEN);
                lith_sign_final_prehash(&sign_state, prehash);
            }
            break;
        case 7:
            if (newSize > LITH_SIGN_PREHASH_LEN + LITH_SIGN_SECRET_KEY_LEN)
            {
                memcpy(prehash, newData, LITH_SIGN_PREHASH_LEN);
                memcpy(secret_key, newData + LITH_SIGN_PREHASH_LEN,
                       LITH_SIGN_SECRET_KEY_LEN);
                lith_sign_create_from_prehash(sig, prehash, secret_key);
            }
            break;
        case 8:
            if (newSize > LITH_SIGN_PREHASH_LEN + LITH_SIGN_PUBLIC_KEY_LEN +
                              LITH_SIGN_LEN)
            {
                memcpy(prehash, newData, LITH_SIGN_PREHASH_LEN);
                memcpy(public_key, newData + LITH_SIGN_PREHASH_LEN,
                       LITH_SIGN_PUBLIC_KEY_LEN);
                memcpy(sig,
                       newData + LITH_SIGN_PREHASH_LEN +
                           LITH_SIGN_PUBLIC_KEY_LEN,
                       LITH_SIGN_LEN);
                lith_sign_verify_prehash(sig, prehash, public_key);
            }
            break;
        case 9:
            if (newSize > 0)
            {
                gimli_hash_init(&hash_state);
                gimli_hash_update(&hash_state, newData + 1, newSize - 1);
                gimli_hash_final(&hash_state, hashOut, newData[0]);
            }
            break;
        case 10:
            if (newSize > GIMLI_AEAD_NONCE_LEN + GIMLI_AEAD_KEY_LEN)
            {
                memcpy(nonce, newData, GIMLI_AEAD_NONCE_LEN);
                memcpy(key, newData + GIMLI_AEAD_NONCE_LEN, GIMLI_AEAD_KEY_LEN);
                gimli_aead_init(&g_state, nonce, key);
                gimli_aead_update_ad(&g_state,
                                     newData + GIMLI_AEAD_NONCE_LEN +
                                         GIMLI_AEAD_KEY_LEN,
                                     newSize - (GIMLI_AEAD_NONCE_LEN +
                                                GIMLI_AEAD_KEY_LEN));
                gimli_aead_final_ad(&g_state);
            }
            break;
        case 11:
            if (newSize > GIMLI_AEAD_NONCE_LEN + GIMLI_AEAD_KEY_LEN +
                              GIMLI_AEAD_TAG_DEFAULT_LEN)
            {
                memcpy(nonce, newData, GIMLI_AEAD_NONCE_LEN);
                memcpy(key, newData + GIMLI_AEAD_NONCE_LEN, GIMLI_AEAD_KEY_LEN);
                gimli_aead_init(&g_state, nonce, key);
                gimli_aead_update_ad(&g_state,
                                     newData + GIMLI_AEAD_NONCE_LEN +
                                         GIMLI_AEAD_KEY_LEN,
                                     GIMLI_AEAD_TAG_DEFAULT_LEN);
                gimli_aead_encrypt_update(&g_state, outputs,
                                          newData + GIMLI_AEAD_NONCE_LEN +
                                              GIMLI_AEAD_KEY_LEN +
                                              GIMLI_AEAD_TAG_DEFAULT_LEN,
                                          newSize -
                                              (GIMLI_AEAD_NONCE_LEN +
                                               GIMLI_AEAD_KEY_LEN +
                                               GIMLI_AEAD_TAG_DEFAULT_LEN));
                gimli_aead_encrypt_final(&g_state, outputs,
                                         GIMLI_AEAD_TAG_DEFAULT_LEN);
            }
            break;
        }
    }

    return 0;
}