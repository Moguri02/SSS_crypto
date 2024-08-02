
/*
This is AES256
*/

#ifndef SECURITY_H
#define SECURITY_H

#ifndef BYTE_TYPE_DEFINED
#define BYTE_TYPE_DEFINED
typedef unsigned char byte;
#endif

#include <stdint.h>
#include <stddef.h>
#include "cfe.h"

#define Nb 4
#define Nk 8
#define Nr 14

typedef uint8_t state_t[4][4];

typedef struct {
    uint8_t round_keys[240];  // 14 rounds * 16 bytes per round (AES-256)
    uint8_t Iv[16];         // Initialization Vector for CBC mode
} AES_ctx;

CFE_Status_t SECURITY_LIB_Init(void);

void KeyExpansion(uint8_t* round_keys, const uint8_t* Key);
void AES_init_ctx(AES_ctx* ctx, const uint8_t* key);

void Addround_keys(uint8_t round, state_t* state, const uint8_t* round_keys);
void SubBytes(state_t* state);
void ShiftRows(state_t* state);
uint8_t xtime(uint8_t x);
void MixColumns(state_t* state);
void Cipher(state_t* state, const uint8_t* round_keys);
void InvMixColumns(state_t* state);
void InvCipher(state_t* state, const uint8_t* round_keys);
void InvSubBytes(state_t* state);
void InvShiftRows(state_t* state);
uint8_t Multiply(uint8_t x, uint8_t y);

void AES_ECB_encrypt(AES_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt(AES_ctx* ctx, uint8_t* buf);

void encrypt_data(byte* data, size_t size, const byte* key, byte* round_keys);
void decrypt_data(byte* data, size_t size, const byte* key, byte* round_keys);



#endif /* SECURITY_H */