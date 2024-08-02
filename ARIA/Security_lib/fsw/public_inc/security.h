/* 평문 비트 / 키 사이즈 / 라운드
128 - 16 / 16 / 12
192 - 16 / 24 / 14
256 - 16 / 32 /16
*/

/*
This is Aria
*/

#ifndef SECURITY_H
#define SECURITY_H

#ifndef BYTE_TYPE_DEFINED
#define BYTE_TYPE_DEFINED
typedef unsigned char byte;
#endif

#include <stdio.h>
#include <string.h>
#include "cfe.h"


#define Nk 32
#define Nb 16

#if Nk == 16
#define Nr 12

#elif Nk == 24
#define Nr 14

#else
#define Nr 16

#endif

CFE_Status_t SECURITY_LIB_Init(void);
void left_shift(byte* x, int l);
void right_shift(byte* x, int l);
void ROR(byte* x, int r);
void ROL(byte* x, int r);
void Add_Round_Key(byte* state, byte* w);
void LT(byte* state);
void inv_LT(byte* state);
void SubstLayer(byte* state, int eo);
void DiffLayer(byte* state);
void F_o(byte* state, byte* k);
void F_e(byte* state, byte* k);
void Key_expansion(byte* w, byte* key);
void aria_enc(byte* state, byte* out, byte* w);
void aria_dec(byte* state, byte* out, byte* w);
void encrypt_data(byte* data, size_t size, const byte* key, byte* round_keys);
void decrypt_data(byte* data, size_t size, const byte* key, byte* round_keys);

#endif /* SECURITY_H */
