/**
 * MIT License
 *
 * Copyright (c) 2021 Infineon Technologies AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 */

#ifndef TPM_API_H_
#define TPM_API_H_

#include <tss2/tss2_mu.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#define TPM_HANDLE_PRIMARYKEY 0x8100beef
#define TPM_HANDLE_LEAFKEY 0x8100cafe

uint8_t tpm_open(ESYS_CONTEXT **ectx);
uint8_t tpm_close(ESYS_CONTEXT **ectx);

uint8_t tpm_forceClear(ESYS_CONTEXT *ectx);
uint8_t tpm_takeOwnership(ESYS_CONTEXT *ectx);
uint8_t tpm_getRandom(ESYS_CONTEXT *ectx, uint8_t *rnd, uint16_t *len);
uint8_t tpm_createPrimaryKey(ESYS_CONTEXT *ectx);
uint8_t tpm_createRsaLeafKey(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle);
void    tpm_readRsaLeafKeyByteLen(size_t *len);
uint8_t tpm_persistHandle(ESYS_CONTEXT *ectx, TPM2_HANDLE tHandle, TPM2_HANDLE pHandle);
uint8_t tpm_clearTransientHandle(ESYS_CONTEXT *ectx, TPM2_HANDLE tHandle);
uint8_t tpm_clearPersistentHandle(ESYS_CONTEXT *ectx, TPM2_HANDLE tHandle);
uint8_t tpm_readRsaPublicKey(ESYS_CONTEXT *ectx, TPM2_HANDLE handle, int *exponent, unsigned char *mod, size_t *modlen);
uint8_t tpm_getSysHandle(ESYS_CONTEXT *ectx, UINT32 property, uint8_t *num_handle, TPM2_HANDLE **sys_handles);
uint8_t tpm_cipher(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, uint8_t *datain, uint16_t lenin, uint8_t *dataout, uint16_t *lenout);
uint8_t tpm_decipher(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, uint8_t *datain, uint16_t lenin, uint8_t *dataout, uint16_t *lenout);
uint8_t tpm_sign(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, const unsigned char *datain, size_t lenin, unsigned char *dataout, size_t *lenout);
uint8_t tpm_verify(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, uint8_t *digest, uint16_t digestlen, uint8_t *sig, uint16_t siglen, uint8_t *result);

uint8_t tpm_wrap_clear(void);
uint8_t tpm_wrap_perso(void);
uint8_t tpm_wrap_decipher(uint8_t *secret, uint16_t secretlen, uint8_t *msg, uint16_t *msglen);
uint8_t tpm_wrap_sign(const unsigned char *hash, size_t hashlen, unsigned char *sig, size_t *siglen);
uint8_t tpm_wrap_getRsaPk(int *exponent, unsigned char *mod, size_t *modlen);
uint8_t tpm_wrap_getRandom(uint8_t *rnd, uint16_t *len);

#endif
