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
#define TPM_HANDLE_RSALEAFKEY 0x8100cafe
#define TPM_HANDLE_ECLEAFKEY 0x8100bead

int tpmapi_open(ESYS_CONTEXT **ectx);
int tpmapi_close(ESYS_CONTEXT **ectx);

int tpmapi_forceClear(ESYS_CONTEXT *ectx);
int tpmapi_takeOwnership(ESYS_CONTEXT *ectx);
int tpmapi_getRandom(ESYS_CONTEXT *ectx, unsigned char *rnd, size_t *len);
int tpmapi_createPrimaryKey(ESYS_CONTEXT *ectx);
int tpmapi_createRsaLeafKey(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle);
int tpmapi_createEcLeafKey(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle);
int tpmapi_persistHandle(ESYS_CONTEXT *ectx, TPM2_HANDLE tHandle, TPM2_HANDLE pHandle);
int tpmapi_clearTransientHandle(ESYS_CONTEXT *ectx, TPM2_HANDLE tHandle);
int tpmapi_clearPersistentHandle(ESYS_CONTEXT *ectx, TPM2_HANDLE tHandle);
int tpmapi_readRsaPublicKey(ESYS_CONTEXT *ectx, TPM2_HANDLE handle, int *exponent, unsigned char *mod, size_t *modLen);
int tpmapi_getSysHandle(ESYS_CONTEXT *ectx, UINT32 property, int *num_handle, TPM2_HANDLE **sys_handles);
int tpmapi_cipher(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, TPM2_ALG_ID paddingScheme, TPM2_ALG_ID hashAlgo, const unsigned char *dataIn, size_t inLen, unsigned char *dataOut, size_t *outLen);
int tpmapi_decipher(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, TPM2_ALG_ID paddingScheme, TPM2_ALG_ID hashAlgo, const unsigned char *dataIn, size_t inLen, unsigned char *dataOut, size_t *outLen);
int tpmapi_rsa_sign(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, TPM2_ALG_ID paddingScheme, TPM2_ALG_ID hashAlgo, const unsigned char *dataIn, size_t inLen, unsigned char *sig, size_t *sigLen);
int tpmapi_rsa_verify(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, TPM2_ALG_ID paddingScheme, TPM2_ALG_ID hashAlgo, const unsigned char *dataIn, size_t inLen, unsigned char *sig, size_t sigLen, int *result);
int tpmapi_ec_sign(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, TPM2_ALG_ID paddingScheme, TPM2_ALG_ID hashAlgo, const unsigned char *dataIn, size_t inLen, unsigned char *sigR, size_t *rLen, unsigned char *sigS, size_t *sLen);
int tpmapi_ec_verify(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, TPM2_ALG_ID paddingScheme, TPM2_ALG_ID hashAlgo, const unsigned char *dataIn, size_t inLen, unsigned char *sigR, size_t rLen, unsigned char *sigS, size_t sLen, int *result);

TPM2_ALG_ID tpmapi_convert_rsaes_algo(int mbedtls_algo);
TPM2_ALG_ID tpmapi_convert_rsassa_algo(int mbedtls_algo);
TPM2_ALG_ID tpmapi_convert_hash_algo(int mbedtls_algo);

int tpmapi_wrapped_clear(void);
int tpmapi_wrapped_perso(void);
int tpmapi_wrapped_decipher(TPM2_ALG_ID scheme, TPM2_ALG_ID hashAlgo, const unsigned char *input, size_t inLen, unsigned char *output, size_t *outLen);
int tpmapi_wrapped_rsa_sign(TPM2_ALG_ID scheme, TPM2_ALG_ID hashAlgo, const unsigned char *hash, size_t hashLen, unsigned char *sig, size_t *sigLen);
int tpmapi_wrapped_getRsaPk(int *exponent, unsigned char *mod, size_t *modLen);
int tpmapi_wrapped_getRandom(unsigned char *rnd, size_t *len);

int tpmapi_unit_test();

#endif
