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

int tpm_open(ESYS_CONTEXT **ectx);
int tpm_close(ESYS_CONTEXT **ectx);

int tpm_forceClear(ESYS_CONTEXT *ectx);
int tpm_takeOwnership(ESYS_CONTEXT *ectx);
int tpm_getRandom(ESYS_CONTEXT *ectx, unsigned char *rnd, size_t *len);
int tpm_createPrimaryKey(ESYS_CONTEXT *ectx);
int tpm_createRsaLeafKey(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle);
int tpm_persistHandle(ESYS_CONTEXT *ectx, TPM2_HANDLE tHandle, TPM2_HANDLE pHandle);
int tpm_clearTransientHandle(ESYS_CONTEXT *ectx, TPM2_HANDLE tHandle);
int tpm_clearPersistentHandle(ESYS_CONTEXT *ectx, TPM2_HANDLE tHandle);
int tpm_readRsaPublicKey(ESYS_CONTEXT *ectx, TPM2_HANDLE handle, int *exponent, unsigned char *mod, size_t *modlen);
int tpm_getSysHandle(ESYS_CONTEXT *ectx, UINT32 property, int *num_handle, TPM2_HANDLE **sys_handles);
int tpm_cipher(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, TPM2_ALG_ID paddingScheme, TPM2_ALG_ID hashAlgo, const unsigned char *datain, size_t lenin, unsigned char *dataout, size_t *lenout);
int tpm_decipher(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, TPM2_ALG_ID paddingScheme, TPM2_ALG_ID hashAlgo, const unsigned char *datain, size_t lenin, unsigned char *dataout, size_t *lenout);
int tpm_sign(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, TPM2_ALG_ID paddingScheme, TPM2_ALG_ID hashAlgo, const unsigned char *datain, size_t lenin, unsigned char *dataout, size_t *lenout);
int tpm_verify(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, TPM2_ALG_ID paddingScheme, TPM2_ALG_ID hashAlgo, const unsigned char *digest, size_t digestlen, unsigned char *sig, size_t siglen, int *result);

TPM2_ALG_ID tpm_convert_rsaes_algo(int mbedtls_algo);
TPM2_ALG_ID tpm_convert_rsassa_algo(int mbedtls_algo);
TPM2_ALG_ID tpm_convert_hash_algo(int mbedtls_algo);

int tpm_wrapped_clear(void);
int tpm_wrapped_perso(void);
int tpm_wrapped_decipher(TPM2_ALG_ID scheme, TPM2_ALG_ID hashAlgo, const unsigned char *input, size_t inlen, unsigned char *output, size_t *outlen);
int tpm_wrapped_sign(TPM2_ALG_ID scheme, TPM2_ALG_ID hashAlgo, const unsigned char *hash, size_t hashlen, unsigned char *sig, size_t *siglen);
int tpm_wrapped_getRsaPk(int *exponent, unsigned char *mod, size_t *modlen);
int tpm_wrapped_getRandom(unsigned char *rnd, size_t *len);

int tpm_unit_test();

#endif
