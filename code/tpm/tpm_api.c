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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#include "tpm_api.h"

#define FILE_TPMAPI "tpm_api :"
#define TPM2_RSA_KEY_BITS 2048
#define TPM2_RSA_KEY_BYTES TPM2_RSA_KEY_BITS/8
#define TPM2_RSA_HASH_BYTES 32
#define TPM2_EC_NIST_P256_BYTES 32

#define TPM2_AUTH_SH "owner123" // storage hierarchy
#define TPM2_AUTH_EH "endorsement123" // endorsement hierarchy
#define TPM2_AUTH_LOCKOUT "lockout123"
#define TPM2_AUTH_SRK "srk123" // storage root key / primary key
#define TPM2_AUTH_RSALEAFKEY "rsaleaf123"
#define TPM2_AUTH_ECLEAFKEY "ecleaf123"

static int tpmapi_openEncryptedSession(ESYS_CONTEXT *ectx, TPM2_HANDLE *sHandle);
static int tpmapi_closeEncryptedSession(ESYS_CONTEXT *ectx, TPM2_HANDLE sHandle);
static int tpmapi_alg2HashSize(TPM2_ALG_ID id);

int tpmapi_open(ESYS_CONTEXT **ectx) {
    TSS2_TCTI_CONTEXT *tcti;

    /* Get the TCTI context */
#ifdef TCTI_NAME_CONF
    TSS2_RC rc = Tss2_TctiLdr_Initialize(TCTI_NAME_CONF, &tcti);
#else
    TSS2_RC rc = Tss2_TctiLdr_Initialize(NULL, &tcti);
#endif

    /* Initializing the Esys context */
    rc = Esys_Initialize(ectx, tcti, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        printf("%s Failed to initialize the Esys context\n", FILE_TPMAPI);
        return 1;
    }

    /*printf("%s Expected TPM error (256):\n"
            "           Error (2.0): TPM_RC_INITIALIZE\n"
            "           Description: TPM not initialized by TPM2_Startup or already initialized\n",
            FILE_TPMAPI);*/

    return 0;
}

int tpmapi_close(ESYS_CONTEXT **ectx) {
    TSS2_TCTI_CONTEXT *tcti = NULL;

    /* Properly shutdown TPM */
    TSS2_RC rc = Esys_Shutdown(*ectx,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            TPM2_SU_CLEAR);
    if (rc != TPM2_RC_SUCCESS) {
        printf("%s Failed to Esys_Shutdown()\n", FILE_TPMAPI);
        return 1;
    }

    /* Get tcti context */
    rc = Esys_GetTcti(*ectx, &tcti);
    if (rc != TPM2_RC_SUCCESS) {
        printf("%s Failed to Esys_GetTcti()\n", FILE_TPMAPI);
        return 1;
    }

    /* Clean up TSS, TIS, and Hardware layers */
    Esys_Finalize(ectx);

    Tss2_TctiLdr_Finalize(&tcti);

    return 0;
}

/* Returns only the 1st handle found */
int tpmapi_getSysHandle(ESYS_CONTEXT *ectx, UINT32 property, int *count, TPM2_HANDLE **sys_handles) {
    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA *fetched_data = NULL;
    TSS2_RC rval = Esys_GetCapability (ectx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                       TPM2_CAP_HANDLES, property, TPM2_MAX_CAP_HANDLES,
                                       &more_data, &fetched_data);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_GetCapability error\n", FILE_TPMAPI);
        return 1;
    }

    *count = fetched_data->data.handles.count;

    if (sys_handles != NULL && *count > 0) {
        size_t i = 0;
        *sys_handles = malloc(sizeof(TPM2_HANDLE)*(*count));
        printf("%s TPM found %d handles:\n", FILE_TPMAPI, *count);

        for (; i<*count; i++) {
            printf("%s - 0x%x\n", FILE_TPMAPI, fetched_data->data.handles.handle[i]);
            *((*sys_handles) + i) = fetched_data->data.handles.handle[i];
        }
    }

    free(fetched_data);
    return 0;
}

int tpmapi_readRsaPublicKey(ESYS_CONTEXT *ectx, TPM2_HANDLE handle, int *exponent, unsigned char *mod, size_t *modLen) {
    TPM2B_NAME *nameKeySign;
    TPM2B_NAME *keyQualifiedName;
    TPM2B_PUBLIC *outPublic;
    ESYS_TR keyHandle;
    TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, handle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &keyHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\n", FILE_TPMAPI);
        return 1;
    }

    // Open encrypted session
    TPM2_HANDLE sHandle = ESYS_TR_NONE;
    if (tpmapi_openEncryptedSession(ectx, &sHandle)) {
        printf("%s tpmapi_openEncryptedSession error\n", FILE_TPMAPI);
        return 1;
    }

    rval = Esys_ReadPublic(ectx, keyHandle, sHandle, ESYS_TR_NONE,
                           ESYS_TR_NONE, &outPublic, &nameKeySign,
                           &keyQualifiedName);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_ReadPublic error\n", FILE_TPMAPI);
        return 1;
    }

    *exponent = outPublic->publicArea.parameters.rsaDetail.exponent;
    if (*exponent == 0)
        *exponent = 65537; //0x10001

    uint16_t len = outPublic->publicArea.unique.rsa.size;
    
    if (len > *modLen) {
        printf("%s tpmapi_readRsaPublicKey output buffer insufficient error\n", FILE_TPMAPI);
        return 1;
    }
    *modLen = len;
    memcpy(mod, outPublic->publicArea.unique.rsa.buffer, len);

    free(nameKeySign);
    free(keyQualifiedName);
    free(outPublic);

    printf("%s TPM read public key of handle: 0x%x\n", FILE_TPMAPI, handle);

    // Close encrypted session
    if (tpmapi_closeEncryptedSession(ectx, sHandle)) {
        printf("%s tpmapi_closeEncryptedSession error\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

int tpmapi_readEcpPublicKey(ESYS_CONTEXT *ectx, TPM2_HANDLE handle, unsigned char *x, size_t *xLen, unsigned char *y, size_t *yLen) {
    TPM2B_NAME *nameKeySign;
    TPM2B_NAME *keyQualifiedName;
    TPM2B_PUBLIC *outPublic;
    ESYS_TR keyHandle;
    TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, handle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &keyHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\n", FILE_TPMAPI);
        return 1;
    }

    // Open encrypted session
    TPM2_HANDLE sHandle = ESYS_TR_NONE;
    if (tpmapi_openEncryptedSession(ectx, &sHandle)) {
        printf("%s tpmapi_openEncryptedSession error\n", FILE_TPMAPI);
        return 1;
    }

    rval = Esys_ReadPublic(ectx, keyHandle, sHandle, ESYS_TR_NONE,
                           ESYS_TR_NONE, &outPublic, &nameKeySign,
                           &keyQualifiedName);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_ReadPublic error\n", FILE_TPMAPI);
        return 1;
    }

    *xLen = outPublic->publicArea.unique.ecc.x.size;
    memcpy(x, outPublic->publicArea.unique.ecc.x.buffer, *xLen);
    *yLen = outPublic->publicArea.unique.ecc.y.size;
    memcpy(y, outPublic->publicArea.unique.ecc.y.buffer, *yLen);

    free(nameKeySign);
    free(keyQualifiedName);
    free(outPublic);

    printf("%s TPM read public key of handle: 0x%x\n", FILE_TPMAPI, handle);

    // Close encrypted session
    if (tpmapi_closeEncryptedSession(ectx, sHandle)) {
        printf("%s tpmapi_closeEncryptedSession error\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

int tpmapi_clearTransientHandle(ESYS_CONTEXT *ectx, TPM2_HANDLE tHandle) {
    ESYS_TR handle;
    TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, tHandle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &handle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\n", FILE_TPMAPI);
        return 1;
    }

    rval = Esys_FlushContext(ectx, handle);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_FlushContext error\n", FILE_TPMAPI);
        return 1;
    }

    printf("%s TPM cleared transient handle: 0x%x\n", FILE_TPMAPI, tHandle);
    return 0;
}

int tpmapi_clearPersistentHandle(ESYS_CONTEXT *ectx, TPM2_HANDLE tHandle) {
    TPM2B_DIGEST pwd;
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", TPM2_AUTH_SH);

    TSS2_RC rval = Esys_TR_SetAuth(ectx, ESYS_TR_RH_OWNER, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_TR_SetAuth error\n", FILE_TPMAPI);
        return 1;
    }

    ESYS_TR handle;
    rval = Esys_TR_FromTPMPublic(ectx, tHandle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &handle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\n", FILE_TPMAPI);
        return 1;
    }

    ESYS_TR dummy;
    rval = Esys_EvictControl(ectx, ESYS_TR_RH_OWNER, handle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, &dummy);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_EvictControl error\n", FILE_TPMAPI);
        return 1;
    }

    printf("%s TPM cleared persistent handle: 0x%x\n", FILE_TPMAPI, tHandle);
    return 0;
}

int tpmapi_persistHandle(ESYS_CONTEXT *ectx, TPM2_HANDLE tHandle, TPM2_HANDLE pHandle) {
    TPM2B_DIGEST pwd;
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", TPM2_AUTH_SH);
    
    TSS2_RC rval = Esys_TR_SetAuth(ectx, ESYS_TR_RH_OWNER, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_TR_SetAuth error\n", FILE_TPMAPI);
        return 1;
    }

    ESYS_TR transientHandle;
    rval = Esys_TR_FromTPMPublic(ectx, tHandle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &transientHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\n", FILE_TPMAPI);
        return 1;
    }

    ESYS_TR persistentHandle;
    rval = Esys_EvictControl(ectx, ESYS_TR_RH_OWNER, transientHandle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            pHandle, &persistentHandle);

    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_EvictControl error\n", FILE_TPMAPI);
        return 1;
    }

    printf("%s Transient object (0x%x) moved to persistent (0x%x)\n", FILE_TPMAPI, tHandle, pHandle);
    return 0;
}

int tpmapi_createRsaLeafKey(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle)
{
    TPM2B_PUBLIC            *outPublic;
    TPM2B_PRIVATE           *outPrivate;
    
    /******************************/
    /***** 1) Create leaf key *****/
    /******************************/
    {
        ESYS_TR primaryHandle;
        TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, pHandle,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &primaryHandle);
        if (rval != TSS2_RC_SUCCESS) {
            printf("%s Esys_TR_FromTPMPublic error\n", FILE_TPMAPI);
            return 1;
        }
        
        TPM2B_DIGEST pwd;
        pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", TPM2_AUTH_SRK);
        
        rval = Esys_TR_SetAuth(ectx, primaryHandle, &pwd);
        if (rval != TPM2_RC_SUCCESS) {
            printf("%s Esys_TR_SetAuth error\n", FILE_TPMAPI);
            return 1;
        }

        pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", TPM2_AUTH_RSALEAFKEY);
        
        TPM2B_SENSITIVE_CREATE inSensitiveLeaf = {
            .size = 4,
            .sensitive = {
                .userAuth = {.size = 0,.buffer = {0},
                 },
                .data = {.size = 0,.buffer = {0},
                 },
            },
        };
        inSensitiveLeaf.sensitive.userAuth = pwd;

        TPM2B_PUBLIC inPublic = {
            .size = 0,
            .publicArea = {
                .type = TPM2_ALG_RSA,
                .nameAlg = TPM2_ALG_SHA256,
                .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_FIXEDTPM |
                                     TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                     TPMA_OBJECT_DECRYPT | TPMA_OBJECT_SIGN_ENCRYPT),
                .authPolicy = {
                    .size = 0,
                },
                .parameters.rsaDetail = {
                    .symmetric = {
                        .algorithm = TPM2_ALG_NULL,
                    },
                    .scheme = {
                        .scheme = TPM2_ALG_NULL,
                    },
                    .keyBits = TPM2_RSA_KEY_BITS,
                    .exponent = 0,
                 },
                .unique.rsa = {
                    .size = 0,
                    .buffer = {0},
                 },
            },
        };

        TPM2B_DATA              outsideInfo = { .size = 0 };
        TPML_PCR_SELECTION      creationPCR = { .count = 0 };

        TPM2B_CREATION_DATA     *creationData;
        TPM2B_DIGEST            *creationHash;
        TPMT_TK_CREATION        *creationTicket;
        rval = Esys_Create(ectx, primaryHandle,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                &inSensitiveLeaf, &inPublic, &outsideInfo, &creationPCR,
                &outPrivate, &outPublic, &creationData, &creationHash,
                &creationTicket);
        if(rval != TPM2_RC_SUCCESS) {
            printf("%s Esys_Create error\n", FILE_TPMAPI);
            return 1;
        }
        free(creationData);
        free(creationHash);
        free(creationTicket);

        //printf("%s TPM leaf keypair created\n", FILE_TPMAPI);
    }
    
    /****************************/
    /***** 2) Load leaf key *****/
    /****************************/
    //sudo tpm2_load -C RSAprimary.ctx -P RSAprimary123 -r RSALeafPriv.key -u RSALeafPub.key -n key_name_structure.data -o RSALeaf.ctx
    ESYS_TR transientHandle;
    {
        ESYS_TR primaryHandle;
        TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, pHandle,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &primaryHandle);
        if (rval != TSS2_RC_SUCCESS) {
            printf("%s Esys_TR_FromTPMPublic error\n", FILE_TPMAPI);
            goto err1;
        }
        
        TPM2B_DIGEST pwd;
        pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", TPM2_AUTH_SRK);
        
        rval = Esys_TR_SetAuth(ectx, primaryHandle, &pwd);
        if (rval != TPM2_RC_SUCCESS) {
            printf("%s Esys_TR_SetAuth error\n", FILE_TPMAPI);
            goto err1;
        }
        
        rval = Esys_Load(ectx, primaryHandle,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                outPrivate, outPublic, &transientHandle);
        if (rval != TPM2_RC_SUCCESS)
        {
            printf("%s Esys_Load error\n", FILE_TPMAPI);
            goto err1;
        }
    }
        
    ESYS_TR persistentHandle;
    TPM2_RC rval = Esys_EvictControl(ectx, ESYS_TR_RH_OWNER, transientHandle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            TPM_HANDLE_RSALEAFKEY, &persistentHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_EvictControl error\n", FILE_TPMAPI);
        goto err1;
    }

    rval = Esys_FlushContext(ectx, transientHandle);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_FlushContext error\n", FILE_TPMAPI);
        goto err1;
    }

    printf("%s Created persistent RSA leaf key (0x%x)\n", FILE_TPMAPI, TPM_HANDLE_RSALEAFKEY);

    if (0) {
err1:
        free(outPublic);
        free(outPrivate);
        return 1;
    }

    free(outPublic);
    free(outPrivate);
    return 0;
}

int tpmapi_createEcpLeafKey(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle)
{
    TPM2B_PUBLIC            *outPublic;
    TPM2B_PRIVATE           *outPrivate;

    /******************************/
    /***** 1) Create leaf key *****/
    /******************************/
    {
        ESYS_TR primaryHandle;
        TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, pHandle,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &primaryHandle);
        if (rval != TSS2_RC_SUCCESS) {
            printf("%s Esys_TR_FromTPMPublic error\n", FILE_TPMAPI);
            return 1;
        }

        TPM2B_DIGEST pwd;
        pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", TPM2_AUTH_SRK);

        rval = Esys_TR_SetAuth(ectx, primaryHandle, &pwd);
        if (rval != TPM2_RC_SUCCESS) {
            printf("%s Esys_TR_SetAuth error\n", FILE_TPMAPI);
            return 1;
        }

        pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", TPM2_AUTH_ECLEAFKEY);

        TPM2B_SENSITIVE_CREATE inSensitiveLeaf = {
            .size = 4,
            .sensitive = {
                .userAuth = {.size = 0,.buffer = {0},
                },
                .data = {.size = 0,.buffer = {0},
                },
            },
        };
        inSensitiveLeaf.sensitive.userAuth = pwd;

        TPM2B_PUBLIC inPublic = {
            .size = 0,
            .publicArea = {
                .type = TPM2_ALG_ECC,
                .nameAlg = TPM2_ALG_SHA256,
                .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_FIXEDTPM |
                                     TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                     TPMA_OBJECT_SIGN_ENCRYPT),
                .authPolicy = {
                    .size = 0,
                },
                .parameters.eccDetail = {
                    .symmetric = {
                        .algorithm = TPM2_ALG_NULL
                    },
                    .scheme = {
                        .scheme = TPM2_ALG_NULL,
                        .details = {{0}}
                    },
                    .curveID = TPM2_ECC_NIST_P256,
                    .kdf = {
                        .scheme = TPM2_ALG_NULL,
                        .details = {{0}}
                    }
                },
                .unique.ecc = {
                    .x = {.size = 0, .buffer = { 0 }},
                    .y = {.size = 0, .buffer = { 0 }}
                }
            },
        };

        TPM2B_DATA              outsideInfo = { .size = 0 };
        TPML_PCR_SELECTION      creationPCR = { .count = 0 };

        TPM2B_CREATION_DATA     *creationData;
        TPM2B_DIGEST            *creationHash;
        TPMT_TK_CREATION        *creationTicket;
        rval = Esys_Create(ectx, primaryHandle,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                &inSensitiveLeaf, &inPublic, &outsideInfo, &creationPCR,
                &outPrivate, &outPublic, &creationData, &creationHash,
                &creationTicket);
        if(rval != TPM2_RC_SUCCESS) {
            printf("%s Esys_Create error\n", FILE_TPMAPI);
            return 1;
        }
        free(creationData);
        free(creationHash);
        free(creationTicket);

        //printf("%s TPM leaf keypair created\n", FILE_TPMAPI);
    }

    /****************************/
    /***** 2) Load leaf key *****/
    /****************************/
    //sudo tpm2_load -C RSAprimary.ctx -P RSAprimary123 -r RSALeafPriv.key -u RSALeafPub.key -n key_name_structure.data -o RSALeaf.ctx
    ESYS_TR transientHandle;
    {
        ESYS_TR primaryHandle;
        TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, pHandle,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &primaryHandle);
        if (rval != TSS2_RC_SUCCESS) {
            printf("%s Esys_TR_FromTPMPublic error\n", FILE_TPMAPI);
            goto err1;
        }

        TPM2B_DIGEST pwd;
        pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", TPM2_AUTH_SRK);

        rval = Esys_TR_SetAuth(ectx, primaryHandle, &pwd);
        if (rval != TPM2_RC_SUCCESS) {
            printf("%s Esys_TR_SetAuth error\n", FILE_TPMAPI);
            goto err1;
        }

        rval = Esys_Load(ectx, primaryHandle,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                outPrivate, outPublic, &transientHandle);
        if (rval != TPM2_RC_SUCCESS)
        {
            printf("%s Esys_Load error\n", FILE_TPMAPI);
            goto err1;
        }
    }

    ESYS_TR persistentHandle;
    TPM2_RC rval = Esys_EvictControl(ectx, ESYS_TR_RH_OWNER, transientHandle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            TPM_HANDLE_ECPLEAFKEY, &persistentHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_EvictControl error\n", FILE_TPMAPI);
        goto err1;
    }

    rval = Esys_FlushContext(ectx, transientHandle);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_FlushContext error\n", FILE_TPMAPI);
        goto err1;
    }

    printf("%s Created persistent EC leaf key (0x%x)\n", FILE_TPMAPI, TPM_HANDLE_ECPLEAFKEY);

    if (0) {
err1:
        free(outPublic);
        free(outPrivate);
        return 1;
    }

    free(outPublic);
    free(outPrivate);
    return 0;
}

int tpmapi_createPrimaryKey(ESYS_CONTEXT *ectx) {
    TPM2B_DIGEST pwd;
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", TPM2_AUTH_SH);
    
    TSS2_RC rval = Esys_TR_SetAuth(ectx, ESYS_TR_RH_OWNER, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_TR_SetAuth error\n", FILE_TPMAPI);
        return 1;
    }

    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", TPM2_AUTH_SRK);
    
    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 4,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0},
             },
            .data = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };
    inSensitivePrimary.sensitive.userAuth = pwd;
     
    /* This will create same primary key as tool "tpm2_createprimary -a o -P owner123 -p RSAprimary123 -g 0x000B -G 0x0001 -o RSAprimary.ctx */
    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_RESTRICTED),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.rsaDetail = {
                 .symmetric = {.algorithm = TPM2_ALG_AES, .keyBits.aes = 128,.mode.aes = TPM2_ALG_CFB
                 }, 
                 .scheme = { .scheme = TPM2_ALG_NULL
                 }, 
                 .keyBits = TPM2_RSA_KEY_BITS,
                 .exponent = 0,
             },
            .unique.rsa = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {0},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    ESYS_TR transientHandle = ESYS_TR_NONE;
    TPM2B_PUBLIC *outPublic;
    TPM2B_CREATION_DATA *creationData;
    TPM2B_DIGEST *creationHash;
    TPMT_TK_CREATION *creationTicket;

    rval = Esys_CreatePrimary(ectx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                              ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary,
                              &inPublic, &outsideInfo, &creationPCR,
                              &transientHandle, &outPublic, &creationData,
                              &creationHash, &creationTicket);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_CreatePrimary error\n", FILE_TPMAPI);
        return 1;
    }

    free(outPublic);
    free(creationData);
    free(creationHash);
    free(creationTicket);

    ESYS_TR persistentHandle;
    rval = Esys_EvictControl(ectx, ESYS_TR_RH_OWNER, transientHandle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            TPM_HANDLE_PRIMARYKEY, &persistentHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_EvictControl error\n", FILE_TPMAPI);
        return 1;
    }

    rval = Esys_FlushContext(ectx, transientHandle);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_FlushContext error\n", FILE_TPMAPI);
        return 1;
    }

    printf("%s Created persistent primary key (0x%x)\n", FILE_TPMAPI, TPM_HANDLE_PRIMARYKEY);

    return 0;
}

int tpmapi_takeOwnership(ESYS_CONTEXT *ectx) {
    TPM2B_DIGEST pwd;
    
    /* Set owner password */
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", TPM2_AUTH_SH);
    TSS2_RC rval = Esys_HierarchyChangeAuth(ectx, ESYS_TR_RH_OWNER,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_HierarchyChangeAuth owner error\n", FILE_TPMAPI);
        return 1;
    }

    //printf("%s TPM set owner password ok\n", FILE_TPMAPI);
    
    /* Set endorsement password */
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", TPM2_AUTH_EH);
    rval = Esys_HierarchyChangeAuth(ectx, ESYS_TR_RH_ENDORSEMENT,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_HierarchyChangeAuth endorsement error\n", FILE_TPMAPI);
        return 1;
    }

    //printf("%s TPM set endorsement password ok\n", FILE_TPMAPI);
    
    /* Set lockout password */
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", TPM2_AUTH_LOCKOUT);
    rval = Esys_HierarchyChangeAuth(ectx, ESYS_TR_RH_LOCKOUT,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_HierarchyChangeAuth lockout error\n", FILE_TPMAPI);
        return 1;
    }

    //printf("%s TPM set lockout password ok\n", FILE_TPMAPI);
    
    printf("%s TPM take ownership\n", FILE_TPMAPI);
    return 0;
}

int tpmapi_forceClear(ESYS_CONTEXT *ectx) {
    TSS2_RC rval = Esys_Clear(ectx, ESYS_TR_RH_PLATFORM,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rval != TPM2_RC_SUCCESS && rval != TPM2_RC_INITIALIZE) {
        printf("%s Esys_Clear error\n", FILE_TPMAPI);
        return 1;
    }

    printf("%s TPM force clear\n", FILE_TPMAPI);
    return 0;
}

static int tpmapi_openEncryptedSession(ESYS_CONTEXT *ectx, TPM2_HANDLE *sHandle) {
    // Get primary key handle
    TPM2B_DIGEST pwd;
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", TPM2_AUTH_SRK);
    TPM2_HANDLE tHandle = TPM_HANDLE_PRIMARYKEY;
    ESYS_TR pHandle;
    TSS2_RC rval = Esys_TR_FromTPMPublic(ectx, tHandle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &pHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\n", FILE_TPMAPI);
        return 1;
    }

    // Provide auth value to unlock the primary key
    rval = Esys_TR_SetAuth(ectx, pHandle, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_TR_SetAuth error\n", FILE_TPMAPI);
        return 1;
    }

    // Start a HMAC and encrypted session using the primary key
    TPMT_SYM_DEF sym = { .algorithm = TPM2_ALG_AES,
                         .keyBits = { .aes = 128 },
                         .mode = { .aes = TPM2_ALG_CFB }
                       };
    rval = Esys_StartAuthSession(ectx, pHandle, pHandle, ESYS_TR_NONE,
            ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC, &sym,
            TPM2_ALG_SHA256, sHandle);
    if (rval != TPM2_RC_SUCCESS && rval != TPM2_RC_INITIALIZE) {
        printf("%s Esys_StartAuthSession error\n", FILE_TPMAPI);
        return 1;
    }

    rval = Esys_TRSess_SetAttributes(ectx, *sHandle,
                    TPMA_SESSION_CONTINUESESSION |
                    TPMA_SESSION_DECRYPT |
                    TPMA_SESSION_ENCRYPT, 0xff);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TRSess_SetAttributes error\n", FILE_TPMAPI);
        return 1;
    }

    printf("%s TPM open encrypted session\n", FILE_TPMAPI);
    return 0;
}

static int tpmapi_closeEncryptedSession(ESYS_CONTEXT *ectx, TPM2_HANDLE sHandle) {
    // Close the session
    TSS2_RC rval = Esys_FlushContext(ectx, sHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_FlushContext error\n", FILE_TPMAPI);
        return 1;
    }

    printf("%s TPM close encrypted session\n", FILE_TPMAPI);
    return 0;
}

static int tpmapi_alg2HashSize(TPM2_ALG_ID id) {

    switch (id) {
    case TPM2_ALG_SHA1:
        return TPM2_SHA1_DIGEST_SIZE;
    case TPM2_ALG_SHA256:
        return TPM2_SHA256_DIGEST_SIZE;
    case TPM2_ALG_SHA384:
        return TPM2_SHA384_DIGEST_SIZE;
    case TPM2_ALG_SHA512:
        return TPM2_SHA512_DIGEST_SIZE;
    case TPM2_ALG_SM3_256:
        return TPM2_SM3_256_DIGEST_SIZE;
    }

    return 0;
}

int tpmapi_getRandom(ESYS_CONTEXT *ectx, unsigned char *rnd, size_t *len) {

    // Open encrypted session
    TPM2_HANDLE sHandle = ESYS_TR_NONE;
    if (tpmapi_openEncryptedSession(ectx, &sHandle)) {
        printf("%s tpmapi_openEncryptedSession error\n", FILE_TPMAPI);
        return 1;
    }

    // Get random
    TPM2B_DIGEST *random_bytes;
    TSS2_RC rval = Esys_GetRandom(ectx,
                    sHandle, ESYS_TR_NONE, ESYS_TR_NONE,
                    *len, &random_bytes);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_GetRandom error\n", FILE_TPMAPI);
        return 1;
    }
    *len = random_bytes->size;
    memcpy(rnd, random_bytes->buffer, *len);
    free(random_bytes);

    printf("%s TPM get random\n", FILE_TPMAPI);

    // Close encrypted session
    if (tpmapi_closeEncryptedSession(ectx, sHandle)) {
        printf("%s tpmapi_closeEncryptedSession error\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

int tpmapi_cipher(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, 
                  TPM2_ALG_ID paddingScheme, TPM2_ALG_ID hashAlgo, const unsigned char *dataIn,
                  size_t inLen, unsigned char *dataOut, size_t *outLen) {
    
    if (inLen > TPM2_RSA_KEY_BYTES || *outLen < TPM2_RSA_KEY_BYTES) {
        printf("%s tpmapi_cipher invalid length error\n", FILE_TPMAPI);
        return 1;
    }

    TPMT_RSA_DECRYPT scheme = {0};
    switch (paddingScheme) {
        case TPM2_ALG_OAEP:
            scheme.scheme = TPM2_ALG_OAEP;
            scheme.details.oaep.hashAlg = hashAlgo;
            break;
        case TPM2_ALG_RSAES:
            scheme.scheme = TPM2_ALG_RSAES;
            break;
        default:
            printf("%s unknown scheme error\n", FILE_TPMAPI);
            return 1;
    }

    // Open encrypted session
    TPM2_HANDLE sHandle;
    if (tpmapi_openEncryptedSession(ectx, &sHandle)) {
        printf("%s tpmapi_openEncryptedSession error\n", FILE_TPMAPI);
        return 1;
    }

    TPM2B_PUBLIC_KEY_RSA *encrypted_msg;
    TPM2B_PUBLIC_KEY_RSA clear_msg = {
        .size = inLen,
    };
    memcpy(clear_msg.buffer, dataIn, inLen);
    
    ESYS_TR keyHandle;
    TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, pHandle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &keyHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\n", FILE_TPMAPI);
        return 1;
    }

    TPM2B_DATA label = {
        .size = 0,
        .buffer = {0}
    };

    rval = Esys_RSA_Encrypt(ectx, keyHandle,
                            sHandle, ESYS_TR_NONE, ESYS_TR_NONE,
                            &clear_msg, &scheme, &label, &encrypted_msg);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_RSA_Encrypt error\n", FILE_TPMAPI);
        return 1;
    }
    
    memcpy(dataOut, encrypted_msg->buffer, encrypted_msg->size);
    *outLen = encrypted_msg->size;
    
    free(encrypted_msg);

    printf("%s TPM encryption using RSA key handle 0x%x\n", FILE_TPMAPI, pHandle);

    // Close encrypted session
    if (tpmapi_closeEncryptedSession(ectx, sHandle)) {
        printf("%s tpmapi_closeEncryptedSession error\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

int tpmapi_decipher(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle,
                    TPM2_ALG_ID paddingScheme, TPM2_ALG_ID hashAlgo, const unsigned char *dataIn,
                    size_t inLen, unsigned char *dataOut, size_t *outLen) {

    if (inLen > TPM2_RSA_KEY_BYTES || *outLen < TPM2_RSA_KEY_BYTES) {
        printf("%s tpmapi_decipher invalid length error\n", FILE_TPMAPI);
        return 1;
    }

    TPMT_RSA_DECRYPT scheme = {0};
    switch (paddingScheme) {
        case TPM2_ALG_OAEP:
            scheme.scheme = TPM2_ALG_OAEP;
            scheme.details.oaep.hashAlg = hashAlgo;
            break;
        case TPM2_ALG_RSAES:
            scheme.scheme = TPM2_ALG_RSAES;
            break;
        default:
            printf("%s unknown scheme error\n", FILE_TPMAPI);
            return 1;
    }

    // Open encrypted session
    TPM2_HANDLE sHandle;
    if (tpmapi_openEncryptedSession(ectx, &sHandle)) {
        printf("%s tpmapi_openEncryptedSession error\n", FILE_TPMAPI);
        return 1;
    }

    ESYS_TR keyHandle;
    TPM2B_PUBLIC_KEY_RSA *decrypted_msg;
    TPM2B_PUBLIC_KEY_RSA encrypted_msg = {
        .size = inLen,
    };
    memcpy(encrypted_msg.buffer, dataIn, inLen);

    TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, pHandle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &keyHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\n", FILE_TPMAPI);
        return 1;
    }

    TPM2B_DIGEST pwd;
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", TPM2_AUTH_RSALEAFKEY);

    rval = Esys_TR_SetAuth(ectx, keyHandle, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_TR_SetAuth error\n", FILE_TPMAPI);
        return 1;
    }

    TPM2B_DATA null_data = {
        .size = 0,
        .buffer = {0}
    };

    rval = Esys_RSA_Decrypt(ectx, keyHandle, sHandle, ESYS_TR_NONE, ESYS_TR_NONE,&encrypted_msg, &scheme, &null_data, &decrypted_msg);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_RSA_Decrypt error\n", FILE_TPMAPI);
        return 1;
    }

    if (*outLen < decrypted_msg->size) {
        printf("%s insufficient buffer size error\n", FILE_TPMAPI);
        return 1;
    }
   
    memcpy(dataOut, decrypted_msg->buffer, decrypted_msg->size);
    *outLen = decrypted_msg->size;
    
    free(decrypted_msg);

    printf("%s TPM decryption using RSA key handle 0x%x\n", FILE_TPMAPI, pHandle);

    // Close encrypted session
    if (tpmapi_closeEncryptedSession(ectx, sHandle)) {
        printf("%s tpmapi_closeEncryptedSession error\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

int tpmapi_rsa_sign(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle,
                    TPM2_ALG_ID paddingScheme, TPM2_ALG_ID hashAlgo,
                    const unsigned char *dataIn, size_t inLen, unsigned char *sig, size_t *sigLen) {
    
    if (inLen != TPM2_RSA_HASH_BYTES || *sigLen < TPM2_RSA_KEY_BYTES) {
        printf("%s tpmapi_rsa_sign invalid length error\n", FILE_TPMAPI);
        return 1;
    }

    TPMT_SIG_SCHEME scheme = {0};
    switch (paddingScheme) {
        case TPM2_ALG_RSAPSS:
            scheme.scheme = TPM2_ALG_RSAPSS;
            scheme.details.rsapss.hashAlg = hashAlgo;
            break;
        case TPM2_ALG_RSASSA:
            scheme.scheme = TPM2_ALG_RSASSA;
            scheme.details.rsassa.hashAlg = hashAlgo;
            break;
        default:
            printf("%s Unknown scheme error\n", FILE_TPMAPI);
            return 1;
    }

    // Open encrypted session
    TPM2_HANDLE sHandle;
    if (tpmapi_openEncryptedSession(ectx, &sHandle)) {
        printf("%s tpmapi_openEncryptedSession error\n", FILE_TPMAPI);
        return 1;
    }

    ESYS_TR keyHandle;
    TPMT_SIGNATURE *signature;
    TPM2B_DIGEST digest = {
        .size = inLen
    };
    memcpy(digest.buffer, dataIn, inLen);
    
    TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, pHandle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &keyHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\n", FILE_TPMAPI);
        return 1;
    }

    TPM2B_DIGEST pwd;
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", TPM2_AUTH_RSALEAFKEY);
    
    rval = Esys_TR_SetAuth(ectx, keyHandle, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_TR_SetAuth error\n", FILE_TPMAPI);
        return 1;
    }

    /* Not using ticket/hash_validation, since hash is not calculated by TPM.
     *
     * hash_validation is generated by using TPM to hash a message
     * and it is to prove that a hash is generated by TPM
     *
     * this provide an option to check in between calc hash
     * and sign if the hash value is modified ilegally
     */
    TPMT_TK_HASHCHECK hash_validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest = {0}
    };

    rval = Esys_Sign(ectx, keyHandle,
            sHandle, ESYS_TR_NONE, ESYS_TR_NONE,
            &digest, &scheme, &hash_validation, &signature);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_Sign error\n", FILE_TPMAPI);
        return 1;
    }

    switch (paddingScheme) {
        case TPM2_ALG_RSAPSS:
        case TPM2_ALG_RSASSA:
            *sigLen = signature->signature.rsassa.sig.size;
            memcpy(sig, signature->signature.rsassa.sig.buffer, *sigLen);
            break;
    }

    free(signature);

    printf("%s TPM signing using RSA key handle 0x%x\n", FILE_TPMAPI, pHandle);

    // Close encrypted session
    if (tpmapi_closeEncryptedSession(ectx, sHandle)) {
        printf("%s tpmapi_closeEncryptedSession error\n", FILE_TPMAPI);
        return 1;
    }

    return 0;

}

int tpmapi_rsa_verify(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle,
                      TPM2_ALG_ID paddingScheme, TPM2_ALG_ID hashAlgo,
                      const unsigned char *dataIn, size_t inLen, unsigned char *sig,
                      size_t sigLen, int *result) {
    *result = 0;
    if (inLen != TPM2_RSA_HASH_BYTES || sigLen < TPM2_RSA_KEY_BYTES) {
        printf("%s tpmapi_rsa_verify invalid length error\n", FILE_TPMAPI);
        return 1;
    }

    TPMT_SIGNATURE signature = {0};
    switch (paddingScheme) {
        case TPM2_ALG_RSAPSS:
            signature.sigAlg = TPM2_ALG_RSAPSS;
            signature.signature.rsapss.hash = hashAlgo;
            signature.signature.rsapss.sig.size = sigLen;
            break;
        case TPM2_ALG_RSASSA:
            signature.sigAlg = TPM2_ALG_RSASSA;
            signature.signature.rsassa.hash = hashAlgo;
            signature.signature.rsassa.sig.size = sigLen;
            break;
        default:
            printf("%s unknown scheme error\n", FILE_TPMAPI);
            return 1;
    }
    memcpy(signature.signature.rsassa.sig.buffer, sig, sigLen);

    // Open encrypted session
    TPM2_HANDLE sHandle;
    if (tpmapi_openEncryptedSession(ectx, &sHandle)) {
        printf("%s tpmapi_openEncryptedSession error\n", FILE_TPMAPI);
        return 1;
    }

    TPM2B_DIGEST hash = {
        .size = inLen
    };
    memcpy(hash.buffer, dataIn, inLen);
    
    ESYS_TR keyHandle;
    TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, pHandle,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &keyHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\n", FILE_TPMAPI);
        return 1;
    }

    /* This is a ticket generated by verify signature,
     * no clue what is the purpose of it... */
    TPMT_TK_VERIFIED *validation;
    rval = Esys_VerifySignature(ectx, keyHandle,
            sHandle, ESYS_TR_NONE, ESYS_TR_NONE,
            &hash, &signature, &validation);
    int mask = rval & (TPM2_RC_FMT1 + 0x3F);
    if (rval != TSS2_RC_SUCCESS && mask != TPM2_RC_SIGNATURE) {
        printf("%s Esys_VerifySignature error\n", FILE_TPMAPI);
        return 0;
    }

    if (rval == TSS2_RC_SUCCESS)
        *result = 1;

    free(validation);

    printf("%s TPM verification using RSA key handle 0x%x\n", FILE_TPMAPI, pHandle);

    // Close encrypted session
    if (tpmapi_closeEncryptedSession(ectx, sHandle)) {
        printf("%s tpmapi_closeEncryptedSession error\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

int tpmapi_ecp_sign(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle,
                   TPM2_ALG_ID sigScheme, TPM2_ALG_ID hashAlgo,
                   const unsigned char *dataIn, size_t inLen,
                   unsigned char *sigR, size_t *rLen,
                   unsigned char *sigS, size_t *sLen) {

    if (inLen != tpmapi_alg2HashSize(hashAlgo) ||
        *rLen < TPM2_EC_NIST_P256_BYTES ||
        *sLen < TPM2_EC_NIST_P256_BYTES ) {
        printf("%s tpmapi_ecp_sign invalid length error\n", FILE_TPMAPI);
        return 1;
    }

    TPMT_SIG_SCHEME scheme = {0};
    switch (sigScheme) {
        case TPM2_ALG_ECDSA:
            scheme.scheme = TPM2_ALG_ECDSA;
            scheme.details.ecdsa.hashAlg = hashAlgo;
            break;
        default:
            printf("%s Unknown scheme error\n", FILE_TPMAPI);
            return 1;
    }

    // Open encrypted session
    TPM2_HANDLE sHandle;
    if (tpmapi_openEncryptedSession(ectx, &sHandle)) {
        printf("%s tpmapi_openEncryptedSession error\n", FILE_TPMAPI);
        return 1;
    }

    ESYS_TR keyHandle;
    TPMT_SIGNATURE *signature;
    TPM2B_DIGEST digest = {
        .size = inLen
    };
    memcpy(digest.buffer, dataIn, inLen);

    TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, pHandle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &keyHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\n", FILE_TPMAPI);
        return 1;
    }

    TPM2B_DIGEST pwd;
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", TPM2_AUTH_ECLEAFKEY);

    rval = Esys_TR_SetAuth(ectx, keyHandle, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_TR_SetAuth error\n", FILE_TPMAPI);
        return 1;
    }

    /* Not using ticket/hash_validation, since hash is not calculated by TPM.
     *
     * hash_validation is generated by using TPM to hash a message
     * and it is to prove that a hash is generated by TPM
     *
     * this provide an option to check in between calc hash
     * and sign if the hash value is modified ilegally
     */
    TPMT_TK_HASHCHECK hash_validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest = {0}
    };

    rval = Esys_Sign(ectx, keyHandle,
            sHandle, ESYS_TR_NONE, ESYS_TR_NONE,
            &digest, &scheme, &hash_validation, &signature);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_Sign error\n", FILE_TPMAPI);
        return 1;
    }

    switch (sigScheme) {
        case TPM2_ALG_ECDSA:
            *sLen = signature->signature.ecdsa.signatureS.size;
            memcpy(sigS, signature->signature.ecdsa.signatureS.buffer, *sLen);
            *rLen = signature->signature.ecdsa.signatureR.size;
            memcpy(sigR, signature->signature.ecdsa.signatureR.buffer, *rLen);
            break;
    }

    free(signature);

    printf("%s TPM signing using EC key handle 0x%x\n", FILE_TPMAPI, pHandle);

    // Close encrypted session
    if (tpmapi_closeEncryptedSession(ectx, sHandle)) {
        printf("%s tpmapi_closeEncryptedSession error\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

int tpmapi_ecp_verify(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle,
                     TPM2_ALG_ID scheme, TPM2_ALG_ID hashAlgo,
                     const unsigned char *dataIn, size_t inLen,
                     unsigned char *sigR, size_t rLen,
                     unsigned char *sigS, size_t sLen, int *result) {
    if (inLen != tpmapi_alg2HashSize(hashAlgo) ||
        rLen < TPM2_EC_NIST_P256_BYTES ||
        sLen < TPM2_EC_NIST_P256_BYTES ) {
        printf("%s tpmapi_ecp_verify invalid length error\n", FILE_TPMAPI);
        return 1;
    }

    *result = 0;

    TPMT_SIGNATURE signature = {0};
    switch (scheme) {
        case TPM2_ALG_ECDSA:
            signature.sigAlg = TPM2_ALG_ECDSA;
            signature.signature.ecdsa.hash = hashAlgo;
            signature.signature.ecdsa.signatureR.size = rLen;
            memcpy(signature.signature.ecdsa.signatureR.buffer, sigR, rLen);
            signature.signature.ecdsa.signatureS.size = sLen;
            memcpy(signature.signature.ecdsa.signatureS.buffer, sigS, sLen);
            break;
        default:
            printf("%s unknown scheme error\n", FILE_TPMAPI);
            return 1;
    }

    // Open encrypted session
    TPM2_HANDLE sHandle;
    if (tpmapi_openEncryptedSession(ectx, &sHandle)) {
        printf("%s tpmapi_openEncryptedSession error\n", FILE_TPMAPI);
        return 1;
    }

    TPM2B_DIGEST hash = {
        .size = inLen
    };
    memcpy(hash.buffer, dataIn, inLen);

    ESYS_TR keyHandle;
    TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, pHandle,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &keyHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\n", FILE_TPMAPI);
        return 1;
    }

    /* This is a ticket generated by verify signature,
     * no clue what is the purpose of it... */
    TPMT_TK_VERIFIED *validation;
    rval = Esys_VerifySignature(ectx, keyHandle,
            sHandle, ESYS_TR_NONE, ESYS_TR_NONE,
            &hash, &signature, &validation);
    int mask = rval & (TPM2_RC_FMT1 + 0x3F);
    if (rval != TSS2_RC_SUCCESS && mask != TPM2_RC_SIGNATURE) {
        printf("%s Esys_VerifySignature error\n", FILE_TPMAPI);
        return 0;
    }

    if (rval == TSS2_RC_SUCCESS)
        *result = 1;

    free(validation);

    printf("%s TPM verification using EC key handle 0x%x\n", FILE_TPMAPI, pHandle);

    // Close encrypted session
    if (tpmapi_closeEncryptedSession(ectx, sHandle)) {
        printf("%s tpmapi_closeEncryptedSession error\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

TPM2_ALG_ID tpmapi_convert_rsaes_algo(int mbedtls_algo) {
    switch (mbedtls_algo) {
        case MBEDTLS_RSA_PKCS_V15:
            return TPM2_ALG_RSAES;
        case MBEDTLS_RSA_PKCS_V21:
            return TPM2_ALG_OAEP;
        default:
            return TPM2_ALG_NULL;
    }
}

TPM2_ALG_ID tpmapi_convert_rsassa_algo(int mbedtls_algo) {
    switch (mbedtls_algo) {
        case MBEDTLS_RSA_PKCS_V15:
            return TPM2_ALG_RSASSA;
        case MBEDTLS_RSA_PKCS_V21:
            return TPM2_ALG_RSAPSS;
        default:
            return TPM2_ALG_NULL;
    }
}

TPM2_ALG_ID tpmapi_convert_ecp_algo(int mbedtls_algo) {
    switch (mbedtls_algo) {
        case MBEDTLS_PK_ECDSA:
            return TPM2_ALG_ECDSA;
        default:
            return TPM2_ALG_NULL;
    }
}

TPM2_ALG_ID tpmapi_convert_hash_algo(int mbedtls_algo) {
    switch (mbedtls_algo) {
        case MBEDTLS_MD_SHA256:
            return TPM2_ALG_SHA256;
        default:
            return TPM2_ALG_NULL;
    }
}

int tpmapi_wrapped_clear(void) {
    ESYS_CONTEXT *ectx = NULL;

    if (tpmapi_open(&ectx)) {
        printf("%s tpmapi_open error\n", FILE_TPMAPI);
        return 1;
    }

    if (tpmapi_clearPersistentHandle(ectx, TPM_HANDLE_RSALEAFKEY)) {
        printf("%s tpmapi_clearPersistentHandle(TPM_HANDLE_RSALEAFKEY) error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_clearPersistentHandle(ectx, TPM_HANDLE_ECPLEAFKEY)) {
        printf("%s tpmapi_clearPersistentHandle(TPM_HANDLE_RSALEAFKEY) error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_clearPersistentHandle(ectx, TPM_HANDLE_PRIMARYKEY)) {
        printf("%s tpmapi_clearPersistentHandle(TPM_HANDLE_PRIMARYKEY) error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_close(&ectx)) {
        printf("%s tpmapi_close error\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

int tpmapi_wrapped_perso(void) {
    ESYS_CONTEXT *ectx = NULL;
    int count = 0, found = 0;
    TPM2_HANDLE *persistent_sys_handles = NULL;
    
    if (tpmapi_open(&ectx)) {
        printf("%s tpmapi_open error\n", FILE_TPMAPI);
        return 1;
    }

    // get number of keys
    if (tpmapi_getSysHandle(ectx, TPM2_PERSISTENT_FIRST, &count, NULL)) {
        printf("%s tpmapi_getSysHandle error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    // check keys
    if (count > 0) {
        size_t i = 0;

        // look for existing keys
        if (tpmapi_getSysHandle(ectx, TPM2_PERSISTENT_FIRST, &count, &persistent_sys_handles)) {
            printf("%s tpmapi_getSysHandle error\n", FILE_TPMAPI);
            tpmapi_close(&ectx);
            free(persistent_sys_handles);
            return 1;
        }

        for (i=0 ; i<count; i++) {
            if (*(persistent_sys_handles + i) == TPM_HANDLE_PRIMARYKEY
                || *(persistent_sys_handles + i) == TPM_HANDLE_ECPLEAFKEY
                || *(persistent_sys_handles + i) == TPM_HANDLE_RSALEAFKEY) {
                found++;
            }
        } 

        free(persistent_sys_handles);
    }

    // initialize tpm if key not found
    if (found != 3) {

        printf("%s keys missing, clear and provision the TPM...\n", FILE_TPMAPI);

        if (tpmapi_forceClear(ectx)) {
            printf("%s tpmapi_forceClear error\n", FILE_TPMAPI);
            tpmapi_close(&ectx);
            return 1;
        }

        if (tpmapi_takeOwnership(ectx)) {
            printf("%s tpmapi_takeOwnership error\n", FILE_TPMAPI);
            tpmapi_close(&ectx);
            return 1;
        }

        if (tpmapi_createPrimaryKey(ectx)) {
            printf("%s tpmapi_createPrimaryKey error\n", FILE_TPMAPI);
            tpmapi_close(&ectx);
            return 1;
        }

        if (tpmapi_createRsaLeafKey(ectx, TPM_HANDLE_PRIMARYKEY)) {
            printf("%s tpmapi_createRsaLeafKey error\n", FILE_TPMAPI);
            tpmapi_close(&ectx);
            return 1;
        }

        if (tpmapi_createEcpLeafKey(ectx, TPM_HANDLE_PRIMARYKEY)) {
            printf("%s tpmapi_createEcpLeafKey error\n", FILE_TPMAPI);
            tpmapi_close(&ectx);
            return 1;
        }

        printf("%s TPM provisioning completed\n", FILE_TPMAPI);

    } else {
        printf("%s TPM is already provisioned, no work to be done\n", FILE_TPMAPI);
    }

    if (tpmapi_close(&ectx)) {
        printf("%s tpmapi_close error\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

int tpmapi_wrapped_rsa_sign(TPM2_ALG_ID scheme, TPM2_ALG_ID hashAlgo, const unsigned char *hash, size_t hashLen, unsigned char *sig, size_t *sigLen) {
    ESYS_CONTEXT *ectx = NULL;
    
    if (tpmapi_open(&ectx)) {
        printf("%s tpmapi_open error\n", FILE_TPMAPI);
        return 1;
    }
    
    if (tpmapi_rsa_sign(ectx, TPM_HANDLE_RSALEAFKEY, scheme, hashAlgo, hash, hashLen, sig, sigLen)) {
        printf("%s tpmapi_rsa_sign error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }
    
    if (tpmapi_close(&ectx)) {
        printf("%s tpmapi_close error\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

int tpmapi_wrapped_ecp_sign(TPM2_ALG_ID scheme, TPM2_ALG_ID hashAlgo, const unsigned char *hash, size_t hashLen, unsigned char *sigR, size_t *rLen, unsigned char *sigS, size_t *sLen) {
    ESYS_CONTEXT *ectx = NULL;
    
    if (tpmapi_open(&ectx)) {
        printf("%s tpmapi_open error\n", FILE_TPMAPI);
        return 1;
    }
    
    if (tpmapi_ecp_sign(ectx, TPM_HANDLE_ECPLEAFKEY, scheme, hashAlgo, hash, hashLen, sigR, rLen, sigS, sLen)) {
        printf("%s tpmapi_rsa_sign error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }
    
    if (tpmapi_close(&ectx)) {
        printf("%s tpmapi_close error\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

int tpmapi_wrapped_decipher(TPM2_ALG_ID scheme, TPM2_ALG_ID hash, const unsigned char *input, size_t inLen, unsigned char *output, size_t *outLen) {
    ESYS_CONTEXT *ectx = NULL;
    
    if (tpmapi_open(&ectx)) {
        printf("%s tpmapi_open error\n", FILE_TPMAPI);
        return 1;
    }

    if (tpmapi_decipher(ectx, TPM_HANDLE_RSALEAFKEY, scheme, hash, input, inLen, output, outLen)) {
        printf("%s tpmapi_decipher error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_close(&ectx)) {
        printf("%s tpmapi_close error\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

int tpmapi_wrapped_getRsaPk(int *exponent, unsigned char *mod, size_t *modLen) {
    ESYS_CONTEXT *ectx = NULL;
    
    if (tpmapi_open(&ectx)) {
        printf("%s tpmapi_open error\n", FILE_TPMAPI);
        return 1;
    }

    if (tpmapi_readRsaPublicKey(ectx, TPM_HANDLE_RSALEAFKEY, exponent, mod, modLen)) {
        printf("%s tpmapi_readRsaPublicKey error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_close(&ectx)) {
        printf("%s tpmapi_close error\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

int tpmapi_wrapped_getEcpPk(unsigned char *x, size_t *xLen, unsigned char *y, size_t *yLen) {
    ESYS_CONTEXT *ectx = NULL;
    
    if (tpmapi_open(&ectx)) {
        printf("%s tpmapi_open error\n", FILE_TPMAPI);
        return 1;
    }

    
    if (tpmapi_readEcpPublicKey(ectx, TPM_HANDLE_ECPLEAFKEY, x, xLen, y, yLen)) {
        printf("%s tpmapi_readEcpPublicKey error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_close(&ectx)) {
        printf("%s tpmapi_close error\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

int tpmapi_wrapped_getRandom(unsigned char *rnd, size_t *len) {
    ESYS_CONTEXT *ectx = NULL;
    
    if (tpmapi_open(&ectx)) {
        printf("%s tpmapi_open error\n", FILE_TPMAPI);
        return 1;
    }

    if (tpmapi_getRandom(ectx, rnd, len)) {
        printf("%s tpmapi_getRandom error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_close(&ectx)) {
        printf("%s tpmapi_close error\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

int tpmapi_unit_test() {
    ESYS_CONTEXT *ectx = NULL;
    int count, result, exponent;
    unsigned char rnd[32], mod[256], message[32], cipher[256], decipher[256], hash[32], sig[256];
    unsigned char sig_r[32], sig_s[32];
    size_t rnd_len = sizeof(rnd), mod_len = sizeof(mod), sig_len = sizeof(sig);
    size_t sig_r_len = sizeof(sig_r), sig_s_len = sizeof(sig_s);
    size_t cipher_len = sizeof(cipher), decipher_len = sizeof(decipher);

    memset(message, 0x55, sizeof(message));
    memset(cipher, 0, sizeof(cipher));
    memset(decipher, 0, sizeof(decipher));
    memset(hash, 0x2a, sizeof(hash));
    memset(sig, 0, sizeof(sig));

    if (tpmapi_open(&ectx)) {
        printf("%s tpmapi_open error\n", FILE_TPMAPI);
        return 1;
    }

    if (tpmapi_forceClear(ectx)) {
        printf("%s tpmapi_forceClear error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_takeOwnership(ectx)) {
        printf("%s tpmapi_takeOwnership error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_createPrimaryKey(ectx)) {
        printf("%s tpmapi_createPrimaryKey error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_getRandom(ectx, rnd, &rnd_len)) {
        printf("%s tpmapi_getRandom error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_createRsaLeafKey(ectx, TPM_HANDLE_PRIMARYKEY)) {
        printf("%s tpmapi_createLeafKey error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_createEcpLeafKey(ectx, TPM_HANDLE_PRIMARYKEY)) {
        printf("%s tpmapi_createLeafKey error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_readRsaPublicKey(ectx, TPM_HANDLE_RSALEAFKEY, &exponent, mod, &mod_len)) {
        printf("%s tpmapi_readRsaPublicKey error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_getSysHandle(ectx, TPM2_PERSISTENT_FIRST, &count, NULL)) {
        printf("%s tpmapi_getSysHandle error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_cipher(ectx, TPM_HANDLE_RSALEAFKEY, TPM2_ALG_RSAES, TPM2_ALG_NULL, message, sizeof(message), cipher, &cipher_len)) {
        printf("%s tpmapi_cipher error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_decipher(ectx, TPM_HANDLE_RSALEAFKEY, TPM2_ALG_RSAES, TPM2_ALG_NULL, cipher, cipher_len, decipher, &decipher_len)) {
        printf("%s tpmapi_decipher error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    cipher_len = sizeof(cipher);
    if (tpmapi_cipher(ectx, TPM_HANDLE_RSALEAFKEY, TPM2_ALG_OAEP, TPM2_ALG_SHA256, message, sizeof(message), cipher, &cipher_len)) {
        printf("%s tpmapi_cipher error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    decipher_len = sizeof(decipher);
    if (tpmapi_decipher(ectx, TPM_HANDLE_RSALEAFKEY, TPM2_ALG_OAEP, TPM2_ALG_SHA256, cipher, cipher_len, decipher, &decipher_len)) {
        printf("%s tpmapi_decipher error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_rsa_sign(ectx, TPM_HANDLE_RSALEAFKEY, TPM2_ALG_RSASSA, TPM2_ALG_SHA256, hash, sizeof(hash), sig, &sig_len)) {
        printf("%s tpmapi_rsa_sign error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_rsa_verify(ectx, TPM_HANDLE_RSALEAFKEY, TPM2_ALG_RSASSA, TPM2_ALG_SHA256, hash, sizeof(hash), sig, sig_len, &result)) {
        printf("%s tpmapi_rsa_verify error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    sig_len = sizeof(sig);
    if (tpmapi_rsa_sign(ectx, TPM_HANDLE_RSALEAFKEY, TPM2_ALG_RSAPSS, TPM2_ALG_SHA256, hash, sizeof(hash), sig, &sig_len)) {
        printf("%s tpmapi_rsa_sign error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_rsa_verify(ectx, TPM_HANDLE_RSALEAFKEY, TPM2_ALG_RSAPSS, TPM2_ALG_SHA256, hash, sizeof(hash), sig, sig_len, &result)) {
        printf("%s tpmapi_rsa_verify error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_ecp_sign(ectx, TPM_HANDLE_ECPLEAFKEY, TPM2_ALG_ECDSA, TPM2_ALG_SHA256, hash, sizeof(hash), sig_r, &sig_r_len, sig_s, &sig_s_len)) {
        printf("%s tpmapi_ecp_sign error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_ecp_verify(ectx, TPM_HANDLE_ECPLEAFKEY, TPM2_ALG_ECDSA, TPM2_ALG_SHA256, hash, sizeof(hash), sig_r, sig_r_len, sig_s, sig_s_len, &result)) {
        printf("%s tpmapi_ecp_verify error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_clearPersistentHandle(ectx, TPM_HANDLE_RSALEAFKEY)) {
        printf("%s tpmapi_clearPersistentHandle(TPM_HANDLE_RSALEAFKEY) error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_clearPersistentHandle(ectx, TPM_HANDLE_ECPLEAFKEY)) {
        printf("%s tpmapi_clearPersistentHandle(TPM_HANDLE_ECPLEAFKEY) error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_clearPersistentHandle(ectx, TPM_HANDLE_PRIMARYKEY)) {
        printf("%s tpmapi_clearPersistentHandle(TPM_HANDLE_PRIMARYKEY) error\n", FILE_TPMAPI);
        tpmapi_close(&ectx);
        return 1;
    }

    if (tpmapi_close(&ectx)) {
        printf("%s tpmapi_close error\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}
