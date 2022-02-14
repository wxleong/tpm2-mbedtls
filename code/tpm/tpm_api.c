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
#include "tpm_api.h"

#define FILE_TPMAPI "tpm_api :"
#define TPM2_RSA_KEY_BITS 2048
#define TPM2_RSA_KEY_BYTES TPM2_RSA_KEY_BITS/8
#define TPM2_RSA_HASH_BYTES 32

uint8_t tpm_openEncryptedSession(ESYS_CONTEXT *ectx, TPM2_HANDLE *sHandle);
uint8_t tpm_closeEncryptedSession(ESYS_CONTEXT *ectx, TPM2_HANDLE sHandle);

uint8_t tpm_open(ESYS_CONTEXT **ectx) {
    TSS2_TCTI_CONTEXT *tcti;

    /* Getting the TCTI context size */
    TSS2_RC rc = Tss2_TctiLdr_Initialize(TCTI_NAME_CONF, &tcti);

    /* Initializing the Esys context */
    rc = Esys_Initialize(ectx, tcti, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        printf("%s Failed to initialize the Esys context\r\n", FILE_TPMAPI);
        return 1;
    }

    /*printf("%s Expected TPM error (256):\r\n"
            "           Error (2.0): TPM_RC_INITIALIZE\r\n"
            "           Description: TPM not initialized by TPM2_Startup or already initialized\r\n",
            FILE_TPMAPI);*/

    return 0;
}

uint8_t tpm_close(ESYS_CONTEXT **ectx) {
    TSS2_TCTI_CONTEXT *tcti = NULL;

    /* Properly shutdown TPM */
    TSS2_RC rc = Esys_Shutdown(*ectx,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            TPM2_SU_CLEAR);
    if (rc != TPM2_RC_SUCCESS) {
        printf("%s Failed to Esys_Shutdown()\r\n", FILE_TPMAPI);
        return 1;
    }

    /* Get tcti context */
    rc = Esys_GetTcti(*ectx, &tcti);
    if (rc != TPM2_RC_SUCCESS) {
        printf("%s Failed to Esys_GetTcti()\r\n", FILE_TPMAPI);
        return 1;
    }

    /* Clean up TSS, TIS, and Hardware layers */
    Esys_Finalize(ectx);

    Tss2_TctiLdr_Finalize(&tcti);

    return 0;
}

/* Returns only the 1st handle found */
uint8_t tpm_getSysHandle(ESYS_CONTEXT *ectx, UINT32 property, uint8_t *count, TPM2_HANDLE **sys_handles) {
    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA *fetched_data = NULL;
    TSS2_RC rval = Esys_GetCapability (ectx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                       TPM2_CAP_HANDLES, property, TPM2_MAX_CAP_HANDLES,
                                       &more_data, &fetched_data);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_GetCapability error\r\n", FILE_TPMAPI);
        return 1;
    }

    *count = (uint8_t) fetched_data->data.handles.count;

    if (sys_handles != NULL) {
        size_t i = 0;
        for (; i<*count; i++)
            **(sys_handles + i) = fetched_data->data.handles.handle[i];
    }

    free(fetched_data);
    return 0;
}

uint8_t tpm_readPublicKey(ESYS_CONTEXT *ectx, TPM2_HANDLE handle, uint32_t *exponent, uint8_t *mod, uint16_t *modlen) {

    TPM2B_NAME *nameKeySign;
    TPM2B_NAME *keyQualifiedName;
    TPM2B_PUBLIC *outPublic;
    ESYS_TR keyHandle;
    TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, handle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &keyHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\r\n", FILE_TPMAPI);
        return 1;
    }

    // Open encrypted session
    TPM2_HANDLE sHandle = ESYS_TR_NONE;
    if (tpm_openEncryptedSession(ectx, &sHandle)) {
        printf("%s tpm_openEncryptedSession error\r\n", FILE_TPMAPI);
        return 1;
    }

    rval = Esys_ReadPublic(ectx, keyHandle, sHandle, ESYS_TR_NONE,
                           ESYS_TR_NONE, &outPublic, &nameKeySign,
                           &keyQualifiedName);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_ReadPublic error\r\n", FILE_TPMAPI);
        return 1;
    }
    
    // Close encrypted session
    if (tpm_closeEncryptedSession(ectx, sHandle)) {
        printf("%s tpm_closeEncryptedSession error\r\n", FILE_TPMAPI);
        return 1;
    }

    *exponent = outPublic->publicArea.parameters.rsaDetail.exponent;
    if (*exponent == 0)
        *exponent = 65537; //0x10001

    uint16_t len = outPublic->publicArea.unique.rsa.size;
    
    if (len > *modlen) {
        printf("%s tpm_readPublicKey output buffer insufficient error\r\n", FILE_TPMAPI);
        return 1;
    }
    *modlen = len;
    memcpy(mod, outPublic->publicArea.unique.rsa.buffer, len);
    
    free(nameKeySign);
    free(keyQualifiedName);
    free(outPublic);
    printf("%s TPM read public key of handle: 0x%lx\r\n", FILE_TPMAPI, handle);
    return 0;
}

uint8_t tpm_clearTransientHandle(ESYS_CONTEXT *ectx, TPM2_HANDLE tHandle) {
    ESYS_TR handle;
    TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, tHandle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &handle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\r\n", FILE_TPMAPI);
        return 1;
    }

    rval = Esys_FlushContext(ectx, handle);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_FlushContext error\r\n", FILE_TPMAPI);
        return 1;
    }

    printf("%s TPM cleared transient handle: 0x%lx\r\n", FILE_TPMAPI, tHandle);
    return 0;
}

uint8_t tpm_clearPersistentHandle(ESYS_CONTEXT *ectx, TPM2_HANDLE tHandle) {
    TPM2B_DIGEST pwd;
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", "owner123");

    TSS2_RC rval = Esys_TR_SetAuth(ectx, ESYS_TR_RH_OWNER, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_TR_SetAuth error\r\n", FILE_TPMAPI);
        return 1;
    }

    ESYS_TR handle;
    rval = Esys_TR_FromTPMPublic(ectx, tHandle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &handle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\r\n", FILE_TPMAPI);
        return 1;
    }

    ESYS_TR dummy;
    rval = Esys_EvictControl(ectx, ESYS_TR_RH_OWNER, handle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, &dummy);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_EvictControl error\r\n", FILE_TPMAPI);
        return 1;
    }

    printf("%s TPM cleared persistent handle: 0x%lx\r\n", FILE_TPMAPI, tHandle);
    return 0;
}

uint8_t tpm_persistHandle(ESYS_CONTEXT *ectx, TPM2_HANDLE tHandle, TPM2_HANDLE pHandle) {
    TPM2B_DIGEST pwd;
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", "owner123");
    
    TSS2_RC rval = Esys_TR_SetAuth(ectx, ESYS_TR_RH_OWNER, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_TR_SetAuth error\r\n", FILE_TPMAPI);
        return 1;
    }

    ESYS_TR transientHandle;
    rval = Esys_TR_FromTPMPublic(ectx, tHandle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &transientHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\r\n", FILE_TPMAPI);
        return 1;
    }

    ESYS_TR persistentHandle;
    rval = Esys_EvictControl(ectx, ESYS_TR_RH_OWNER, transientHandle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            pHandle, &persistentHandle);

    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_EvictControl error\r\n", FILE_TPMAPI);
        return 1;
    }

    printf("%s Transient object (0x%lx) moved to persistent (0x%lx)\r\n", FILE_TPMAPI, tHandle, pHandle);
    return 0;
}

uint8_t tpm_createLeafKey(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle)
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
            printf("%s Esys_TR_FromTPMPublic error\r\n", FILE_TPMAPI);
            return 1;
        }
        
        TPM2B_DIGEST pwd;
        pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", "RSAprimary123");
        
        rval = Esys_TR_SetAuth(ectx, primaryHandle, &pwd);
        if (rval != TPM2_RC_SUCCESS) {
            printf("%s Esys_TR_SetAuth error\r\n", FILE_TPMAPI);
            return 1;
        }

        pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", "RSAleaf123");
        
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

        /* RSASSA PKCS1.5 SHA256 */
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
            printf("%s Esys_Create error\r\n", FILE_TPMAPI);
            return 1;
        }
        free(creationData);
        free(creationHash);
        free(creationTicket);

        //printf("%s TPM leaf keypair created\r\n", FILE_TPMAPI);
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
            printf("%s Esys_TR_FromTPMPublic error\r\n", FILE_TPMAPI);
            goto err1;
        }
        
        TPM2B_DIGEST pwd;
        pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", "RSAprimary123");
        
        rval = Esys_TR_SetAuth(ectx, primaryHandle, &pwd);
        if (rval != TPM2_RC_SUCCESS) {
            printf("%s Esys_TR_SetAuth error\r\n", FILE_TPMAPI);
            goto err1;
        }
        
        rval = Esys_Load(ectx, primaryHandle,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                outPrivate, outPublic, &transientHandle);
        if (rval != TPM2_RC_SUCCESS)
        {
            printf("%s Esys_Load error\r\n", FILE_TPMAPI);
            goto err1;
        }
    }
        
    ESYS_TR persistentHandle;
    TPM2_RC rval = Esys_EvictControl(ectx, ESYS_TR_RH_OWNER, transientHandle,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            TPM_HANDLE_LEAFKEY, &persistentHandle);

    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_EvictControl error\r\n", FILE_TPMAPI);
        goto err1;
    }

    printf("%s Created persistent leaf key (0x%lx)\r\n", FILE_TPMAPI, TPM_HANDLE_LEAFKEY);

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

uint8_t tpm_createPrimaryKey(ESYS_CONTEXT *ectx) {
    TPM2B_DIGEST pwd;
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", "owner123");
    
    TSS2_RC rval = Esys_TR_SetAuth(ectx, ESYS_TR_RH_OWNER, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_TR_SetAuth error\r\n", FILE_TPMAPI);
        return 1;
    }

    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", "RSAprimary123");
    
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
        printf("%s Esys_CreatePrimary error\r\n", FILE_TPMAPI);
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
        printf("%s Esys_EvictControl error\r\n", FILE_TPMAPI);
        return 1;
    }

    printf("%s Created persistent primary key (0x%lx)\r\n", FILE_TPMAPI, TPM_HANDLE_PRIMARYKEY);

    return 0;
}

uint8_t tpm_takeOwnership(ESYS_CONTEXT *ectx) {
    TPM2B_DIGEST pwd;
    
    /* Set owner password */
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", "owner123");
    TSS2_RC rval = Esys_HierarchyChangeAuth(ectx, ESYS_TR_RH_OWNER,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_HierarchyChangeAuth owner error\r\n", FILE_TPMAPI);
        return 1;
    }

    //printf("%s TPM set owner password ok\r\n", FILE_TPMAPI);
    
    /* Set endorsement password */
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", "endorsement123");
    rval = Esys_HierarchyChangeAuth(ectx, ESYS_TR_RH_ENDORSEMENT,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_HierarchyChangeAuth endorsement error\r\n", FILE_TPMAPI);
        return 1;
    }

    //printf("%s TPM set endorsement password ok\r\n", FILE_TPMAPI);
    
    /* Set lockout password */
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", "lockout123");
    rval = Esys_HierarchyChangeAuth(ectx, ESYS_TR_RH_LOCKOUT,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_HierarchyChangeAuth lockout error\r\n", FILE_TPMAPI);
        return 1;
    }

    //printf("%s TPM set lockout password ok\r\n", FILE_TPMAPI);
    
    printf("%s TPM take ownership\r\n", FILE_TPMAPI);
    return 0;
}

uint8_t tpm_forceClear(ESYS_CONTEXT *ectx) {
    TSS2_RC rval = Esys_Clear(ectx, ESYS_TR_RH_PLATFORM,
                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rval != TPM2_RC_SUCCESS && rval != TPM2_RC_INITIALIZE) {
        printf("%s Esys_Clear error\r\n", FILE_TPMAPI);
        return 1;
    }

    printf("%s TPM force clear\r\n", FILE_TPMAPI);
    return 0;
}

uint8_t tpm_openEncryptedSession(ESYS_CONTEXT *ectx, TPM2_HANDLE *sHandle) {
    // Get primary key handle
    TPM2B_DIGEST pwd;
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", "RSAprimary123");
    TPM2_HANDLE tHandle = TPM_HANDLE_PRIMARYKEY;
    ESYS_TR pHandle;
    TSS2_RC rval = Esys_TR_FromTPMPublic(ectx, tHandle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &pHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\r\n", FILE_TPMAPI);
        return 1;
    }

    // Provide auth value to unlock the primary key
    rval = Esys_TR_SetAuth(ectx, pHandle, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_TR_SetAuth error\r\n", FILE_TPMAPI);
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

    printf("%s TPM open encrypted session\r\n", FILE_TPMAPI);
    return 0;
}

uint8_t tpm_closeEncryptedSession(ESYS_CONTEXT *ectx, TPM2_HANDLE sHandle) {
    // Close the session
    TSS2_RC rval = Esys_FlushContext(ectx, sHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_FlushContext error\n", FILE_TPMAPI);
        return 1;
    }

    printf("%s TPM close encrypted session\r\n", FILE_TPMAPI);
    return 0;
}

uint8_t tpm_getRandom(ESYS_CONTEXT *ectx, uint8_t *rnd, uint16_t *len) {

    // Open encrypted session
    TPM2_HANDLE sHandle = ESYS_TR_NONE;
    if (tpm_openEncryptedSession(ectx, &sHandle)) {
        printf("%s tpm_openEncryptedSession error\r\n", FILE_TPMAPI);
        return 1;
    }

    // Get random
    TPM2B_DIGEST *random_bytes;
    TSS2_RC rval = Esys_GetRandom(ectx,
                    sHandle, ESYS_TR_NONE, ESYS_TR_NONE,
                    *len, &random_bytes);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_GetRandom error\r\n", FILE_TPMAPI);
        return 1;
    }
    *len = random_bytes->size;
    memcpy(rnd, random_bytes->buffer, *len);
    free(random_bytes);

    // Close encrypted session
    if (tpm_closeEncryptedSession(ectx, sHandle)) {
        printf("%s tpm_closeEncryptedSession error\r\n", FILE_TPMAPI);
        return 1;
    }

    printf("%s TPM get random\r\n", FILE_TPMAPI);
    return 0;
}

uint8_t tpm_cipher(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, uint8_t *datain,
                   uint16_t lenin, uint8_t *dataout, uint16_t *lenout) {
    
    if (lenin > TPM2_RSA_KEY_BYTES || *lenout < TPM2_RSA_KEY_BYTES) {
        printf("%s tpm_cipher invalid length error\r\n", FILE_TPMAPI);
        return 1;
    }

    // Open encrypted session
    TPM2_HANDLE sHandle;
    if (tpm_openEncryptedSession(ectx, &sHandle)) {
        printf("%s tpm_openEncryptedSession error\r\n", FILE_TPMAPI);
        return 1;
    }

    TPM2B_PUBLIC_KEY_RSA *encrypted_msg;
    TPM2B_PUBLIC_KEY_RSA clear_msg = {
        .size = lenin,
    };
    memcpy(clear_msg.buffer, datain, lenin);
    
    ESYS_TR keyHandle;
    TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, pHandle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &keyHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\r\n", FILE_TPMAPI);
        return 1;
    }

    
    TPM2B_DATA label = {
        .size = 0,
        .buffer = {0}
    };

    TPMT_RSA_DECRYPT scheme = { 
        .scheme = TPM2_ALG_OAEP,
        .details = {
            .oaep = {
                .hashAlg = TPM2_ALG_SHA1
            }
        }
    };

    rval = Esys_RSA_Encrypt(ectx, keyHandle,
                            sHandle, ESYS_TR_NONE, ESYS_TR_NONE,
                            &clear_msg, &scheme, &label, &encrypted_msg);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_RSA_Encrypt error\r\n", FILE_TPMAPI);
        return 1;
    }
    
    memcpy(dataout, encrypted_msg->buffer, encrypted_msg->size);
    *lenout = encrypted_msg->size;
    
    free(encrypted_msg);

    // Close encrypted session
    if (tpm_closeEncryptedSession(ectx, sHandle)) {
        printf("%s tpm_closeEncryptedSession error\r\n", FILE_TPMAPI);
        return 1;
    }

    printf("%s TPM encryption using RSA key handle 0x%lx\r\n", FILE_TPMAPI, pHandle);
    return 0;
}

uint8_t tpm_decipher(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, uint8_t *datain,
           uint16_t lenin, uint8_t *dataout, uint16_t *lenout) {

    if (lenin > TPM2_RSA_KEY_BYTES || *lenout < TPM2_RSA_KEY_BYTES) {
        printf("%s tpm_decipher invalid length error\r\n", FILE_TPMAPI);
        return 1;
    }

    // Open encrypted session
    TPM2_HANDLE sHandle;
    if (tpm_openEncryptedSession(ectx, &sHandle)) {
        printf("%s tpm_openEncryptedSession error\r\n", FILE_TPMAPI);
        return 1;
    }

    ESYS_TR keyHandle;
    TPM2B_PUBLIC_KEY_RSA *decrypted_msg;
    TPM2B_PUBLIC_KEY_RSA encrypted_msg = {
        .size = lenin,
    };
    memcpy(encrypted_msg.buffer, datain, lenin);
    
    TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, pHandle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &keyHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\r\n", FILE_TPMAPI);
        return 1;
    }

    TPM2B_DIGEST pwd;
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", "RSAleaf123");

    rval = Esys_TR_SetAuth(ectx, keyHandle, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_TR_SetAuth error\r\n", FILE_TPMAPI);
        return 1;
    }

    TPM2B_DATA null_data = {
        .size = 0,
        .buffer = {0}
    };

    TPMT_RSA_DECRYPT scheme = { 
        .scheme = TPM2_ALG_OAEP,
        .details = {
            .oaep = {
                .hashAlg = TPM2_ALG_SHA1
            }
        }
    };

    rval = Esys_RSA_Decrypt(ectx, keyHandle, sHandle, ESYS_TR_NONE, ESYS_TR_NONE,&encrypted_msg, &scheme, &null_data, &decrypted_msg);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_RSA_Decrypt error\r\n", FILE_TPMAPI);
        return 1;
    }
    
    memcpy(dataout, decrypted_msg->buffer, decrypted_msg->size);
    *lenout = decrypted_msg->size;
    
    free(decrypted_msg);

    // Close encrypted session
    if (tpm_closeEncryptedSession(ectx, sHandle)) {
        printf("%s tpm_closeEncryptedSession error\r\n", FILE_TPMAPI);
        return 1;
    }

    printf("%s TPM decryption using RSA key handle 0x%lx\r\n", FILE_TPMAPI, pHandle);
    return 0;
}

uint8_t tpm_sign(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, uint8_t *datain,
                   uint16_t lenin, uint8_t *dataout, uint16_t *lenout) {
    
    if (lenin != TPM2_RSA_HASH_BYTES || *lenout < TPM2_RSA_KEY_BYTES) {
        printf("%s tpm_sign invalid length error\r\n", FILE_TPMAPI);
        return 1;
    }

    // Open encrypted session
    TPM2_HANDLE sHandle;
    if (tpm_openEncryptedSession(ectx, &sHandle)) {
        printf("%s tpm_openEncryptedSession error\r\n", FILE_TPMAPI);
        return 1;
    }

    ESYS_TR keyHandle;
    TPMT_SIGNATURE *signature;
    TPM2B_DIGEST digest = {
        .size = lenin
    };
    memcpy(digest.buffer, datain, lenin);
    
    TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, pHandle,
                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &keyHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\r\n", FILE_TPMAPI);
        return 1;
    }

    TPM2B_DIGEST pwd;
    pwd.size = (UINT16)snprintf((char *)pwd.buffer, sizeof(pwd.buffer), "%s", "RSAleaf123");
    
    rval = Esys_TR_SetAuth(ectx, keyHandle, &pwd);
    if (rval != TPM2_RC_SUCCESS) {
        printf("%s Esys_TR_SetAuth error\r\n", FILE_TPMAPI);
        return 1;
    }
    
    TPMT_SIG_SCHEME scheme = { 
        .scheme = TPM2_ALG_RSASSA,
        .details = {
            .rsassa = {
                .hashAlg = TPM2_ALG_SHA256
            }
        }
    };

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
        printf("%s Esys_Sign error\r\n", FILE_TPMAPI);
        return 1;
    }

    *lenout = signature->signature.rsassa.sig.size;
    memcpy(dataout, signature->signature.rsassa.sig.buffer, *lenout);

    free(signature);

    // Close encrypted session
    if (tpm_closeEncryptedSession(ectx, sHandle)) {
        printf("%s tpm_closeEncryptedSession error\r\n", FILE_TPMAPI);
        return 1;
    }

    printf("%s TPM signing using RSA key handle 0x%lx\r\n", FILE_TPMAPI, pHandle);
    return 0;

}

uint8_t tpm_verify(ESYS_CONTEXT *ectx, TPM2_HANDLE pHandle, uint8_t *digest,
                   uint16_t digestlen, uint8_t *sig, uint16_t siglen, uint8_t *result) {
    *result = 0;
    if (digestlen != TPM2_RSA_HASH_BYTES || siglen < TPM2_RSA_KEY_BYTES) {
        printf("%s tpm_verify invalid length error\r\n", FILE_TPMAPI);
        return 1;
    }

    // Open encrypted session
    TPM2_HANDLE sHandle;
    if (tpm_openEncryptedSession(ectx, &sHandle)) {
        printf("%s tpm_openEncryptedSession error\r\n", FILE_TPMAPI);
        return 1;
    }

    ESYS_TR keyHandle;
    TPMT_SIGNATURE signature = {
        .sigAlg = TPM2_ALG_RSASSA,
        .signature.rsassa = {
            .hash = TPM2_ALG_SHA256,
            .sig.size = siglen,
        }
    };
    memcpy(signature.signature.rsassa.sig.buffer, sig, siglen);
    TPM2B_DIGEST hash = {
        .size = digestlen
    };
    memcpy(hash.buffer, digest, digestlen);
    
    
    TPM2_RC rval = Esys_TR_FromTPMPublic(ectx, pHandle,
            sHandle, ESYS_TR_NONE, ESYS_TR_NONE, &keyHandle);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_TR_FromTPMPublic error\r\n", FILE_TPMAPI);
        return 1;
    }

    /* This is a ticket generated by verify signature,
     * no clue what is the purpose of it... */
    TPMT_TK_VERIFIED *validation;

    rval = Esys_VerifySignature(ectx, keyHandle,
            sHandle, ESYS_TR_NONE, ESYS_TR_NONE,
            &hash, &signature, &validation);
    if (rval != TSS2_RC_SUCCESS) {
        printf("%s Esys_VerifySignature error\r\n", FILE_TPMAPI);
        return 0;
    }

    *result = 1;
    free(validation);

    // Close encrypted session
    if (tpm_closeEncryptedSession(ectx, sHandle)) {
        printf("%s tpm_closeEncryptedSession error\r\n", FILE_TPMAPI);
        return 1;
    }

    printf("%s TPM verification using RSA key handle 0x%lx\r\n", FILE_TPMAPI, pHandle);
    return 0;
}

uint8_t tpm_wrap_clear(void) {
    ESYS_CONTEXT *ectx = NULL;

    if (tpm_open(&ectx)) {
        printf("%s tpm_open error\r\n", FILE_TPMAPI);
        return 1;
    }

    if (tpm_clearPersistentHandle(ectx, TPM_HANDLE_LEAFKEY)) {
        printf("%s tpm_clearPersistentHandle(TPM_HANDLE_LEAFKEY) error\r\n", FILE_TPMAPI);
        tpm_close(&ectx);
        return 1;
    }

    if (tpm_clearPersistentHandle(ectx, TPM_HANDLE_PRIMARYKEY)) {
        printf("%s tpm_clearPersistentHandle(TPM_HANDLE_PRIMARYKEY) error\r\n", FILE_TPMAPI);
        tpm_close(&ectx);
        return 1;
    }

    if (tpm_close(&ectx)) {
        printf("%s tpm_close error\r\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

uint8_t tpm_wrap_perso(void) {
    ESYS_CONTEXT *ectx = NULL;
    uint8_t count = 0, found = 0;
    TPM2_HANDLE **persistent_sys_handles = NULL;
    
    if (tpm_open(&ectx)) {
        printf("%s tpm_open error\r\n", FILE_TPMAPI);
        return 1;
    }

    
    // get number of keys
    if (tpm_getSysHandle(ectx, TPM2_PERSISTENT_FIRST, &count, NULL)) {
        printf("%s tpm_getSysHandle error\r\n", FILE_TPMAPI);
        tpm_close(&ectx);
        return 1;
    }

    // check keys
    if (count > 0) {
        size_t i = 0;
        persistent_sys_handles = malloc(sizeof(TPM2_HANDLE)*count);

        if (persistent_sys_handles == NULL)
            return 1;

        // look for existing keys
        if (tpm_getSysHandle(ectx, TPM2_PERSISTENT_FIRST, &count, persistent_sys_handles)) {
            printf("%s tpm_getSysHandle error\r\n", FILE_TPMAPI);
            tpm_close(&ectx);
            return 1;
        }

        for (; i<count; i++) {
            if (**(persistent_sys_handles + i) == TPM_HANDLE_PRIMARYKEY
                    || **(persistent_sys_handles + i) == TPM_HANDLE_LEAFKEY) {
                found++;
                printf("%s found key handle %04x\r\n", FILE_TPMAPI, **(persistent_sys_handles + i));
            }
        } 
    }

    // initialize tpm if key not found
    if (found != 2) {
        if (tpm_forceClear(ectx)) {
            printf("%s tpm_forceClear error\r\n", FILE_TPMAPI);
            tpm_close(&ectx);
            return 1;
        }

        if (tpm_takeOwnership(ectx)) {
            printf("%s tpm_takeOwnership error\r\n", FILE_TPMAPI);
            tpm_close(&ectx);
            return 1;
        }

        if (tpm_createPrimaryKey(ectx)) {
            printf("%s tpm_createPrimaryKey error\r\n", FILE_TPMAPI);
            tpm_close(&ectx);
            return 1;
        }

        if (tpm_createLeafKey(ectx, TPM_HANDLE_PRIMARYKEY)) {
            printf("%s tpm_createLeafKey error\r\n", FILE_TPMAPI);
            tpm_close(&ectx);
            return 1;
        }
        
        printf("%s TPM provisioning completed\r\n", FILE_TPMAPI);

    } else {
        printf("%s TPM is already provisioned, no work to be done\r\n", FILE_TPMAPI);
    }

    if (tpm_close(&ectx)) {
        printf("%s tpm_close error\r\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

uint8_t tpm_wrap_sign(uint8_t *hash, uint16_t hashlen, uint8_t *sig, uint16_t *siglen) {
    ESYS_CONTEXT *ectx = NULL;
    
    if (tpm_open(&ectx)) {
        printf("%s tpm_open error\r\n", FILE_TPMAPI);
        return 1;
    }
    
    if (tpm_sign(ectx, TPM_HANDLE_LEAFKEY, hash, hashlen, sig, siglen)) {
        printf("%s tpm_sign error\r\n", FILE_TPMAPI);
        tpm_close(&ectx);
        return 1;
    }
    
    if (tpm_close(&ectx)) {
        printf("%s tpm_close error\r\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

uint8_t tpm_wrap_decipher(uint8_t *secret, uint16_t secretlen, uint8_t *msg, uint16_t *msglen) {
    ESYS_CONTEXT *ectx = NULL;
    
    if (tpm_open(&ectx)) {
        printf("%s tpm_open error\r\n", FILE_TPMAPI);
        return 1;
    }
    
    if (tpm_decipher(ectx, TPM_HANDLE_LEAFKEY, secret, secretlen, msg, msglen)) {
        printf("%s tpm_decipher error\r\n", FILE_TPMAPI);
        tpm_close(&ectx);
        return 1;
    }
    
    if (tpm_close(&ectx)) {
        printf("%s tpm_close error\r\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

uint8_t tpm_wrap_getpk(uint32_t *exponent, uint8_t *mod, uint16_t *modlen) {
    ESYS_CONTEXT *ectx = NULL;
    
    if (tpm_open(&ectx)) {
        printf("%s tpm_open error\r\n", FILE_TPMAPI);
        return 1;
    }

    if (tpm_readPublicKey(ectx, TPM_HANDLE_LEAFKEY, exponent, mod, modlen)) {
        printf("%s tpm_readPublicKey error\r\n", FILE_TPMAPI);
        tpm_close(&ectx);
        return 1;
    }

    if (tpm_close(&ectx)) {
        printf("%s tpm_close error\r\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}

uint8_t tpm_wrap_getRandom(uint8_t *rnd, uint16_t *len) {
    ESYS_CONTEXT *ectx = NULL;
    
    if (tpm_open(&ectx)) {
        printf("%s tpm_open error\r\n", FILE_TPMAPI);
        return 1;
    }

    if (tpm_getRandom(ectx, rnd, len)) {
        printf("%s tpm_getRandom error\r\n", FILE_TPMAPI);
        tpm_close(&ectx);
        return 1;
    }

    if (tpm_close(&ectx)) {
        printf("%s tpm_close error\r\n", FILE_TPMAPI);
        return 1;
    }

    return 0;
}
