#include "gpkcs11_locl.h"

struct gpkcs11_soft_token_t gpkcs11_soft_token;

#define MYPROXY_MODULE_VERSION "1.0"

CK_RV
C_Initialize(CK_VOID_PTR a)
{
    CK_C_INITIALIZE_ARGS_PTR args = a;
    gpkcs11_log("Initialize\n");
    int i;
    CK_RV ret;

    if (a != NULL_PTR) {
	gpkcs11_log("\tCreateMutex:\t%p\n", args->CreateMutex);
	gpkcs11_log("\tDestroyMutext\t%p\n", args->DestroyMutex);
	gpkcs11_log("\tLockMutext\t%p\n", args->LockMutex);
	gpkcs11_log("\tUnlockMutext\t%p\n", args->UnlockMutex);
	gpkcs11_log("\tFlags\t%04x\n", (unsigned int)args->flags);
    }

    ret = gpkcs11_init_token(MYPROXY_MODULE_VERSION,
			     "MyProxy repository",
			     &gpkcs11_soft_token);
    if (ret)
	return ret;
    
    return CKR_OK;
}

static CK_RV
func_not_supported(void)
{
    gpkcs11_log("function not supported\n");
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_FUNCTION_LIST funcs = {
    { 2, 11 },
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    C_InitToken,
    (void *)func_not_supported, /* C_InitPIN */
    (void *)func_not_supported, /* C_SetPIN */
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
    (void *)func_not_supported, /* C_GetOperationState */
    (void *)func_not_supported, /* C_SetOperationState */
    C_Login,
    C_Logout,
    (void *)func_not_supported, /* C_CreateObject */
    (void *)func_not_supported, /* C_CopyObject */
    (void *)func_not_supported, /* C_DestroyObject */
    (void *)func_not_supported, /* C_GetObjectSize */
    C_GetAttributeValue,
    (void *)func_not_supported, /* C_SetAttributeValue */
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    C_EncryptInit,
    C_Encrypt,
    C_EncryptUpdate,
    C_EncryptFinal,
    C_DecryptInit,
    C_Decrypt,
    C_DecryptUpdate,
    C_DecryptFinal,
    C_DigestInit,
    (void *)func_not_supported, /* C_Digest */
    (void *)func_not_supported, /* C_DigestUpdate */
    (void *)func_not_supported, /* C_DigestKey */
    (void *)func_not_supported, /* C_DigestFinal */
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    C_SignFinal,
    (void *)func_not_supported, /* C_SignRecoverInit */
    (void *)func_not_supported, /* C_SignRecover */
    C_VerifyInit,
    C_Verify,
    C_VerifyUpdate,
    C_VerifyFinal,
    (void *)func_not_supported, /* C_VerifyRecoverInit */
    (void *)func_not_supported, /* C_VerifyRecover */
    (void *)func_not_supported, /* C_DigestEncryptUpdate */
    (void *)func_not_supported, /* C_DecryptDigestUpdate */
    (void *)func_not_supported, /* C_SignEncryptUpdate */
    (void *)func_not_supported, /* C_DecryptVerifyUpdate */
    (void *)func_not_supported, /* C_GenerateKey */
    (void *)func_not_supported, /* C_GenerateKeyPair */
    (void *)func_not_supported, /* C_WrapKey */
    (void *)func_not_supported, /* C_UnwrapKey */
    (void *)func_not_supported, /* C_DeriveKey */
    (void *)func_not_supported, /* C_SeedRandom */
    C_GenerateRandom,
    (void *)func_not_supported, /* C_GetFunctionStatus */
    (void *)func_not_supported, /* C_CancelFunction */
    (void *)func_not_supported  /* C_WaitForSlotEvent */
};
