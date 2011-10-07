#include "gpkcs11_locl.h"

extern gpkcs11_soft_token_t gpkcs11_soft_token;

static void
snprintf_fill(char *str, size_t size, char fillchar, const char *fmt, ...)
{
    int len;
    va_list ap;
    len = vsnprintf(str, size, fmt, ap);
    va_end(ap);
    if (len < 0 || len > size)
	return;
    while(len < size)
	str[len++] = fillchar;
}


static CK_RV
object_handle_to_object(CK_OBJECT_HANDLE handle,
			struct gpkcs11_st_object **object)
{
    int i = HANDLE_OBJECT_ID(handle);

    *object = NULL;
    if (i >= gpkcs11_soft_token.object.num_objs)
	return CKR_ARGUMENTS_BAD;
    if (gpkcs11_soft_token.object.objs[i] == NULL)
	return CKR_ARGUMENTS_BAD;
    if (gpkcs11_soft_token.object.objs[i]->object_handle != handle)
	return CKR_ARGUMENTS_BAD;
    *object = gpkcs11_soft_token.object.objs[i];
    return CKR_OK;
}

static int
attributes_match(const struct gpkcs11_st_object *obj,
		 const CK_ATTRIBUTE *attributes,
		 CK_ULONG num_attributes)
{
    CK_ULONG i;
    int j;
    gpkcs11_log("attributes_match: %ld\n", (unsigned long)OBJECT_ID(obj));

    for (i = 0; i < num_attributes; i++) {
	int match = 0;
	for (j = 0; j < obj->num_attributes; j++) {
	    if (attributes[i].type == obj->attrs[j].attribute.type &&
		attributes[i].ulValueLen == obj->attrs[j].attribute.ulValueLen &&
		memcmp(attributes[i].pValue, obj->attrs[j].attribute.pValue,
		       attributes[i].ulValueLen) == 0) {
		match = 1;
		break;
	    }
	}
	if (match == 0) {
	    gpkcs11_log("type %d attribute have no match\n", attributes[i].type);
	    return 0;
	}
    }
    gpkcs11_log("attribute matches\n");
    return 1;
}

static void
print_attributes(const CK_ATTRIBUTE *attributes,
		 CK_ULONG num_attributes)
{
    CK_ULONG i;

    gpkcs11_log("find objects: attrs: %lu\n", (unsigned long)num_attributes);

    for (i = 0; i < num_attributes; i++) {
	gpkcs11_log("  type: ");
	switch (attributes[i].type) {
	case CKA_TOKEN: {
	    CK_BBOOL *ck_true;
	    if (attributes[i].ulValueLen != sizeof(CK_BBOOL)) {
		gpkcs11_app_error("token attribute wrong length\n");
		break;
	    }
	    ck_true = attributes[i].pValue;
	    gpkcs11_log("token: %s", *ck_true ? "TRUE" : "FALSE");
	    break;
	}
	case CKA_CLASS: {
	    CK_OBJECT_CLASS *class;
	    if (attributes[i].ulValueLen != sizeof(CK_ULONG)) {
		gpkcs11_app_error("class attribute wrong length\n");
		break;
	    }
	    class = attributes[i].pValue;
	    gpkcs11_log("class ");
	    switch (*class) {
	    case CKO_CERTIFICATE:
		gpkcs11_log("certificate");
		break;
	    case CKO_PUBLIC_KEY:
		gpkcs11_log("public key");
		break;
	    case CKO_PRIVATE_KEY:
		gpkcs11_log("private key");
		break;
	    case CKO_SECRET_KEY:
		gpkcs11_log("secret key");
		break;
	    case CKO_DOMAIN_PARAMETERS:
		gpkcs11_log("domain parameters");
		break;
	    default:
		gpkcs11_log("[class %lx]", (long unsigned)*class);
		break;
	    }
	    break;
	}
	case CKA_PRIVATE:
	    gpkcs11_log("private");
	    break;
	case CKA_LABEL:
	    gpkcs11_log("label");
	    break;
	case CKA_APPLICATION:
	    gpkcs11_log("application");
	    break;
	case CKA_VALUE:
	    gpkcs11_log("value");
	    break;
	case CKA_ID:
	    gpkcs11_log("id");
	    break;
	default:
	    gpkcs11_log("[unknown 0x%08lx]", (unsigned long)attributes[i].type);
	    break;
	}
	gpkcs11_log("\n");
    }
}

static void
find_object_final(struct gpkcs11_session_state *state)
{
    if (state->find.attributes) {
	CK_ULONG i;

	for (i = 0; i < state->find.num_attributes; i++) {
	    if (state->find.attributes[i].pValue)
		free(state->find.attributes[i].pValue);
	}
	free(state->find.attributes);
	state->find.attributes = NULL;
	state->find.num_attributes = 0;
	state->find.next_object = -1;
    }
}

void
reset_crypto_state(struct gpkcs11_session_state *state)
{
    state->encrypt_object = -1;
    if (state->encrypt_mechanism)
	free(state->encrypt_mechanism);
    state->encrypt_mechanism = NULL_PTR;
    state->decrypt_object = -1;
    if (state->decrypt_mechanism)
	free(state->decrypt_mechanism);
    state->decrypt_mechanism = NULL_PTR;
    state->sign_object = -1;
    if (state->sign_mechanism)
	free(state->sign_mechanism);
    state->sign_mechanism = NULL_PTR;
    state->verify_object = -1;
    if (state->verify_mechanism)
	free(state->verify_mechanism);
    state->verify_mechanism = NULL_PTR;
    state->digest_object = -1;
}

static void
close_session(struct gpkcs11_session_state *state)
{
    if (state->find.attributes) {
	gpkcs11_app_error("application didn't do C_FindObjectsFinal\n");
	find_object_final(state);
    }

    state->session_handle = CK_INVALID_HANDLE;
    gpkcs11_soft_token.application = NULL_PTR;
    gpkcs11_soft_token.notify = NULL_PTR;
    reset_crypto_state(state);
}

static const char *
has_session(void)
{
    return gpkcs11_soft_token.open_sessions > 0 ? "yes" : "no";
}

CK_RV
gpkcs11_init_token(const char *version, const char *description,
	           gpkcs11_soft_token_t *token)
{
    int i, ret;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    srandom(getpid() ^ time(NULL));

    for (i = 0; i < MAX_NUM_SESSION; i++) {
	token->state[i].session_handle = CK_INVALID_HANDLE;
	token->state[i].find.attributes = NULL;
	token->state[i].find.num_attributes = 0;
	token->state[i].find.next_object = -1;
	reset_crypto_state(&token->state[i]);
    }

    /* Don't pretend being a HW slot, otherwise NSS will cache the objects
       and fails to store all attributes necessary (Serial Number) */
    gpkcs11_soft_token.flags.hardware_slot = 0;
    gpkcs11_soft_token.flags.app_error_fatal = 0;
    gpkcs11_soft_token.flags.login_done = 0;

    gpkcs11_soft_token.object.objs = NULL;
    gpkcs11_soft_token.object.num_objs = 0;

    gpkcs11_soft_token.logfile = NULL;
#if 0
    gpkcs11_soft_token.logfile = fopen("/tmp/log-pkcs11.txt", "a");
#endif
    gpkcs11_soft_token.desc.text = description;
    ret = sscanf(version, "%c.%c",
		 &gpkcs11_soft_token.desc.libraryVersion.major,
		 &gpkcs11_soft_token.desc.libraryVersion.minor);
    if (ret != 2)
	return CKR_GENERAL_ERROR;

    return CKR_OK;
}

CK_RV
C_Finalize(CK_VOID_PTR args)
{
    int i;

    gpkcs11_log("Finalize\n");

    for (i = 0; i < MAX_NUM_SESSION; i++) {
	if (gpkcs11_soft_token.state[i].session_handle != CK_INVALID_HANDLE) {
	    gpkcs11_app_error("application finalized without "
			      "closing session\n");
	    close_session(&gpkcs11_soft_token.state[i]);
	}
    }

    return CKR_OK;
}

CK_RV
C_GetInfo(CK_INFO_PTR args)
{
    gpkcs11_log("GetInfo\n");

    memset(args, 17, sizeof(*args));
    args->cryptokiVersion.major = 2;
    args->cryptokiVersion.minor = 10;
    snprintf_fill((char *)args->manufacturerID, 
		  sizeof(args->manufacturerID),
		  ' ',
		  MANUFACTURER_ID);
    snprintf_fill((char *)args->libraryDescription, 
		  sizeof(args->libraryDescription), ' ',
		  gpkcs11_soft_token.desc.text);
    args->libraryVersion.major = gpkcs11_soft_token.desc.libraryVersion.major;
    args->libraryVersion.minor = gpkcs11_soft_token.desc.libraryVersion.minor;

    return CKR_OK;
}

extern CK_FUNCTION_LIST funcs;

CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    *ppFunctionList = &funcs;
    return CKR_OK;
}

CK_RV
C_GetSlotList(CK_BBOOL tokenPresent,
	      CK_SLOT_ID_PTR pSlotList,
	      CK_ULONG_PTR   pulCount)
{
    gpkcs11_log("GetSlotList: %s\n",
	    tokenPresent ? "tokenPresent" : "token not Present");
    if (pSlotList)
	pSlotList[0] = 1;
    *pulCount = 1;
    return CKR_OK;
}

CK_RV
C_GetSlotInfo(CK_SLOT_ID slotID,
	      CK_SLOT_INFO_PTR pInfo)
{
    gpkcs11_log("GetSlotInfo: slot: %d : %s\n", (int)slotID, has_session());

    memset(pInfo, 18, sizeof(*pInfo));

    if (slotID != 1)
	return CKR_ARGUMENTS_BAD;

    snprintf_fill((char *)pInfo->slotDescription, 
		  sizeof(pInfo->slotDescription),
		  ' ',
		  gpkcs11_soft_token.desc.text);
    snprintf_fill((char *)pInfo->manufacturerID,
		  sizeof(pInfo->manufacturerID),
		  ' ',
		  MANUFACTURER_ID);
    pInfo->flags = CKF_TOKEN_PRESENT;
    if (gpkcs11_soft_token.flags.hardware_slot)
	pInfo->flags |= CKF_HW_SLOT;
    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;
    
    return CKR_OK;
}

CK_RV
C_GetTokenInfo(CK_SLOT_ID slotID,
	       CK_TOKEN_INFO_PTR pInfo)
{
    gpkcs11_log("GetTokenInfo: %s\n", has_session()); 

    memset(pInfo, 19, sizeof(*pInfo));

    snprintf_fill((char *)pInfo->label, 
		  sizeof(pInfo->label),
		  ' ',
		  gpkcs11_soft_token.desc.text);
    snprintf_fill((char *)pInfo->manufacturerID, 
		  sizeof(pInfo->manufacturerID),
		  ' ',
		  MANUFACTURER_ID);
    snprintf_fill((char *)pInfo->model,
		  sizeof(pInfo->model),
		  ' ',
		  gpkcs11_soft_token.desc.text);
    snprintf_fill((char *)pInfo->serialNumber, 
		  sizeof(pInfo->serialNumber),
		  ' ',
		  "3942");
    pInfo->flags = 
	CKF_TOKEN_INITIALIZED | 
	CKF_USER_PIN_INITIALIZED;

    if (gpkcs11_soft_token.flags.login_done == 0)
	pInfo->flags |= CKF_LOGIN_REQUIRED;

    /* CFK_RNG |
       CKF_RESTORE_KEY_NOT_NEEDED |
    */
    pInfo->ulMaxSessionCount = MAX_NUM_SESSION;
    pInfo->ulSessionCount = gpkcs11_soft_token.open_sessions;
    pInfo->ulMaxRwSessionCount = MAX_NUM_SESSION;
    pInfo->ulRwSessionCount = gpkcs11_soft_token.open_sessions;
    pInfo->ulMaxPinLen = 1024;
    pInfo->ulMinPinLen = 0;
    pInfo->ulTotalPublicMemory = 4096;
    pInfo->ulFreePublicMemory = 4096;
    pInfo->ulTotalPrivateMemory = 4096;
    pInfo->ulFreePrivateMemory = 4096;
    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 0;

    return CKR_OK;
}

CK_RV
C_GetMechanismList(CK_SLOT_ID slotID,
		   CK_MECHANISM_TYPE_PTR pMechanismList,
		   CK_ULONG_PTR pulCount)
{
    gpkcs11_log("GetMechanismList\n");

    *pulCount = 2;
    if (pMechanismList == NULL_PTR)
	return CKR_OK;
    pMechanismList[0] = CKM_RSA_X_509;
    pMechanismList[1] = CKM_RSA_PKCS;

    return CKR_OK;
}

CK_RV
C_GetMechanismInfo(CK_SLOT_ID slotID,
		   CK_MECHANISM_TYPE type,
		   CK_MECHANISM_INFO_PTR pInfo)
{
    gpkcs11_log("GetMechanismInfo: slot %d type: %d\n",
	    (int)slotID, (int)type);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_InitToken(CK_SLOT_ID slotID,
	    CK_UTF8CHAR_PTR pPin,
	    CK_ULONG ulPinLen,
	    CK_UTF8CHAR_PTR pLabel)
{
    gpkcs11_log("InitToken: slot %d\n", (int)slotID);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_OpenSession(CK_SLOT_ID slotID,
	      CK_FLAGS flags,
	      CK_VOID_PTR pApplication,
	      CK_NOTIFY Notify,
	      CK_SESSION_HANDLE_PTR phSession)
{
    int i;

    gpkcs11_log("OpenSession: slot: %d\n", (int)slotID);
    
    if (gpkcs11_soft_token.open_sessions == MAX_NUM_SESSION)
	return CKR_SESSION_COUNT;

    gpkcs11_soft_token.application = pApplication;
    gpkcs11_soft_token.notify = Notify;

    for (i = 0; i < MAX_NUM_SESSION; i++)
	if (gpkcs11_soft_token.state[i].session_handle == CK_INVALID_HANDLE)
	    break;
    if (i == MAX_NUM_SESSION)
	abort();

    gpkcs11_soft_token.open_sessions++;

    gpkcs11_soft_token.state[i].session_handle =
	(CK_SESSION_HANDLE)(random() & 0xfffff);
    *phSession = gpkcs11_soft_token.state[i].session_handle;

    return CKR_OK;
}

CK_RV
C_CloseSession(CK_SESSION_HANDLE hSession)
{
    struct gpkcs11_session_state *state;
    gpkcs11_log("CloseSession\n");

    if (gpkcs11_verify_session_handle(hSession, &state) != CKR_OK)
	gpkcs11_app_error("closed session not open");
    else
	close_session(state);

    return CKR_OK;
}

CK_RV
C_CloseAllSessions(CK_SLOT_ID slotID)
{
    int i;

    gpkcs11_log("CloseAllSessions\n");

    for (i = 0; i < MAX_NUM_SESSION; i++)
	if (gpkcs11_soft_token.state[i].session_handle != CK_INVALID_HANDLE)
	    close_session(&gpkcs11_soft_token.state[i]);

    return CKR_OK;
}

CK_RV
C_GetSessionInfo(CK_SESSION_HANDLE hSession,
		 CK_SESSION_INFO_PTR pInfo)
{
    gpkcs11_log("GetSessionInfo\n");
    
    VERIFY_SESSION_HANDLE(hSession, NULL);

    memset(pInfo, 20, sizeof(*pInfo));

    pInfo->slotID = 1;
    if (gpkcs11_soft_token.flags.login_done)
	pInfo->state = CKS_RO_USER_FUNCTIONS;
    else
	pInfo->state = CKS_RO_PUBLIC_SESSION;
    pInfo->flags = CKF_SERIAL_SESSION;
    pInfo->ulDeviceError = 0;

    return CKR_OK;
}

CK_RV
C_Logout(CK_SESSION_HANDLE hSession)
{
    gpkcs11_log("Logout\n");
    VERIFY_SESSION_HANDLE(hSession, NULL);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_GetObjectSize(CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		CK_ULONG_PTR pulSize)
{
    gpkcs11_log("GetObjectSize\n");
    VERIFY_SESSION_HANDLE(hSession, NULL);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_GetAttributeValue(CK_SESSION_HANDLE hSession,
		    CK_OBJECT_HANDLE hObject,
		    CK_ATTRIBUTE_PTR pTemplate,
		    CK_ULONG ulCount)
{
    struct gpkcs11_session_state *state;
    struct gpkcs11_st_object *obj;
    CK_ULONG i;
    CK_RV ret;
    int j;

    gpkcs11_log("GetAttributeValue: %lx\n",
	    (unsigned long)HANDLE_OBJECT_ID(hObject));
    VERIFY_SESSION_HANDLE(hSession, &state);

    if ((ret = object_handle_to_object(hObject, &obj)) != CKR_OK) {
	gpkcs11_log("object not found: %lx\n",
		(unsigned long)HANDLE_OBJECT_ID(hObject));
	return ret;
    }

    for (i = 0; i < ulCount; i++) {
	gpkcs11_log("	getting 0x%08lx\n", (unsigned long)pTemplate[i].type);
	for (j = 0; j < obj->num_attributes; j++) {
	    if (obj->attrs[j].secret) {
		pTemplate[i].ulValueLen = (CK_ULONG)-1;
		break;
	    }
	    if (pTemplate[i].type == obj->attrs[j].attribute.type) {
		if (pTemplate[i].pValue != NULL_PTR && obj->attrs[j].secret == 0) {
		    if (pTemplate[i].ulValueLen >= obj->attrs[j].attribute.ulValueLen)
			memcpy(pTemplate[i].pValue, obj->attrs[j].attribute.pValue,
			       obj->attrs[j].attribute.ulValueLen);
		}
		pTemplate[i].ulValueLen = obj->attrs[j].attribute.ulValueLen;
		break;
	    }
	}
	if (j == obj->num_attributes) {
	    gpkcs11_log("key type: 0x%08lx not found\n", (unsigned long)pTemplate[i].type);
	    pTemplate[i].ulValueLen = (CK_ULONG)-1;
	}

    }
    return CKR_OK;
}

CK_RV
C_FindObjectsInit(CK_SESSION_HANDLE hSession,
		  CK_ATTRIBUTE_PTR pTemplate,
		  CK_ULONG ulCount)
{
    struct gpkcs11_session_state *state;

    gpkcs11_log("FindObjectsInit\n");

    VERIFY_SESSION_HANDLE(hSession, &state);

    if (state->find.next_object != -1) {
	gpkcs11_app_error("application didn't do C_FindObjectsFinal\n");
	find_object_final(state);
    }
    if (ulCount) {
	CK_ULONG i;

	print_attributes(pTemplate, ulCount);

	state->find.attributes = 
	    calloc(1, ulCount * sizeof(state->find.attributes[0]));
	if (state->find.attributes == NULL)
	    return CKR_DEVICE_MEMORY;
	for (i = 0; i < ulCount; i++) {
	    state->find.attributes[i].pValue = 
		malloc(pTemplate[i].ulValueLen);
	    if (state->find.attributes[i].pValue == NULL) {
		find_object_final(state);
		return CKR_DEVICE_MEMORY;
	    }
	    memcpy(state->find.attributes[i].pValue,
		   pTemplate[i].pValue, pTemplate[i].ulValueLen);
	    state->find.attributes[i].type = pTemplate[i].type;
	    state->find.attributes[i].ulValueLen = pTemplate[i].ulValueLen;
	}
	state->find.num_attributes = ulCount;
	state->find.next_object = 0;
    } else {
	gpkcs11_log("find all objects\n");
	state->find.attributes = NULL;
	state->find.num_attributes = 0;
	state->find.next_object = 0;
    }

    return CKR_OK;
}

CK_RV
C_FindObjects(CK_SESSION_HANDLE hSession,
	      CK_OBJECT_HANDLE_PTR phObject,
	      CK_ULONG ulMaxObjectCount,
	      CK_ULONG_PTR pulObjectCount)
{
    struct gpkcs11_session_state *state;
    int i;

    gpkcs11_log("FindObjects\n");

    VERIFY_SESSION_HANDLE(hSession, &state);

    if (state->find.next_object == -1) {
	gpkcs11_app_error("application didn't do C_FindObjectsInit\n");
	return CKR_ARGUMENTS_BAD;
    }
    if (ulMaxObjectCount == 0) {
	gpkcs11_app_error("application asked for 0 objects\n");
	return CKR_ARGUMENTS_BAD;
    }
    *pulObjectCount = 0;
    for (i = state->find.next_object; i < gpkcs11_soft_token.object.num_objs; i++) {
	gpkcs11_log("FindObjects: %d\n", i);
	state->find.next_object = i + 1;
	if (attributes_match(gpkcs11_soft_token.object.objs[i],
			     state->find.attributes,
			     state->find.num_attributes)) {
	    *phObject++ = gpkcs11_soft_token.object.objs[i]->object_handle;
	    ulMaxObjectCount--;
	    (*pulObjectCount)++;
	    if (ulMaxObjectCount == 0)
		break;
	}
    }
    return CKR_OK;
}

CK_RV
C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    struct gpkcs11_session_state *state;

    gpkcs11_log("FindObjectsFinal\n");
    VERIFY_SESSION_HANDLE(hSession, &state);
    find_object_final(state);
    return CKR_OK;
}

static CK_RV
commonInit(CK_ATTRIBUTE *attr_match, int attr_match_len,
	   const CK_MECHANISM_TYPE *mechs, int mechs_len,
	   const CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey,
	   struct gpkcs11_st_object **o)
{
    CK_RV ret;
    int i;

    *o = NULL;
    if ((ret = object_handle_to_object(hKey, o)) != CKR_OK)
	return ret;

    ret = attributes_match(*o, attr_match, attr_match_len);
    if (!ret) {
	gpkcs11_app_error("called commonInit on key that doesn't "
			  "support required attr");
	return CKR_ARGUMENTS_BAD;
    }

    for (i = 0; i < mechs_len; i++)
	if (mechs[i] == pMechanism->mechanism)
	    break;
    if (i == mechs_len) {
	gpkcs11_app_error("called mech (%08lx) not supported\n",
			  pMechanism->mechanism);
	return CKR_ARGUMENTS_BAD;
    }
    return CKR_OK;
}


static CK_RV
dup_mechanism(CK_MECHANISM_PTR *dup, const CK_MECHANISM_PTR pMechanism)
{
    CK_MECHANISM_PTR p;

    p = malloc(sizeof(*p));
    if (p == NULL)
	return CKR_DEVICE_MEMORY;

    if (*dup)
	free(*dup);
    *dup = p;
    memcpy(p, pMechanism, sizeof(*p));

    return CKR_OK;
}


CK_RV
C_EncryptInit(CK_SESSION_HANDLE hSession,
	      CK_MECHANISM_PTR pMechanism,
	      CK_OBJECT_HANDLE hKey)
{
    struct gpkcs11_session_state *state;
    CK_MECHANISM_TYPE mechs[] = { CKM_RSA_PKCS, CKM_RSA_X_509 };
    CK_BBOOL bool_true = CK_TRUE;
    CK_ATTRIBUTE attr[] = {
	{ CKA_ENCRYPT, &bool_true, sizeof(bool_true) }
    };
    struct gpkcs11_st_object *o;
    CK_RV ret;

    gpkcs11_log("EncryptInit\n");
    VERIFY_SESSION_HANDLE(hSession, &state);
    
    ret = commonInit(attr, sizeof(attr)/sizeof(attr[0]), 
		     mechs, sizeof(mechs)/sizeof(mechs[0]),
		     pMechanism, hKey, &o);
    if (ret)
	return ret;

    ret = dup_mechanism(&state->encrypt_mechanism, pMechanism);
    if (ret == CKR_OK) 
	state->encrypt_object = OBJECT_ID(o);
			
    return ret;
}

CK_RV
C_Encrypt(CK_SESSION_HANDLE hSession,
	  CK_BYTE_PTR pData,
	  CK_ULONG ulDataLen,
	  CK_BYTE_PTR pEncryptedData,
	  CK_ULONG_PTR pulEncryptedDataLen)
{
    struct gpkcs11_session_state *state;
    struct gpkcs11_st_object *o;
    void *buffer = NULL;
    CK_RV ret;
    RSA *rsa;
    int padding, len, buffer_len, padding_len;

    gpkcs11_log("Encrypt\n");

    VERIFY_SESSION_HANDLE(hSession, &state);

    if (state->encrypt_object == -1)
	return CKR_ARGUMENTS_BAD;

    o = gpkcs11_soft_token.object.objs[state->encrypt_object];

    if (o->u.public_key == NULL) {
	gpkcs11_log("public key NULL\n");
	return CKR_ARGUMENTS_BAD;
    }

    rsa = o->u.public_key->pkey.rsa;

    if (rsa == NULL)
	return CKR_ARGUMENTS_BAD;

    RSA_blinding_off(rsa); /* XXX RAND is broken while running in mozilla ? */

    buffer_len = RSA_size(rsa);

    buffer = malloc(buffer_len);
    if (buffer == NULL) {
	ret = CKR_DEVICE_MEMORY;
	goto out;
    }

    ret = CKR_OK;
    switch(state->encrypt_mechanism->mechanism) {
    case CKM_RSA_PKCS:
	padding = RSA_PKCS1_PADDING;
	padding_len = RSA_PKCS1_PADDING_SIZE;
	break;
    case CKM_RSA_X_509:
	padding = RSA_NO_PADDING;
	padding_len = 0;
	break;
    default:
	ret = CKR_FUNCTION_NOT_SUPPORTED;
	goto out;
    }

    if (buffer_len + padding_len < ulDataLen) {
	ret = CKR_ARGUMENTS_BAD;
	goto out;
    }

    if (pulEncryptedDataLen == NULL) {
	gpkcs11_log("pulEncryptedDataLen NULL\n");
	ret = CKR_ARGUMENTS_BAD;
	goto out;
    }

    if (pData == NULL_PTR) {
	gpkcs11_log("data NULL\n");
	ret = CKR_ARGUMENTS_BAD;
	goto out;
    }

    len = RSA_public_encrypt(ulDataLen, pData, buffer, rsa, padding);
    if (len <= 0) {
	ret = CKR_DEVICE_ERROR;
	goto out;
    }
    if (len > buffer_len)
	abort();
	
    if (pEncryptedData != NULL_PTR)
	memcpy(pEncryptedData, buffer, len);
    *pulEncryptedDataLen = len;

 out:
    if (buffer) {
	memset(buffer, 0, buffer_len);
	free(buffer);
    }
    return ret;
}

CK_RV
C_EncryptUpdate(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,
		CK_ULONG ulPartLen,
		CK_BYTE_PTR pEncryptedPart,
		CK_ULONG_PTR pulEncryptedPartLen)
{
    gpkcs11_log("EncryptUpdate\n");
    VERIFY_SESSION_HANDLE(hSession, NULL);
    return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV
C_EncryptFinal(CK_SESSION_HANDLE hSession,
	       CK_BYTE_PTR pLastEncryptedPart,
	       CK_ULONG_PTR pulLastEncryptedPartLen)
{
    gpkcs11_log("EncryptFinal\n");
    VERIFY_SESSION_HANDLE(hSession, NULL);
    return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_DecryptInit initializes a decryption operation. */
CK_RV
C_DecryptInit(CK_SESSION_HANDLE hSession,
	      CK_MECHANISM_PTR pMechanism,
	      CK_OBJECT_HANDLE hKey)
{
    struct gpkcs11_session_state *state;
    CK_MECHANISM_TYPE mechs[] = { CKM_RSA_PKCS, CKM_RSA_X_509 };
    CK_BBOOL bool_true = CK_TRUE;
    CK_ATTRIBUTE attr[] = {
	{ CKA_DECRYPT, &bool_true, sizeof(bool_true) }
    };
    struct gpkcs11_st_object *o;
    CK_RV ret;

    gpkcs11_log("DecryptInit\n");
    VERIFY_SESSION_HANDLE(hSession, &state);
    
    ret = commonInit(attr, sizeof(attr)/sizeof(attr[0]), 
		     mechs, sizeof(mechs)/sizeof(mechs[0]),
		     pMechanism, hKey, &o);
    if (ret)
	return ret;

    ret = dup_mechanism(&state->decrypt_mechanism, pMechanism);
    if (ret == CKR_OK) 
	state->decrypt_object = OBJECT_ID(o);

    return CKR_OK;
}


CK_RV
C_Decrypt(CK_SESSION_HANDLE hSession,
	  CK_BYTE_PTR       pEncryptedData,
	  CK_ULONG          ulEncryptedDataLen,
	  CK_BYTE_PTR       pData,
	  CK_ULONG_PTR      pulDataLen)
{
    struct gpkcs11_session_state *state;
    struct gpkcs11_st_object *o;
    void *buffer = NULL;
    CK_RV ret;
    RSA *rsa;
    int padding, len, buffer_len, padding_len;

    gpkcs11_log("Decrypt\n");

    VERIFY_SESSION_HANDLE(hSession, &state);

    if (state->decrypt_object == -1)
	return CKR_ARGUMENTS_BAD;

    o = gpkcs11_soft_token.object.objs[state->decrypt_object];

    if (o->u.private_key.key == NULL) {
	gpkcs11_log("private key NULL\n");
	return CKR_ARGUMENTS_BAD;
    }

    rsa = o->u.private_key.key->pkey.rsa;

    if (rsa == NULL)
	return CKR_ARGUMENTS_BAD;

    RSA_blinding_off(rsa); /* XXX RAND is broken while running in mozilla ? */

    buffer_len = RSA_size(rsa);

    buffer = malloc(buffer_len);
    if (buffer == NULL) {
	ret = CKR_DEVICE_MEMORY;
	goto out;
    }

    ret = CKR_OK;
    switch(state->decrypt_mechanism->mechanism) {
    case CKM_RSA_PKCS:
	padding = RSA_PKCS1_PADDING;
	padding_len = RSA_PKCS1_PADDING_SIZE;
	break;
    case CKM_RSA_X_509:
	padding = RSA_NO_PADDING;
	padding_len = 0;
	break;
    default:
	ret = CKR_FUNCTION_NOT_SUPPORTED;
	goto out;
    }

    if (buffer_len + padding_len < ulEncryptedDataLen) {
	ret = CKR_ARGUMENTS_BAD;
	goto out;
    }

    if (pulDataLen == NULL) {
	gpkcs11_log("pulDataLen NULL\n");
	ret = CKR_ARGUMENTS_BAD;
	goto out;
    }

    if (pEncryptedData == NULL_PTR) {
	gpkcs11_log("data NULL\n");
	ret = CKR_ARGUMENTS_BAD;
	goto out;
    }

    len = RSA_private_decrypt(ulEncryptedDataLen, pEncryptedData, buffer, 
			      rsa, padding);
    if (len <= 0) {
	ret = CKR_DEVICE_ERROR;
	goto out;
    }
    if (len > buffer_len)
	abort();
	
    if (pData != NULL_PTR)
	memcpy(pData, buffer, len);
    *pulDataLen = len;

 out:
    if (buffer) {
	memset(buffer, 0, buffer_len);
	free(buffer);
    }
    return ret;
}


CK_RV
C_DecryptUpdate(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pEncryptedPart,
		CK_ULONG ulEncryptedPartLen,
		CK_BYTE_PTR pPart,
		CK_ULONG_PTR pulPartLen)

{
    gpkcs11_log("DecryptUpdate\n");
    VERIFY_SESSION_HANDLE(hSession, NULL);
    return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV
C_DecryptFinal(CK_SESSION_HANDLE hSession,
	       CK_BYTE_PTR pLastPart,
	       CK_ULONG_PTR pulLastPartLen)
{
    gpkcs11_log("DecryptFinal\n");
    VERIFY_SESSION_HANDLE(hSession, NULL);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_DigestInit(CK_SESSION_HANDLE hSession,
	     CK_MECHANISM_PTR pMechanism)
{
    gpkcs11_log("DigestInit\n");
    VERIFY_SESSION_HANDLE(hSession, NULL);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_SignInit(CK_SESSION_HANDLE hSession,
	   CK_MECHANISM_PTR pMechanism,
	   CK_OBJECT_HANDLE hKey)
{
    struct gpkcs11_session_state *state;
    CK_MECHANISM_TYPE mechs[] = { CKM_RSA_PKCS, CKM_RSA_X_509 };
    CK_BBOOL bool_true = CK_TRUE;
    CK_ATTRIBUTE attr[] = {
	{ CKA_SIGN, &bool_true, sizeof(bool_true) }
    };
    struct gpkcs11_st_object *o;
    CK_RV ret;

    gpkcs11_log("SignInit\n");
    VERIFY_SESSION_HANDLE(hSession, &state);
    
    ret = commonInit(attr, sizeof(attr)/sizeof(attr[0]), 
		     mechs, sizeof(mechs)/sizeof(mechs[0]),
		     pMechanism, hKey, &o);
    if (ret)
	return ret;

    ret = dup_mechanism(&state->sign_mechanism, pMechanism);
    if (ret == CKR_OK) 
	state->sign_object = OBJECT_ID(o);

    return CKR_OK;
}

CK_RV
C_Sign(CK_SESSION_HANDLE hSession,
       CK_BYTE_PTR pData,
       CK_ULONG ulDataLen,
       CK_BYTE_PTR pSignature,
       CK_ULONG_PTR pulSignatureLen)
{
    struct gpkcs11_session_state *state;
    struct gpkcs11_st_object *o;
    void *buffer = NULL;
    CK_RV ret;
    RSA *rsa;
    int padding, len, buffer_len, padding_len;

    gpkcs11_log("Sign\n");
    VERIFY_SESSION_HANDLE(hSession, &state);

    if (state->sign_object == -1)
	return CKR_ARGUMENTS_BAD;

    o = gpkcs11_soft_token.object.objs[state->sign_object];

    if (o->u.private_key.key == NULL) {
	gpkcs11_log("private key NULL\n");
	return CKR_ARGUMENTS_BAD;
    }

    rsa = o->u.private_key.key->pkey.rsa;

    if (rsa == NULL)
	return CKR_ARGUMENTS_BAD;

    RSA_blinding_off(rsa); /* XXX RAND is broken while running in mozilla ? */

    buffer_len = RSA_size(rsa);

    buffer = malloc(buffer_len);
    if (buffer == NULL) {
	ret = CKR_DEVICE_MEMORY;
	goto out;
    }

    switch(state->sign_mechanism->mechanism) {
    case CKM_RSA_PKCS:
	padding = RSA_PKCS1_PADDING;
	padding_len = RSA_PKCS1_PADDING_SIZE;
	break;
    case CKM_RSA_X_509:
	padding = RSA_NO_PADDING;
	padding_len = 0;
	break;
    default:
	ret = CKR_FUNCTION_NOT_SUPPORTED;
	goto out;
    }

    if (buffer_len < ulDataLen + padding_len) {
	ret = CKR_ARGUMENTS_BAD;
	goto out;
    }

    if (pulSignatureLen == NULL) {
	gpkcs11_log("signature len NULL\n");
	ret = CKR_ARGUMENTS_BAD;
	goto out;
    }

    if (pData == NULL_PTR) {
	gpkcs11_log("data NULL\n");
	ret = CKR_ARGUMENTS_BAD;
	goto out;
    }

    len = RSA_private_encrypt(ulDataLen, pData, buffer, rsa, padding);
    gpkcs11_log("private encrypt done\n");
    if (len <= 0) {
	ret = CKR_DEVICE_ERROR;
	goto out;
    }
    if (len > buffer_len)
	abort();
	
    if (pSignature != NULL_PTR)
	memcpy(pSignature, buffer, len);
    *pulSignatureLen = len;

    ret = CKR_OK;

 out:
    if (buffer) {
	memset(buffer, 0, buffer_len);
	free(buffer);
    }
    return ret;
}

CK_RV
C_SignUpdate(CK_SESSION_HANDLE hSession,
	     CK_BYTE_PTR pPart,
	     CK_ULONG ulPartLen)
{
    gpkcs11_log("SignUpdate\n");
    VERIFY_SESSION_HANDLE(hSession, NULL);
    return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV
C_SignFinal(CK_SESSION_HANDLE hSession,
	    CK_BYTE_PTR pSignature,
	    CK_ULONG_PTR pulSignatureLen)
{
    gpkcs11_log("SignUpdate\n");
    VERIFY_SESSION_HANDLE(hSession, NULL);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_VerifyInit(CK_SESSION_HANDLE hSession,
	     CK_MECHANISM_PTR pMechanism,
	     CK_OBJECT_HANDLE hKey)
{
    struct gpkcs11_session_state *state;
    CK_MECHANISM_TYPE mechs[] = { CKM_RSA_PKCS, CKM_RSA_X_509 };
    CK_BBOOL bool_true = CK_TRUE;
    CK_ATTRIBUTE attr[] = {
	{ CKA_VERIFY, &bool_true, sizeof(bool_true) }
    };
    struct gpkcs11_st_object *o;
    CK_RV ret;

    gpkcs11_log("VerifyInit\n");
    VERIFY_SESSION_HANDLE(hSession, &state);
    
    ret = commonInit(attr, sizeof(attr)/sizeof(attr[0]), 
		     mechs, sizeof(mechs)/sizeof(mechs[0]),
		     pMechanism, hKey, &o);
    if (ret)
	return ret;

    ret = dup_mechanism(&state->verify_mechanism, pMechanism);
    if (ret == CKR_OK) 
	state->verify_object = OBJECT_ID(o);
			
    return ret;
}

CK_RV
C_Verify(CK_SESSION_HANDLE hSession,
	 CK_BYTE_PTR pData,
	 CK_ULONG ulDataLen,
	 CK_BYTE_PTR pSignature,
	 CK_ULONG ulSignatureLen)
{
    struct gpkcs11_session_state *state;
    struct gpkcs11_st_object *o;
    void *buffer = NULL;
    CK_RV ret;
    RSA *rsa;
    int padding, len, buffer_len;

    gpkcs11_log("Verify\n");
    VERIFY_SESSION_HANDLE(hSession, &state);

    if (state->verify_object == -1)
	return CKR_ARGUMENTS_BAD;

    o = gpkcs11_soft_token.object.objs[state->verify_object];

    if (o->u.public_key == NULL) {
	gpkcs11_log("public key NULL\n");
	return CKR_ARGUMENTS_BAD;
    }

    rsa = o->u.public_key->pkey.rsa;

    if (rsa == NULL)
	return CKR_ARGUMENTS_BAD;

    RSA_blinding_off(rsa); /* XXX RAND is broken while running in mozilla ? */

    buffer_len = RSA_size(rsa);

    buffer = malloc(buffer_len);
    if (buffer == NULL) {
	ret = CKR_DEVICE_MEMORY;
	goto out;
    }

    ret = CKR_OK;
    switch(state->verify_mechanism->mechanism) {
    case CKM_RSA_PKCS:
	padding = RSA_PKCS1_PADDING;
	break;
    case CKM_RSA_X_509:
	padding = RSA_NO_PADDING;
	break;
    default:
	ret = CKR_FUNCTION_NOT_SUPPORTED;
	goto out;
    }

    if (buffer_len < ulDataLen) {
	ret = CKR_ARGUMENTS_BAD;
	goto out;
    }

    if (pSignature == NULL) {
	gpkcs11_log("signature NULL\n");
	ret = CKR_ARGUMENTS_BAD;
	goto out;
    }

    if (pData == NULL_PTR) {
	gpkcs11_log("data NULL\n");
	ret = CKR_ARGUMENTS_BAD;
	goto out;
    }

    len = RSA_public_decrypt(ulDataLen, pData, buffer, rsa, padding);
    gpkcs11_log("private encrypt done\n");
    if (len <= 0) {
	ret = CKR_DEVICE_ERROR;
	goto out;
    }
    if (len > buffer_len)
	abort();
	
    if (len != ulSignatureLen) {
	ret = CKR_GENERAL_ERROR;
	goto out;
    }
	
    if (memcmp(pSignature, buffer, len) != 0) {
	ret = CKR_GENERAL_ERROR;
	goto out;
    }

 out:
    if (buffer) {
	memset(buffer, 0, buffer_len);
	free(buffer);
    }
    return ret;
}


CK_RV
C_VerifyUpdate(CK_SESSION_HANDLE hSession,
	       CK_BYTE_PTR pPart,
	       CK_ULONG ulPartLen)
{
    gpkcs11_log("VerifyUpdate\n");
    VERIFY_SESSION_HANDLE(hSession, NULL);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_VerifyFinal(CK_SESSION_HANDLE hSession,
	      CK_BYTE_PTR pSignature,
	      CK_ULONG ulSignatureLen)
{
    gpkcs11_log("VerifyFinal\n");
    VERIFY_SESSION_HANDLE(hSession, NULL);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
C_GenerateRandom(CK_SESSION_HANDLE hSession,
		 CK_BYTE_PTR RandomData,
		 CK_ULONG ulRandomLen)
{
    gpkcs11_log("GenerateRandom\n");
    VERIFY_SESSION_HANDLE(hSession, NULL);
    return CKR_FUNCTION_NOT_SUPPORTED;
}
