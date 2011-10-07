#include "gpkcs11_locl.h"

extern gpkcs11_soft_token_t gpkcs11_soft_token;

CK_RV
gpkcs11_verify_session_handle(CK_SESSION_HANDLE hSession,
			      gpkcs11_session_state **state)
{
    int i;

    for (i = 0; i < MAX_NUM_SESSION; i++) {
	if (gpkcs11_soft_token.state[i].session_handle == hSession)
	    break;
    }
    if (i == MAX_NUM_SESSION) {
	gpkcs11_app_error("use of invalid handle: 0x%08lx\n",
			  (unsigned long)hSession);
	return CKR_SESSION_HANDLE_INVALID;
    }
    if (state)
	*state = &gpkcs11_soft_token.state[i];
    return CKR_OK;
}



static struct gpkcs11_st_object *
add_st_object(void)
{
    struct gpkcs11_st_object *o, **objs;
    int i;

    o = malloc(sizeof(*o));
    if (o == NULL)
	return NULL;
    memset(o, 0, sizeof(*o));
    o->attrs = NULL;
    o->num_attributes = 0;
    
    for (i = 0; i < gpkcs11_soft_token.object.num_objs; i++) {
	if (gpkcs11_soft_token.object.objs == NULL) {
	    gpkcs11_soft_token.object.objs[i] = o;
	    break;
	}
    }
    if (i == gpkcs11_soft_token.object.num_objs) {
	objs = realloc(gpkcs11_soft_token.object.objs,
		       (gpkcs11_soft_token.object.num_objs + 1) * sizeof(gpkcs11_soft_token.object.objs[0]));
	if (objs == NULL) {
	    free(o);
	    return NULL;
	}
	gpkcs11_soft_token.object.objs = objs;
	gpkcs11_soft_token.object.objs[gpkcs11_soft_token.object.num_objs++] = o;
    }	
    gpkcs11_soft_token.object.objs[i]->object_handle =
	(random() & (~OBJECT_ID_MASK)) | i;

    return o;
}

static CK_RV
add_object_attribute(struct gpkcs11_st_object *o, 
		     int secret,
		     CK_ATTRIBUTE_TYPE type,
		     CK_VOID_PTR pValue,
		     CK_ULONG ulValueLen)
{
    struct gpkcs11_st_attr *a;
    int i;

    i = o->num_attributes;
    a = realloc(o->attrs, (i + 1) * sizeof(o->attrs[0]));
    if (a == NULL)
	return CKR_DEVICE_MEMORY;
    o->attrs = a;
    o->attrs[i].secret = secret;
    o->attrs[i].attribute.type = type;
    o->attrs[i].attribute.pValue = malloc(ulValueLen);
    if (o->attrs[i].attribute.pValue == NULL && ulValueLen != 0)
	return CKR_DEVICE_MEMORY;
    memcpy(o->attrs[i].attribute.pValue, pValue, ulValueLen);
    o->attrs[i].attribute.ulValueLen = ulValueLen;
    o->num_attributes++;

    return CKR_OK;
}

static CK_RV
add_pubkey_info(struct gpkcs11_st_object *o, CK_KEY_TYPE key_type, EVP_PKEY *key)
{
    switch (key_type) {
    case CKK_RSA: {
	CK_BYTE *modulus = NULL;
	size_t modulus_len = 0;
	CK_ULONG modulus_bits = 0;
	CK_BYTE *exponent = NULL;
	size_t exponent_len = 0;

	modulus_bits = BN_num_bits(key->pkey.rsa->n);

	modulus_len = BN_num_bytes(key->pkey.rsa->n);
	modulus = malloc(modulus_len);
	BN_bn2bin(key->pkey.rsa->n, modulus);
	
	exponent_len = BN_num_bytes(key->pkey.rsa->e);
	exponent = malloc(exponent_len);
	BN_bn2bin(key->pkey.rsa->e, exponent);
	
	add_object_attribute(o, 0, CKA_MODULUS, modulus, modulus_len);
	add_object_attribute(o, 0, CKA_MODULUS_BITS,
			     &modulus_bits, sizeof(modulus_bits));
	add_object_attribute(o, 0, CKA_PUBLIC_EXPONENT,
			     exponent, exponent_len);

	RSA_set_method(key->pkey.rsa, RSA_PKCS1_SSLeay());

	free(modulus);
	free(exponent);
    }
    default:
	/* XXX */
	break;
    }
    return CKR_OK;
}


static int
pem_callback(char *buf, int num, int w, void *key)
{
    return -1;
}

CK_RV
gpkcs11_add_certificate(char *label,
			X509 *cert,
			char *id,
			int anchor)
{
    struct gpkcs11_st_object *o = NULL;
    void *cert_data = NULL;
    size_t cert_length;
    void *subject_data = NULL;
    size_t subject_length;
    void *issuer_data = NULL;
    size_t issuer_length;
    void *serial_data = NULL;
    size_t serial_length;
    EVP_PKEY *public_key;
    unsigned char sha1[SHA_DIGEST_LENGTH];
    CK_TRUST trust_ca = CKT_NSS_TRUSTED_DELEGATOR;
    int ret;
    CK_BBOOL bool_true = CK_TRUE;
    CK_BBOOL bool_false = CK_FALSE;
    CK_OBJECT_CLASS c;
    CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
    CK_KEY_TYPE key_type;
    CK_MECHANISM_TYPE mech_type;
    size_t id_len = strlen(id);

    OPENSSL_ASN1_MALLOC_ENCODE(X509, cert_data, cert_length, cert, ret);
    if (ret)
	goto out;

    OPENSSL_ASN1_MALLOC_ENCODE(X509_NAME, issuer_data, issuer_length, 
			       X509_get_issuer_name(cert), ret);
    if (ret)
	goto out;

    OPENSSL_ASN1_MALLOC_ENCODE(X509_NAME, subject_data, subject_length, 
			       X509_get_subject_name(cert), ret);
    if (ret)
	goto out;

    OPENSSL_ASN1_MALLOC_ENCODE(ASN1_INTEGER, serial_data, serial_length, 
			       X509_get_serialNumber(cert), ret);
    if (ret)
	goto out;

    gpkcs11_log("done parsing, adding to internal structure\n");

    o = add_st_object();
    if (o == NULL) {
	ret = CKR_DEVICE_MEMORY;
	goto out;
    }
    o->type = STO_T_CERTIFICATE;
    o->u.cert = cert;
    public_key = X509_get_pubkey(o->u.cert);

    switch (EVP_PKEY_type(public_key->type)) {
    case EVP_PKEY_RSA:
	key_type = CKK_RSA;
	break;
    case EVP_PKEY_DSA:
	key_type = CKK_DSA;
	break;
    default:
	/* XXX */
	break;
    }

    c = CKO_CERTIFICATE;
    add_object_attribute(o, 0, CKA_CLASS, &c, sizeof(c));
    add_object_attribute(o, 0, CKA_TOKEN, &bool_true, sizeof(bool_true));
    add_object_attribute(o, 0, CKA_PRIVATE, &bool_false, sizeof(bool_false));
    add_object_attribute(o, 0, CKA_MODIFIABLE, &bool_false, sizeof(bool_false));
    add_object_attribute(o, 0, CKA_LABEL, label, strlen(label));

    add_object_attribute(o, 0, CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type));
    add_object_attribute(o, 0, CKA_ID, id, id_len);

    add_object_attribute(o, 0, CKA_SUBJECT, subject_data, subject_length);
    add_object_attribute(o, 0, CKA_ISSUER, issuer_data, issuer_length);
    add_object_attribute(o, 0, CKA_SERIAL_NUMBER, serial_data, serial_length);
    add_object_attribute(o, 0, CKA_VALUE, cert_data, cert_length);
    if (anchor)
	add_object_attribute(o, 0, CKA_TRUSTED, &bool_true, sizeof(bool_true));
    else
	add_object_attribute(o, 0, CKA_TRUSTED, &bool_false, sizeof(bool_false));

    gpkcs11_log("add cert ok: %lx\n", (unsigned long)OBJECT_ID(o));

    if (anchor) {
	o = add_st_object();
	if (o == NULL) {
	    ret = CKR_DEVICE_MEMORY;
	    goto out;
	}

	o->type = STO_T_NETSCAPE_TRUST;

	c = CKO_NETSCAPE_TRUST;
	add_object_attribute(o, 0, CKA_CLASS, &c, sizeof(c));
	add_object_attribute(o, 0, CKA_LABEL, "IGTF CA Trust", 13);
	add_object_attribute(o, 0, CKA_ID, id, id_len);
	add_object_attribute(o, 0, CKA_TOKEN, &bool_true, sizeof(bool_true));
	add_object_attribute(o, 0, CKA_ISSUER, issuer_data, issuer_length);
	add_object_attribute(o, 0, CKA_SUBJECT, subject_data, subject_length);
	add_object_attribute(o, 0, CKA_SERIAL_NUMBER, serial_data, serial_length);
	EVP_Digest(cert_data, cert_length, sha1, NULL, EVP_sha1(), NULL);
	add_object_attribute(o, 0, CKA_CERT_SHA1_HASH, sha1, sizeof(sha1));
	add_object_attribute(o, 0, CKA_TRUST_SERVER_AUTH, &trust_ca, sizeof(trust_ca));
	add_object_attribute(o, 0, CKA_TRUST_CLIENT_AUTH, &trust_ca, sizeof(trust_ca));
	add_object_attribute(o, 0, CKA_TRUST_CODE_SIGNING, &trust_ca, sizeof(trust_ca));
	add_object_attribute(o, 0, CKA_TRUST_EMAIL_PROTECTION, &trust_ca, sizeof(trust_ca));
	gpkcs11_log("add Netscape trust object: %lx\n", (unsigned long)OBJECT_ID(o));
    }

    o = add_st_object();
    if (o == NULL) {
	ret = CKR_DEVICE_MEMORY;
	goto out;
    }
    o->type = STO_T_PUBLIC_KEY;
    o->u.public_key = public_key;

    c = CKO_PUBLIC_KEY;
    add_object_attribute(o, 0, CKA_CLASS, &c, sizeof(c));
    add_object_attribute(o, 0, CKA_TOKEN, &bool_true, sizeof(bool_true));
    add_object_attribute(o, 0, CKA_PRIVATE, &bool_false, sizeof(bool_false));
    add_object_attribute(o, 0, CKA_MODIFIABLE, &bool_false, sizeof(bool_false));
    add_object_attribute(o, 0, CKA_LABEL, label, strlen(label));

    add_object_attribute(o, 0, CKA_KEY_TYPE, &key_type, sizeof(key_type));
    add_object_attribute(o, 0, CKA_ID, id, id_len);
    add_object_attribute(o, 0, CKA_START_DATE, "", 1); /* XXX */
    add_object_attribute(o, 0, CKA_END_DATE, "", 1); /* XXX */
    add_object_attribute(o, 0, CKA_DERIVE, &bool_false, sizeof(bool_false));
    add_object_attribute(o, 0, CKA_LOCAL, &bool_false, sizeof(bool_false));
    mech_type = CKM_RSA_X_509;
    add_object_attribute(o, 0, CKA_KEY_GEN_MECHANISM, &mech_type, sizeof(mech_type));

    add_object_attribute(o, 0, CKA_SUBJECT, subject_data, subject_length);
    add_object_attribute(o, 0, CKA_ENCRYPT, &bool_true, sizeof(bool_true));
    add_object_attribute(o, 0, CKA_VERIFY, &bool_true, sizeof(bool_true));
    add_object_attribute(o, 0, CKA_VERIFY_RECOVER, &bool_false, sizeof(bool_false));
    add_object_attribute(o, 0, CKA_WRAP, &bool_true, sizeof(bool_true));
    add_object_attribute(o, 0, CKA_TRUSTED, &bool_true, sizeof(bool_true));

    add_pubkey_info(o, key_type, public_key);

    gpkcs11_log("add key ok: %lx\n", (unsigned long)OBJECT_ID(o));

    ret = CKR_OK;

out:
    free(cert_data);
    free(serial_data);
    free(issuer_data);
    free(subject_data);

    return ret;
}

CK_RV
gpkcs11_add_credentials(char *label,
			const char *cert_file,
			const char *private_key_file,
			char *id,
			int anchor)
{
    struct gpkcs11_st_object *o = NULL;
    CK_BBOOL bool_true = CK_TRUE;
    CK_BBOOL bool_false = CK_FALSE;
    CK_OBJECT_CLASS c;
    CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
    CK_KEY_TYPE key_type;
    CK_MECHANISM_TYPE mech_type;
    CK_RV ret = CKR_GENERAL_ERROR;
    void *subject_data = NULL;
    size_t subject_length;
    X509 *cert, *proxy_cert = NULL;
    EVP_PKEY *public_key;
    FILE *f = NULL;
    size_t id_len = strlen(id);

    f = fopen(cert_file, "r");
    if (f == NULL) {
	gpkcs11_log("failed to open file %s\n", cert_file);
	return CKR_GENERAL_ERROR;
    }

    while (1) {
	cert = PEM_read_X509(f, NULL, NULL, NULL);
	if (cert == NULL) {
	    if (ERR_GET_REASON(ERR_peek_error()) == PEM_R_NO_START_LINE)
		break;
	    ret = CKR_GENERAL_ERROR;
	    goto out;
	}
	if (proxy_cert == NULL)
	    proxy_cert = cert;
	ret = gpkcs11_add_certificate(label, cert, id, anchor);
	if (ret)
	    goto out;
    }

    public_key = X509_get_pubkey(proxy_cert);
    switch (EVP_PKEY_type(public_key->type)) {
    case EVP_PKEY_RSA:
	key_type = CKK_RSA;
	break;
    case EVP_PKEY_DSA:
	key_type = CKK_DSA;
	break;
    default:
	/* XXX */
	break;
    }

    OPENSSL_ASN1_MALLOC_ENCODE(X509_NAME, subject_data, subject_length, 
			       X509_get_subject_name(proxy_cert), ret);
    if (ret)
	goto out;


    if (private_key_file) {
	CK_FLAGS flags;
	FILE *f;

	o = add_st_object();
	if (o == NULL) {
	    ret = CKR_DEVICE_MEMORY;
	    goto out;
	}
	o->type = STO_T_PRIVATE_KEY;
	o->u.private_key.file = strdup(private_key_file);
	o->u.private_key.key = NULL;

	o->u.private_key.cert = proxy_cert;

	c = CKO_PRIVATE_KEY;
	add_object_attribute(o, 0, CKA_CLASS, &c, sizeof(c));
	add_object_attribute(o, 0, CKA_TOKEN, &bool_true, sizeof(bool_true));
	add_object_attribute(o, 0, CKA_PRIVATE, &bool_true, sizeof(bool_false));
	add_object_attribute(o, 0, CKA_MODIFIABLE, &bool_false, sizeof(bool_false));
	add_object_attribute(o, 0, CKA_LABEL, label, strlen(label));

	add_object_attribute(o, 0, CKA_KEY_TYPE, &key_type, sizeof(key_type));
	add_object_attribute(o, 0, CKA_ID, id, id_len);
	add_object_attribute(o, 0, CKA_START_DATE, "", 1); /* XXX */
	add_object_attribute(o, 0, CKA_END_DATE, "", 1); /* XXX */
	add_object_attribute(o, 0, CKA_DERIVE, &bool_false, sizeof(bool_false));
	add_object_attribute(o, 0, CKA_LOCAL, &bool_false, sizeof(bool_false));
	mech_type = CKM_RSA_X_509;
	add_object_attribute(o, 0, CKA_KEY_GEN_MECHANISM, &mech_type, sizeof(mech_type));

	add_object_attribute(o, 0, CKA_SUBJECT, subject_data, subject_length);
	add_object_attribute(o, 0, CKA_SENSITIVE, &bool_true, sizeof(bool_true));
	add_object_attribute(o, 0, CKA_SECONDARY_AUTH, &bool_false, sizeof(bool_true));
	flags = 0;
	add_object_attribute(o, 0, CKA_AUTH_PIN_FLAGS, &flags, sizeof(flags));

	add_object_attribute(o, 0, CKA_DECRYPT, &bool_true, sizeof(bool_true));
	add_object_attribute(o, 0, CKA_SIGN, &bool_true, sizeof(bool_true));
	add_object_attribute(o, 0, CKA_SIGN_RECOVER, &bool_false, sizeof(bool_false));
	add_object_attribute(o, 0, CKA_UNWRAP, &bool_true, sizeof(bool_true));
	add_object_attribute(o, 0, CKA_EXTRACTABLE, &bool_true, sizeof(bool_true));
	add_object_attribute(o, 0, CKA_NEVER_EXTRACTABLE, &bool_false, sizeof(bool_false));

	add_pubkey_info(o, key_type, public_key);

	f = fopen(private_key_file, "r");
	if (f == NULL) {
	    gpkcs11_log("failed to open private key\n");
	    return CKR_GENERAL_ERROR;
	}

	o->u.private_key.key = PEM_read_PrivateKey(f, NULL, pem_callback, NULL);
	fclose(f);
	if (o->u.private_key.key == NULL) {
	    gpkcs11_log("failed to read private key a startup\n");
	    /* don't bother with this failure for now, 
	       fix it at C_Login time */;
	} else {
	    /* XXX verify keytype */

	    if (key_type == CKK_RSA)
		RSA_set_method(o->u.private_key.key->pkey.rsa, 
			       RSA_PKCS1_SSLeay());

	    if (X509_check_private_key(proxy_cert, o->u.private_key.key) != 1) {
		EVP_PKEY_free(o->u.private_key.key);	    
		o->u.private_key.key = NULL;
		gpkcs11_log("private key doesn't verify\n");
	    } else {
		gpkcs11_log("private key usable\n");
		gpkcs11_soft_token.flags.login_done = 1;
	    }
	}
    }

    ret = CKR_OK;
 out:
    if (ret != CKR_OK) {
	gpkcs11_log("something went wrong when adding cert!\n");

	/* XXX wack o */;
    }

    if (f)
	fclose(f);

    return ret;
}
