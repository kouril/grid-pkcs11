#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/sha.h>

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <dirent.h>

#include <pkcs11u.h>
#include <pkcs11.h>
#include <pkcs11n.h>

#ifdef HAVE_MYPROXY
#include <myproxy.h>
#include <gsi_socket.h>
#endif

#define MANUFACTURER_ID "CESNET"

#define OPENSSL_ASN1_MALLOC_ENCODE(T, B, BL, S, R)	\
{											\
  unsigned char *p;							\
  (BL) = i2d_##T((S), NULL);				\
  if ((BL) <= 0) {							\
     (R) = EINVAL;							\
  } else {									\
    (B) = malloc((BL));						\
    if ((B) == NULL) {						\
       (R) = ENOMEM;						\
    } else {								\
        p = (B);							\
        (R) = 0;							\
        (BL) = i2d_##T((S), &p);			\
        if ((BL) <= 0) {					\
           free((B));						\
           (R) = EINVAL;					\
        }									\
    }										\
  }											\
}

#define OBJECT_ID_MASK		0xfff
#define HANDLE_OBJECT_ID(h)	((h) & OBJECT_ID_MASK)
#define OBJECT_ID(obj)		HANDLE_OBJECT_ID((obj)->object_handle)

#define MAX_NUM_SESSION	10

typedef struct gpkcs11_st_attr {
	CK_ATTRIBUTE attribute;
	int secret;
} gpkcs11_st_attr;

typedef struct gpkcs11_session_state {
	CK_SESSION_HANDLE session_handle;

	struct {
		CK_ATTRIBUTE *attributes;
		CK_ULONG num_attributes;
		int next_object;
	} find;

	int encrypt_object;
	CK_MECHANISM_PTR encrypt_mechanism;
	int decrypt_object;
	CK_MECHANISM_PTR decrypt_mechanism;
	int sign_object;
	CK_MECHANISM_PTR sign_mechanism;
	int verify_object;
	CK_MECHANISM_PTR verify_mechanism;
	int digest_object;
} gpkcs11_session_state;

typedef struct gpkcs11_st_object {
	CK_OBJECT_HANDLE object_handle;
	gpkcs11_st_attr *attrs;
	int num_attributes;
	enum {
		STO_T_CERTIFICATE,
		STO_T_PRIVATE_KEY,
		STO_T_PUBLIC_KEY,
		STO_T_NETSCAPE_TRUST
	} type;
	union {
		X509 *cert;
		EVP_PKEY *public_key;
		struct {
			const char *file;
			EVP_PKEY *key;
			X509 *cert;
		} private_key;
	} u;
} gpkcs11_st_object;

typedef struct gpkcs11_soft_token_t {
	struct {
		const char *text;
		CK_VERSION libraryVersion;
	} desc;
	CK_VOID_PTR application;
	CK_NOTIFY notify;
	struct {
		gpkcs11_st_object **objs;
		int num_objs;
	} object;
	struct {
		int hardware_slot;
		int app_error_fatal;
		int login_done;
	} flags;
	int open_sessions;
	gpkcs11_session_state state[MAX_NUM_SESSION];
	FILE *logfile;
	char *myproxy_server;
	char *myproxy_user;
} gpkcs11_soft_token_t;

void
gpkcs11_log(const char *fmt, ...);

void
gpkcs11_app_error(const char *fmt, ...);

CK_RV
gpkcs11_verify_session_handle(CK_SESSION_HANDLE hSession, gpkcs11_session_state **state);

#define VERIFY_SESSION_HANDLE(s, state)	\
{													\
    CK_RV ret;										\
    ret = gpkcs11_verify_session_handle(s, state);	\
    if (ret != CKR_OK) {							\
        return(ret);								\
    }												\
}

CK_RV
gpkcs11_init_token(const char *version, const char *description, gpkcs11_soft_token_t *token);

CK_RV
gpkcs11_add_credentials(char *label, const char *cert_file, const char *private_key_file, char *id, int anchor);

CK_RV
get_myproxy_creds(char *server, char *username, char *password, char **creds);
