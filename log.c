#include "gpkcs11_locl.h"

extern gpkcs11_soft_token_t gpkcs11_soft_token;

void
gpkcs11_vlog(const char *fmt, va_list ap)
{
    if (gpkcs11_soft_token.logfile == NULL)
	return;
    vfprintf(gpkcs11_soft_token.logfile, fmt, ap);
    fflush(gpkcs11_soft_token.logfile);
}

void
gpkcs11_log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    gpkcs11_vlog(fmt, ap);
    va_end(ap);
}

void
gpkcs11_app_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    gpkcs11_vlog(fmt, ap);
    va_end(ap);
    if (gpkcs11_soft_token.flags.app_error_fatal)
	abort();
}
