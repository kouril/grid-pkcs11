INCLUDES = -I$(srcdir)/ref
LDFLAGS = -module
LIBS = -lcrypto

lib_LTLIBRARIES = \
	igtf-pkcs11.la \
	proxy-pkcs11.la

if HAVE_MYPROXY
lib_LTLIBRARIES += myproxy-pkcs11.la
endif

COMMON_PKCS11_SOURCES =			\
	log.c				\
	objects.c			\
	pkcs11_main.c

igtf_pkcs11_la_SOURCES =		\
	$(COMMON_PKCS11_SOURCES)	\
	igtf-pkcs11.c

proxy_pkcs11_la_SOURCES =		\
	$(COMMON_PKCS11_SOURCES)	\
	proxy-pkcs11.c

myproxy_pkcs11_la_SOURCES =		\
	$(COMMON_PKCS11_SOURCES)	\
	myproxy-pkcs11.c

#check_PROGRAMS = test_pkcs11
#test_pkcs11_SOURCES = test_soft_pkcs11.c
#test_pkcs11_LDADD = proxy-pkcs11.la
