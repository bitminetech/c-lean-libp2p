#ifndef LIBP2P_CPPCHECK_MISRA_EXTERNAL_API_H
#define LIBP2P_CPPCHECK_MISRA_EXTERNAL_API_H

#include <stddef.h>
#include <stdint.h>

#ifndef MBSTRING_ASC
#define MBSTRING_ASC 0x1001
#endif

#ifndef X509_VERSION_3
#define X509_VERSION_3 2
#endif

#ifndef EXFLAG_INVALID
#define EXFLAG_INVALID 0x80U
#endif

#ifndef EVP_PKEY_EC
#define EVP_PKEY_EC 408
#endif

#ifndef OPENSSL_NPN_NEGOTIATED
#define OPENSSL_NPN_NEGOTIATED 1
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef F_GETFL
#define F_GETFL 3
#endif

#ifndef F_SETFL
#define F_SETFL 4
#endif

#ifndef O_NONBLOCK
#define O_NONBLOCK 04000
#endif

typedef unsigned int socklen_t;
struct sockaddr;
struct stack_st_CRYPTO_BUFFER;

typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_object_st ASN1_OBJECT;
typedef struct asn1_string_st ASN1_OCTET_STRING;
typedef struct asn1_string_st ASN1_STRING;
typedef struct asn1_time_st ASN1_TIME;
typedef struct crypto_buffer_st CRYPTO_BUFFER;
typedef struct ec_key_st EC_KEY;
typedef struct env_md_st EVP_MD;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct X509_extension_st X509_EXTENSION;
typedef struct X509_name_st X509_NAME;
typedef struct x509_st X509;

int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, const unsigned char *data, int len);
int ASN1_INTEGER_set_uint64(ASN1_INTEGER *out, uint64_t value);
int ASN1_STRING_length(const ASN1_STRING *str);
int ASN1_TIME_to_posix(const ASN1_TIME *time, int64_t *out);
const uint8_t *CRYPTO_BUFFER_data(const CRYPTO_BUFFER *buf);
size_t CRYPTO_BUFFER_len(const CRYPTO_BUFFER *buf);
int EC_KEY_generate_key(EC_KEY *key);
const EVP_MD *EVP_sha256(void);
int EVP_PKEY_assign_EC_KEY(EVP_PKEY *key, EC_KEY *ec_key);
int OBJ_cmp(const ASN1_OBJECT *a, const ASN1_OBJECT *b);
int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, size_t der_len, const uint8_t *der);
int SSL_CTX_check_private_key(const SSL_CTX *ctx);
int SSL_CTX_use_PrivateKey_ASN1(int type, SSL_CTX *ctx, const uint8_t *der, size_t der_len);
int SSL_set_alpn_protos(SSL *ssl, const uint8_t *protos, size_t protos_len);
const ASN1_TIME *X509_get0_notAfter(const X509 *cert);
const ASN1_TIME *X509_get0_notBefore(const X509 *cert);
uint32_t X509_get_extension_flags(X509 *x509);
X509_NAME *X509_get_issuer_name(const X509 *cert);
ASN1_INTEGER *X509_get_serialNumber(X509 *cert);
X509_NAME *X509_get_subject_name(const X509 *cert);
int X509_NAME_add_entry_by_txt(
    X509_NAME *name,
    const char *field,
    int type,
    const unsigned char *bytes,
    long len,
    int loc,
    int set);
int X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b);
int X509_add_ext(X509 *cert, const X509_EXTENSION *extension, int loc);
int X509_set_version(X509 *cert, long version);
int X509_set1_notAfter(X509 *cert, const ASN1_TIME *time);
int X509_set1_notBefore(X509 *cert, const ASN1_TIME *time);
int X509_set_issuer_name(X509 *cert, X509_NAME *name);
int X509_set_pubkey(X509 *cert, EVP_PKEY *key);
int X509_set_subject_name(X509 *cert, X509_NAME *name);
int X509_sign(X509 *cert, EVP_PKEY *key, const EVP_MD *md);
int X509_verify(X509 *cert, EVP_PKEY *key);
int i2d_PrivateKey(const EVP_PKEY *key, uint8_t **out);
int i2d_PUBKEY(const EVP_PKEY *key, uint8_t **out);
int i2d_X509(X509 *cert, uint8_t **out);
size_t sk_CRYPTO_BUFFER_num(const struct stack_st_CRYPTO_BUFFER *sk);

int bind(int socket_fd, const struct sockaddr *addr, socklen_t addr_len);
int fcntl(int fd, int command, ...);
int getsockname(int socket_fd, struct sockaddr *addr, socklen_t *addr_len);

#endif /* LIBP2P_CPPCHECK_MISRA_EXTERNAL_API_H */
