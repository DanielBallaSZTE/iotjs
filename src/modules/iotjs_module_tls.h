/* Copyright 2018-present Samsung Electronics Co., Ltd. and other contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef IOTJS_MODULE_TLS_H
#define IOTJS_MODULE_TLS_H

#include "iotjs_def.h"
#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/net.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

const char SSL_CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4GA1UECxMX\n"
    "R2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMT\n"
    "Ckdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1MDgwMDAwWjBMMSAwHgYDVQQL\n"
    "ExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE\n"
    "AxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8o\n"
    "mUVCxKs+IVSbC9N/hHD6ErPLv4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7\n"
    "SqbKSaZeqKeMWhG8eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQ\n"
    "BoZfXklqtTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzd\n"
    "C9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pazq+r1feq\n"
    "CapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCBmTAOBgNVHQ8BAf8E\n"
    "BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IHV2ccHsBqBt5ZtJot39wZhi4w\n"
    "NgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxzaWduLm5ldC9yb290LXIyLmNy\n"
    "bDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEA\n"
    "mYFThxxol4aR7OBKuEQLq4GsJ0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkI\n"
    "k7mpM0sYmsL4h4hO291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRD\n"
    "LenVOavSot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxd\n"
    "AfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7TBj0/VLZ\n"
    "jmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==\n"
    "-----END CERTIFICATE-----\n";
enum {
  SSL_HANDSHAKE_READY = 0,
  SSL_HANDSHAKE_IN_PROGRESS = 1,
  SSL_HANDSHAKE_DONE = 2,
};

enum { /* ssl Constants */
       SSL_ERROR_NONE = 0,
       SSL_FAILURE = 0,
       SSL_SUCCESS = 1,
       SSL_SHUTDOWN_NOT_DONE = 2,

       SSL_ALPN_NOT_FOUND = -9,
       SSL_BAD_CERTTYPE = -8,
       SSL_BAD_STAT = -7,
       SSL_BAD_PATH = -6,
       SSL_BAD_FILETYPE = -5,
       SSL_BAD_FILE = -4,
       SSL_NOT_IMPLEMENTED = -3,
       SSL_UNKNOWN = -2,
       SSL_FATAL_ERROR = -1,

       SSL_FILETYPE_ASN1 = 2,
       SSL_FILETYPE_PEM = 1,
       SSL_FILETYPE_DEFAULT = 2, /* ASN1 */
       SSL_FILETYPE_RAW = 3,     /* NTRU raw key blob */

       SSL_VERIFY_NONE = 0,
       SSL_VERIFY_PEER = 1,
       SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2,
       SSL_VERIFY_CLIENT_ONCE = 4,
       SSL_VERIFY_FAIL_EXCEPT_PSK = 8,

       SSL_SESS_CACHE_OFF = 0x0000,
       SSL_SESS_CACHE_CLIENT = 0x0001,
       SSL_SESS_CACHE_SERVER = 0x0002,
       SSL_SESS_CACHE_BOTH = 0x0003,
       SSL_SESS_CACHE_NO_AUTO_CLEAR = 0x0008,
       SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 0x0100,
       SSL_SESS_CACHE_NO_INTERNAL_STORE = 0x0200,
       SSL_SESS_CACHE_NO_INTERNAL = 0x0300,

       SSL_ERROR_WANT_READ = 2,
       SSL_ERROR_WANT_WRITE = 3,
       SSL_ERROR_WANT_CONNECT = 7,
       SSL_ERROR_WANT_ACCEPT = 8,
       SSL_ERROR_SYSCALL = 5,
       SSL_ERROR_WANT_X509_LOOKUP = 83,
       SSL_ERROR_ZERO_RETURN = 6,
       SSL_ERROR_SSL = 85,

       SSL_SENT_SHUTDOWN = 1,
       SSL_RECEIVED_SHUTDOWN = 2,
       SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 4,
       SSL_OP_NO_SSLv2 = 8,

       SSL_R_SSL_HANDSHAKE_FAILURE = 101,
       SSL_R_TLSV1_ALERT_UNKNOWN_CA = 102,
       SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN = 103,
       SSL_R_SSLV3_ALERT_BAD_CERTIFICATE = 104,
       PEM_BUFSIZE = 1024
};

struct _BIO;
typedef struct _BIO BIO;

struct _BIO {
  BIO *prev;
  BIO *next;
  BIO *pair;
  unsigned char *mem;
  int write_sz;
  int write_idx;
  int read_idx;
  int read_rq;
  int mem_len;
  int type;
};

enum {
  SSL_BIO_ERROR = -1,
  SSL_BIO_UNSET = -2,
  SSL_BIO_SIZE = 17000,
};

enum BIO_TYPE {
  BIO_BUFFER = 1,
  BIO_SOCKET = 2,
  BIO_SSL = 3,
  BIO_MEMORY = 4,
  BIO_BIO = 5,
  BIO_FILE = 6
};

BIO *iotjs_ssl_bio_new(int type);
int iotjs_bio_make_bio_pair(BIO *b1, BIO *b2);

size_t iotjs_bio_ctrl_pending(BIO *bio);
int iotjs_bio_read(BIO *bio, const char *buf, size_t size);
int iotjs_bio_write(BIO *bio, const char *buf, size_t size);

int iotjs_bio_reset(BIO *bio);
int iotjs_bio_net_recv(void *ctx, unsigned char *buf, size_t len);
int iotjs_bio_net_send(void *ctx, const unsigned char *buf, size_t len);
int iotjs_bio_free_all(BIO *bio);
int iotjs_bio_free(BIO *bio);

typedef struct iotjs_tls_t {
  jerry_value_t jobject;

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt cacert;
  int handshake_state;

  BIO *ssl_bio;
  BIO *app_bio;
} iotjs_tls_t;

#endif /* IOTJS_MODULE_TLS_H */
