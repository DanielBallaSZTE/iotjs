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

#include "iotjs_def.h"
#include "iotjs_js.h"
#include "stdarg.h"
#include "../deps/mbedtls/include/mbedtls/ssl.h"
#include "../deps/mbedtls/include/mbedtls/net.h"
#include "../deps/mbedtls/include/mbedtls/entropy.h"
#include "../deps/mbedtls/include/mbedtls/ctr_drbg.h"
#include "../deps/mbedtls/include/mbedtls/net_sockets.h"
#include "../deps/mbedtls/include/mbedtls/certs.h"
#include "../deps/mbedtls/include/mbedtls/ctr_drbg.h"


JS_FUNCTION(Tls) {
  jerry_value_t ret = jerry_create_string((const jerry_char_t*)"Successfully created tls");
  return ret;
}

typedef struct TlsStruct {
  mbedtls_net_context server_fd;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt cacert;
} TlsStruct;

static TlsStruct* initMbedTls() {
  TlsStruct* ret = (TlsStruct*)iotjs_buffer_allocate(sizeof(TlsStruct));

  mbedtls_net_init( &ret->server_fd );
  
  mbedtls_ssl_init( &ret->ssl );
  mbedtls_ssl_config_init( &ret->conf );
  mbedtls_x509_crt_init( &ret->cacert );
  mbedtls_ctr_drbg_init( &ret->ctr_drbg );
  mbedtls_entropy_init( &ret->entropy );

  return ret;
}

static void freeMbedTls(TlsStruct* tls) {
  mbedtls_net_free( &tls->server_fd );
  mbedtls_x509_crt_free( &tls->cacert );
  mbedtls_ssl_free( &tls->ssl );
  mbedtls_ssl_config_free( &tls->conf );
  mbedtls_ctr_drbg_free( &tls->ctr_drbg );
  mbedtls_entropy_free( &tls->entropy );

  iotjs_buffer_release((char*)tls);
}

static jerry_value_t createErrorMessage(const char* format, ...) {
  va_list args;
  va_start(args, format);
  char buff[256];
  uint16_t err_len = vsprintf(buff, format, args);

  return jerry_create_string_sz((const jerry_char_t*) buff, err_len);

}

/*
JS_FUNCTION(Write) {
  DJS_CHECK_ARGS(1, string);
  iotjs_string_t str = JS_GET_ARG(0, string);

  unsigned char buf_orig[] = "GET /tls_test.js HTTP/1.1\r\nHost: localhost\r\n\r\n";
  unsigned char buf[1024];
  int len = sprintf((char *) buf, (char *) buf_orig);
  int ret = 0;
  while ((ret = mbedtls_ssl_write(&tls_data->ssl, buf, (size_t) len)) <= 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      return createErrorMessage("write error, error code: %d", ret);
    }
  }
}*/

JS_FUNCTION(Connect) {
  DJS_CHECK_ARGS(3, string, string, string);
  iotjs_string_t port = JS_GET_ARG(0, string);
  iotjs_string_t host = JS_GET_ARG(1, string);
  iotjs_string_t hostname = JS_GET_ARG(2, string);

  TlsStruct *tls_data = initMbedTls();


  const char *pers = "ssl_client1";
  int ret = 0;
  if ((ret = mbedtls_ctr_drbg_seed(&tls_data->ctr_drbg, mbedtls_entropy_func, &tls_data->entropy,
                                   (const unsigned char *) pers,
                                   strlen( pers ) ) ) != 0 )
  {
    return createErrorMessage("drbg seeding failed, error code: %d", ret);
  }

  ret = mbedtls_net_connect(&tls_data->server_fd, (const char*)iotjs_string_data(&host), (const char *)iotjs_string_data(&port), MBEDTLS_NET_PROTO_TCP);
  if (ret) {
    return createErrorMessage("failed to connect to %s:%s, error code: %d", iotjs_string_data(&host), iotjs_string_data(&port), ret);
  }

  ret = mbedtls_ssl_config_defaults(&tls_data->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret) {
    return createErrorMessage("ssl config failed, error code: %d", ret);
  }

  mbedtls_ssl_conf_authmode( &tls_data->conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
  mbedtls_ssl_conf_ca_chain( &tls_data->conf, &tls_data->cacert, NULL );
  mbedtls_ssl_conf_rng( &tls_data->conf, mbedtls_ctr_drbg_random, &tls_data->ctr_drbg );

  ret = mbedtls_ssl_setup(&tls_data->ssl, &tls_data->conf);

  if (ret) {
    return createErrorMessage("ssl setup failed, error code: %d", ret);
  }

  ret = mbedtls_ssl_set_hostname(&tls_data->ssl, iotjs_string_data(&hostname));
  if (ret) {
    return createErrorMessage("ssl hostname setup failed, error code: %d", ret);
  }

  mbedtls_ssl_set_bio( &tls_data->ssl, &tls_data->server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

  while ((ret = mbedtls_ssl_handshake(&tls_data->ssl))) {
      if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        return createErrorMessage("handshake failed, error code: -0x%x", -ret);
      }
  }

  freeMbedTls(tls_data);
  return jerry_create_boolean(true);
 }

jerry_value_t InitTls() {
  jerry_value_t tls_obj = jerry_create_external_function(Tls);

  iotjs_jval_set_method(tls_obj, IOTJS_MAGIC_STRING_TLSCONNECT, Connect);

  return tls_obj;
}
