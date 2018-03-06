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

#include "iotjs_module_tls.h"
#include "iotjs_module_buffer.h"

#include "stdarg.h"


IOTJS_DEFINE_NATIVE_HANDLE_INFO_THIS_MODULE(tls);

static void iotjs_tls_destroy(iotjs_tls_t *tls_data) {
  mbedtls_x509_crt_free(&tls_data->cacert);
  mbedtls_ssl_free(&tls_data->ssl);
  mbedtls_ssl_config_free(&tls_data->conf);
  mbedtls_ctr_drbg_free(&tls_data->ctr_drbg);
  mbedtls_entropy_free(&tls_data->entropy);

  IOTJS_RELEASE(tls_data);
}

static iotjs_tls_t *iotjs_tls_create(const jerry_value_t jobject) {
  iotjs_tls_t *tls_data = IOTJS_ALLOC(iotjs_tls_t);

  tls_data->jobject = jobject;
  jerry_set_object_native_pointer(jobject, tls_data, &this_module_native_info);

  mbedtls_ssl_init(&tls_data->ssl);
  mbedtls_ssl_config_init(&tls_data->conf);
  mbedtls_x509_crt_init(&tls_data->cacert);
  mbedtls_ctr_drbg_init(&tls_data->ctr_drbg);
  mbedtls_entropy_init(&tls_data->entropy);

  return tls_data;
}

/* Return the number of pending bytes in read and write buffers */
size_t iotjs_bio_ctrl_pending(BIO *bio) {
  if (bio == NULL) {
    return 0;
  }

  if (bio->type == BIO_MEMORY) {
    return (size_t)bio->mem_len;
  }

  /* type BIO_BIO then check paired buffer */
  if (bio->type == BIO_BIO && bio->pair != NULL) {
    BIO *pair = bio->pair;

    if (pair->write_idx > 0 && pair->write_idx <= pair->read_idx) {
      /* in wrap around state where begining of buffer is being
       * overwritten */
      return (size_t)(pair->write_sz - pair->read_idx + pair->write_idx);
    } else {
      /* simple case where has not wrapped around */
      return (size_t)(pair->write_idx - pair->read_idx);
    }
  }
  return 0;
}

int iotjs_bio_set_write_buf_size(BIO *bio, long size) {
  if (bio == NULL || bio->type != BIO_BIO || size < 0) {
    return SSL_FAILURE;
  }

  /* if already in pair then do not change size */
  if (bio->pair != NULL) {
    return SSL_FAILURE;
  }

  bio->write_sz = (int)size;
  if (bio->write_sz < 0) {
    return SSL_FAILURE;
  }

  if (bio->mem != NULL) {
    iotjs_buffer_release((char *)bio->mem);
  }

  bio->mem = (unsigned char *)iotjs_buffer_allocate((size_t)bio->write_sz);
  if (bio->mem == NULL) {
    return SSL_FAILURE;
  }
  bio->write_idx = 0;
  bio->read_idx = 0;

  return SSL_SUCCESS;
}


/* Joins two BIO_BIO types. The write of b1 goes to the read of b2 and vise
 * versa. Creating something similar to a two way pipe.
 * Reading and writing between the two BIOs is not thread safe, they are
 * expected to be used by the same thread. */
int iotjs_bio_make_bio_pair(BIO *b1, BIO *b2) {
  if (b1 == NULL || b2 == NULL) {
    return SSL_FAILURE;
  }

  /* both are expected to be of type BIO and not already paired */
  if (b1->type != BIO_BIO || b2->type != BIO_BIO || b1->pair != NULL ||
      b2->pair != NULL) {
    return SSL_FAILURE;
  }

  /* set default write size if not already set */
  if (b1->mem == NULL &&
      iotjs_bio_set_write_buf_size(b1, SSL_BIO_SIZE) != SSL_SUCCESS) {
    return SSL_FAILURE;
  }

  if (b2->mem == NULL &&
      iotjs_bio_set_write_buf_size(b2, SSL_BIO_SIZE) != SSL_SUCCESS) {
    return SSL_FAILURE;
  }

  b1->pair = b2;
  b2->pair = b1;

  return SSL_SUCCESS;
}


/* Does not advance read index pointer */
int iotjs_bio_nread0(BIO *bio, char **buf) {
  if (bio == NULL || buf == NULL) {
    return 0;
  }

  /* if paired read from pair */
  if (bio->pair != NULL) {
    BIO *pair = bio->pair;

    /* case where have wrapped around write buffer */
    *buf = (char *)pair->mem + pair->read_idx;
    if (pair->write_idx > 0 && pair->read_idx >= pair->write_idx) {
      return pair->write_sz - pair->read_idx;
    } else {
      return pair->write_idx - pair->read_idx;
    }
  }
  return 0;
}


/* similar to SSL_BIO_nread0 but advances the read index */
int iotjs_bio_nread(BIO *bio, char **buf, size_t num) {
  int sz = SSL_BIO_UNSET;

  if (bio == NULL || buf == NULL) {
    return SSL_FAILURE;
  }

  if (bio->pair != NULL) {
    /* special case if asking to read 0 bytes */
    if (num == 0) {
      *buf = (char *)bio->pair->mem + bio->pair->read_idx;
      return 0;
    }

    /* get amount able to read and set buffer pointer */
    sz = iotjs_bio_nread0(bio, buf);
    if (sz == 0) {
      return SSL_BIO_ERROR;
    }

    if ((int)num < sz) {
      sz = (int)num;
    }
    bio->pair->read_idx += sz;

    /* check if have read to the end of the buffer and need to reset */
    if (bio->pair->read_idx == bio->pair->write_sz) {
      bio->pair->read_idx = 0;
      if (bio->pair->write_idx == bio->pair->write_sz) {
        bio->pair->write_idx = 0;
      }
    }

    /* check if read up to write index, if so then reset indexs */
    if (bio->pair->read_idx == bio->pair->write_idx) {
      bio->pair->read_idx = 0;
      bio->pair->write_idx = 0;
    }
  }

  return sz;
}


int iotjs_bio_nwrite(BIO *bio, char **buf, int num) {
  int sz = SSL_BIO_UNSET;

  if (bio == NULL || buf == NULL) {
    return 0;
  }

  if (bio->pair != NULL) {
    if (num == 0) {
      *buf = (char *)bio->mem + bio->write_idx;
      return 0;
    }

    if (bio->write_idx < bio->read_idx) {
      /* if wrapped around only write up to read index. In this case
       * read_idx is always greater then write_idx so sz will not be negative.
       */
      sz = bio->read_idx - bio->write_idx;
    } else if (bio->read_idx > 0 && bio->write_idx == bio->read_idx) {
      return SSL_BIO_ERROR; /* no more room to write */
    } else {
      /* write index is past read index so write to end of buffer */
      sz = bio->write_sz - bio->write_idx;

      if (sz <= 0) {
        /* either an error has occured with write index or it is at the
         * end of the write buffer. */
        if (bio->read_idx == 0) {
          /* no more room, nothing has been read */
          return SSL_BIO_ERROR;
        }

        bio->write_idx = 0;

        /* check case where read index is not at 0 */
        if (bio->read_idx > 0) {
          sz = bio->read_idx; /* can write up to the read index */
        } else {
          sz = bio->write_sz; /* no restriction other then buffer size */
        }
      }
    }

    if (num < sz) {
      sz = num;
    }
    *buf = (char *)bio->mem + bio->write_idx;
    bio->write_idx += sz;

    /* if at the end of the buffer and space for wrap around then set
     * write index back to 0 */
    if (bio->write_idx == bio->write_sz && bio->read_idx > 0) {
      bio->write_idx = 0;
    }
  }

  return sz;
}


/* Reset BIO to initial state */
int iotjs_bio_reset(BIO *bio) {
  if (bio == NULL) {
    /* -1 is consistent failure even for FILE type */
    return SSL_BIO_ERROR;
  }

  switch (bio->type) {
    case BIO_BIO:
      bio->read_idx = 0;
      bio->write_idx = 0;
      return 0;

    default: { break; }
  }

  return SSL_BIO_ERROR;
}


int iotjs_bio_read(BIO *bio, const char *buf, size_t size) {
  int sz;
  char *pt;
  sz = iotjs_bio_nread(bio, &pt, size);

  if (sz > 0) {
    memset((void *)buf, 0, (size_t)sz);
    memcpy((void *)buf, pt, (size_t)sz);
  }

  return sz;
}

int iotjs_bio_write(BIO *bio, const char *buf, size_t size) {
  /* internal function where arguments have already been sanity checked */
  int sz;
  char *data;

  sz = iotjs_bio_nwrite(bio, &data, size);

  /* test space for write */
  if (sz <= 0) {
    return sz;
  }

  memset(data, 0, (size_t)sz);
  memcpy(data, buf, (size_t)sz);
  return sz;
}


/**
 * support bio type only
 *e
 * @param type
 * @return
 */
BIO *iotjs_ssl_bio_new(int type) {
  BIO *bio = (BIO *)iotjs_buffer_allocate(sizeof(BIO));
  if (bio) {
    bzero(bio, sizeof(BIO));
    bio->type = type;
    bio->mem = NULL;
    bio->prev = NULL;
    bio->next = NULL;
  }
  return bio;
}

int iotjs_bio_free(BIO *bio) {
  /* unchain?, doesn't matter in goahead since from free all */
  if (bio) {
    /* remove from pair by setting the paired bios pair to NULL */
    if (bio->pair != NULL) {
      bio->pair->pair = NULL;
    }
    if (bio->mem)
      iotjs_buffer_release((char *)bio->mem);
    iotjs_buffer_release((char *)bio);
  }
  return 0;
}

int iotjs_bio_free_all(BIO *bio) {
  while (bio) {
    BIO *next = bio->next;
    iotjs_bio_free(bio);
    bio = next;
  }
  return 0;
}

int iotjs_bio_net_send(void *ctx, const unsigned char *buf, size_t len) {
  BIO *bio = (BIO *)ctx;

  int sz;
  sz = iotjs_bio_write(bio, (const char *)buf, len);
  if (sz <= 0) {
    return MBEDTLS_ERR_SSL_WANT_WRITE;
  }
  return sz;
}

int iotjs_bio_net_recv(void *ctx, unsigned char *buf, size_t len) {
  BIO *bio = (BIO *)ctx;
  int sz;
  sz = iotjs_bio_read(bio, (const char *)buf, len);

  if (sz <= 0) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }
  return sz;
}

JS_FUNCTION(TlsConstructor) {
  DJS_CHECK_THIS();

  jerry_value_t jtls = JS_GET_THIS();
  iotjs_tls_t *tls_data = iotjs_tls_create(jtls);

  jerry_value_t opts = jargv[0];

  tls_data->handshake_state = SSL_HANDSHAKE_READY;

  int ret = 0;

  if ((ret = mbedtls_ctr_drbg_seed(&tls_data->ctr_drbg, mbedtls_entropy_func,
                                   &tls_data->entropy, NULL, 0)) != 0) {
    return JS_CREATE_ERROR(COMMON, "drbg_seeding_failed");
  }

  jerry_value_t jca_txt = iotjs_jval_get_property(opts, "ca");
  if (jerry_value_is_string(jca_txt)) {
    iotjs_string_t ca_txt = iotjs_jval_as_string(jca_txt);
    ret = mbedtls_x509_crt_parse(&tls_data->cacert,
                                 (const unsigned char *)iotjs_string_data(
                                     &ca_txt),
                                 (size_t)iotjs_string_size(&ca_txt) + 1);

    iotjs_string_destroy(&ca_txt);
  } else {
    ret = mbedtls_x509_crt_parse(&tls_data->cacert,
                                 (const unsigned char *)SSL_CA_PEM,
                                 sizeof(SSL_CA_PEM));
  }
  if (ret) {
    return JS_CREATE_ERROR(COMMON, "x509 certificate parsing failed");
  }
  mbedtls_ssl_conf_ca_chain(&tls_data->conf, &tls_data->cacert, NULL);

  mbedtls_ssl_conf_rng(&tls_data->conf, mbedtls_ctr_drbg_random,
                       &tls_data->ctr_drbg);
  jerry_release_value(jca_txt);

  if ((ret = mbedtls_ssl_config_defaults(&tls_data->conf, MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT))) {
    return JS_CREATE_ERROR(COMMON, "SSL Configuration failed.");
  }

  jerry_value_t jrejectUnauthorized =
      iotjs_jval_get_property(opts, "rejectUnauthorized");
  bool rejectUnauthorized = iotjs_jval_as_boolean(jrejectUnauthorized);
  mbedtls_ssl_conf_authmode(&tls_data->conf, rejectUnauthorized
                                                 ? MBEDTLS_SSL_VERIFY_REQUIRED
                                                 : MBEDTLS_SSL_VERIFY_NONE);
  jerry_release_value(jrejectUnauthorized);

  jerry_value_t jservername = iotjs_jval_get_property(opts, "servername");
  iotjs_string_t servername = iotjs_jval_as_string(jservername);

  size_t hostname_size = iotjs_string_size(&servername);
  const char hostname[hostname_size + 1];
  memset((void *)hostname, 0, hostname_size + 1);
  memcpy((void *)hostname, iotjs_string_data(&servername), hostname_size);

  iotjs_string_destroy(&servername);
  jerry_release_value(jservername);
  mbedtls_ssl_set_hostname(&tls_data->ssl, hostname);

  if ((ret = mbedtls_ssl_setup(&tls_data->ssl, &tls_data->conf))) {
    return JS_CREATE_ERROR(COMMON, "SSL setup failed");
  }

  tls_data->app_bio = iotjs_ssl_bio_new(BIO_BIO);
  tls_data->ssl_bio = iotjs_ssl_bio_new(BIO_BIO);
  iotjs_bio_make_bio_pair(tls_data->ssl_bio, tls_data->app_bio);
  mbedtls_ssl_set_bio(&tls_data->ssl, tls_data->ssl_bio, iotjs_bio_net_send,
                      iotjs_bio_net_recv, NULL);


  return jerry_create_undefined();
}

void iotjs_tls_update(iotjs_tls_t *tls_data) {
  size_t pending = iotjs_bio_ctrl_pending(tls_data->app_bio);
  if (pending > 0) {
    char src[pending];
    iotjs_bio_read(tls_data->app_bio, src, sizeof(src));

    jerry_value_t jthis = tls_data->jobject;
    jerry_value_t fn = iotjs_jval_get_property(jthis, "onwrite");
    iotjs_jargs_t jargv = iotjs_jargs_create(1);
    jerry_value_t jbuffer = iotjs_bufferwrap_create_buffer((size_t)pending);
    iotjs_bufferwrap_t *buffer_wrap = iotjs_bufferwrap_from_jbuffer(jbuffer);

    iotjs_bufferwrap_copy(buffer_wrap, (const char *)src, pending);
    iotjs_jargs_append_jval(&jargv, jbuffer);
    iotjs_make_callback(fn, jthis, &jargv);

    jerry_release_value(fn);
    jerry_release_value(jbuffer);
    iotjs_jargs_destroy(&jargv);
  }
}

int iotjs_tls_error_handler(iotjs_tls_t *tls_data, const int code) {
  if (code == MBEDTLS_ERR_SSL_WANT_READ || code == MBEDTLS_ERR_SSL_WANT_WRITE) {
    iotjs_tls_update(tls_data);
  } else if (code < 0) {
    printf("mbedtls handshake failed");
  }

  return code;
}

JS_FUNCTION(Handshake) {
  JS_DECLARE_THIS_PTR(tls, tls_data);

  if (tls_data->handshake_state == SSL_HANDSHAKE_DONE) {
    return jerry_create_number(SSL_HANDSHAKE_DONE);
  }
  tls_data->handshake_state = SSL_HANDSHAKE_IN_PROGRESS;

  int ret_val = 0;
  ret_val = mbedtls_ssl_handshake(&tls_data->ssl);
  ret_val = iotjs_tls_error_handler(tls_data, ret_val);

  if (!ret_val) {
    tls_data->handshake_state = SSL_HANDSHAKE_DONE;

    int verify_status = (int)mbedtls_ssl_get_verify_result(&tls_data->ssl);
    if (verify_status) {
      char buf[256];
      mbedtls_x509_crt_verify_info(buf, sizeof(buf), "::",
                                   (uint32_t)verify_status);
      printf("%s\n", buf);
    }

    jerry_value_t fn = iotjs_jval_get_property(jthis, "onhandshakedone");
    iotjs_make_callback(fn, jthis, iotjs_jargs_get_empty());
    jerry_release_value(fn);
  }

  return jerry_create_number(tls_data->handshake_state);
}

JS_FUNCTION(Write) {
  JS_DECLARE_THIS_PTR(tls, tls_data);

  iotjs_bufferwrap_t *buf = iotjs_bufferwrap_from_jbuffer(jargv[0]);
  size_t ret_val =
      (size_t)mbedtls_ssl_write(&tls_data->ssl, (const unsigned char *)buf,
                                iotjs_bufferwrap_length(buf));
  size_t pending = 0;
  if ((pending = iotjs_bio_ctrl_pending(tls_data->app_bio)) > 0) {
    const char temp_buffer[pending];
    memset((void *)temp_buffer, 0, pending);
    ret_val = (size_t)iotjs_bio_read(tls_data->app_bio, temp_buffer, pending);

    jerry_value_t out = iotjs_bufferwrap_create_buffer(ret_val);
    iotjs_bufferwrap_t *outbuf = iotjs_bufferwrap_from_jbuffer(out);
    iotjs_bufferwrap_copy(outbuf, (const char *)temp_buffer, ret_val);
    return out;
  } else {
    return jerry_create_null();
  }
}

JS_FUNCTION(End) {
  JS_DECLARE_THIS_PTR(tls, tls_data);

  iotjs_tls_destroy(tls_data);
  iotjs_bio_free_all(tls_data->app_bio);
  iotjs_bio_free_all(tls_data->ssl_bio);

  return jerry_create_undefined();
}

jerry_value_t InitTls() {
  jerry_value_t jtls = jerry_create_object();
  jerry_value_t tlsConstructor = jerry_create_external_function(TlsConstructor);

  iotjs_jval_set_property_jval(jtls, IOTJS_MAGIC_STRING_TLSWRAP,
                               tlsConstructor);

  jerry_value_t prototype = jerry_create_object();

  iotjs_jval_set_method(prototype, IOTJS_MAGIC_STRING_WRITE, Write);
  iotjs_jval_set_method(prototype, "handshake", Handshake);
  iotjs_jval_set_method(prototype, "end", End);
  iotjs_jval_set_property_jval(tlsConstructor, "prototype", prototype);

  jerry_release_value(prototype);
  jerry_release_value(tlsConstructor);

  return jtls;
}
