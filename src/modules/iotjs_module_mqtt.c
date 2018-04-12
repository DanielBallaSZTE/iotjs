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

#include <string.h>
#include <stdlib.h>

#include "iotjs_def.h"
#include "iotjs_module_mqtt.h"
#include "iotjs_module_buffer.h"


#include "iotjs_handlewrap.h"
#include "iotjs_reqwrap.h"

static void iotjs_mqtt_client_destroy(iotjs_mqtt_client_t *mqtt_client) {

  IOTJS_RELEASE(mqtt_client);
}

static const jerry_object_native_info_t mqtt_client_native_info = {
  .free_cb = (jerry_object_native_free_callback_t)iotjs_mqtt_client_destroy
};

static iotjs_mqtt_client_t *iotjs_mqtt_client_create(const jerry_value_t jobject) {
  iotjs_mqtt_client_t *mqtt_client = IOTJS_ALLOC(iotjs_mqtt_client_t);

  jerry_set_object_native_pointer(jobject, mqtt_client, &mqtt_client_native_info);

  return mqtt_client;
}


IOTJS_DEFINE_NATIVE_HANDLE_INFO_THIS_MODULE(mqtt_client);



JS_FUNCTION(MqttInit) {
  DJS_CHECK_THIS();

  jerry_value_t jtls = JS_GET_THIS();

  iotjs_mqtt_client_t *mqtt_client = iotjs_mqtt_client_create(jtls);

  IOTJS_UNUSED(mqtt_client);

  return jerry_create_undefined();
}

static size_t iotjs_encode_remaining_length(char *ptr, int len) {
  size_t rc = 0;

  do {
    char d = len % 128;
    len /= 128;
    if (len > 0) {
      d |= 0x80;
    }
    ptr[rc++] = d;
  } while (len > 0);

  return rc;
}

static iotjs_mqtt_payload_t iotjs_create_payload(iotjs_bufferwrap_t *bufferwrap) {
  iotjs_mqtt_payload_t payload;
  payload.data.msb = (uint8_t) ((bufferwrap->length & 0xFF00) >> 8);
  payload.data.lsb = (uint8_t) (bufferwrap->length & 0x00FF);
  payload.data.buffer = bufferwrap->buffer;
  payload.size =
      sizeof(payload.data.msb) + sizeof(payload.data.lsb) + bufferwrap->length;
  payload.buffer_size = bufferwrap->length;

  return payload;
}

JS_FUNCTION(MqttConnect) {
  DJS_CHECK_THIS();

  DJS_CHECK_ARGS(1, object);

  jerry_value_t joptions = JS_GET_ARG(0, object);

  jerry_value_t jclient_id = iotjs_jval_get_property(joptions, "clientId");
  jerry_value_t jusername = iotjs_jval_get_property(joptions, "username");
  jerry_value_t jpassword = iotjs_jval_get_property(joptions, "password");

  uint8_t connect_flag = 0;
  connect_flag |= FLAG_CLEANSESSION;

  if (!jerry_value_is_undefined(jusername)) {
    connect_flag |= FLAG_USERNAME;
  }
  if (!jerry_value_is_undefined(jpassword)) {
    connect_flag |= FLAG_PASSWORD;
  }

  iotjs_bufferwrap_t *client_id = iotjs_bufferwrap_from_jbuffer(jclient_id);
  iotjs_mqtt_payload_t client_id_payload = iotjs_create_payload(client_id);

  unsigned char protocol[] = "MQTT";
  uint8_t version = (char) 4;
  uint8_t keep_alive_msb = 0;
  uint8_t keep_alive_lsb = 10;
  uint8_t length_msb = 0;
  uint8_t length_lsb = 4;

  size_t variable_header_len =
      sizeof(length_msb) +       // 1, 0
      sizeof(length_lsb) +       // 1, 4
      (sizeof(protocol) - 1) +     // 4, MQTT
      sizeof(version) +          // 1, '4'
      sizeof(connect_flag) + // 1, connect flags
      sizeof(keep_alive_lsb) +   // 1, 0
      sizeof(keep_alive_msb);    // 1, 10

  size_t payload_len = client_id_payload.size;
  uint8_t remaining_length = payload_len + variable_header_len;
  size_t full_len = sizeof(MQTTHeader) + payload_len + variable_header_len + sizeof(remaining_length);

  jerry_value_t jbuff = iotjs_bufferwrap_create_buffer(full_len);
  iotjs_bufferwrap_t *buffer_wrap = iotjs_bufferwrap_from_jbuffer(jbuff);

  IOTJS_UNUSED(client_id_payload);

  MQTTHeader header = {0};

  header.byte = 0;
  header.bits.type = CONNECT;

  size_t offset = 0;

  // Fixed header
  memcpy(buffer_wrap->buffer, &header.byte, sizeof(header.byte));
  offset += sizeof(header.byte);

  // Write remaining length
  offset += iotjs_encode_remaining_length(buffer_wrap->buffer + offset,
                                          remaining_length);

  // Variable header
  // Length MSB, Length LSB
  memcpy(buffer_wrap->buffer + offset, &length_msb, sizeof(length_msb));
  offset += sizeof(length_msb);
  memcpy(buffer_wrap->buffer + offset, &length_lsb, sizeof(length_lsb));
  offset += sizeof(length_lsb);

  // Protocol info
  // Need -1 because the buffer puts \0
  memcpy(buffer_wrap->buffer + offset, protocol, sizeof(protocol) - 1);
  offset += sizeof(protocol) - 1;
  memcpy(buffer_wrap->buffer + offset, &version, sizeof(version));
  offset += sizeof(version);

  // Flags
  memcpy(buffer_wrap->buffer + offset, &connect_flag, sizeof(connect_flag));
  offset += sizeof(connect_flag);

  // Keep alive interval
  memcpy(buffer_wrap->buffer + offset, &keep_alive_msb, sizeof(keep_alive_msb));
  offset += sizeof(keep_alive_msb);
  memcpy(buffer_wrap->buffer + offset, &keep_alive_lsb, sizeof(keep_alive_lsb));
  offset += sizeof(keep_alive_lsb);

  // client id
  memcpy(buffer_wrap->buffer + offset, &client_id_payload.data.msb, sizeof(uint8_t));
  offset += sizeof(uint8_t);
  memcpy(buffer_wrap->buffer + offset, &client_id_payload.data.lsb, sizeof(uint8_t));
  offset += sizeof(uint8_t);
  memcpy(buffer_wrap->buffer + offset, client_id_payload.data.buffer, client_id_payload.buffer_size);

  jerry_release_value(jclient_id);
  jerry_release_value(jusername);
  jerry_release_value(jpassword);

  return jbuff;
}

jerry_value_t InitMQTT() {
  jerry_value_t jMQTT = jerry_create_object();

  iotjs_jval_set_method(jMQTT, IOTJS_MAGIC_STRING_MQTTINIT, MqttInit);
  iotjs_jval_set_method(jMQTT, IOTJS_MAGIC_STRING_CONNECT, MqttConnect);

  return jMQTT;
}
