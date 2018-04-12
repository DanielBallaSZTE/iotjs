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

JS_FUNCTION(MqttConnect) {
  DJS_CHECK_THIS();

  iotjs_mqtt_message_connect_t connect;

  // Set up the first byte of the packet
  connect.fixed_header.packet.packet_type = CONNECT;
  connect.fixed_header.packet.DUP = 0;
  connect.fixed_header.packet.QoS = 0;
  connect.fixed_header.packet.RETAIN = 0;

  connect.length_msb = 0;
  connect.length_lsb = 4;
  connect.protocol[0] = 'M';
  connect.protocol[1] = 'Q';
  connect.protocol[2] = 'T';
  connect.protocol[3] = 'T';
  // connect.fixed_header.remaining_length

  connect.protocol_level = 4;
  connect.connect_flags.user_name = false;
  connect.connect_flags.password = false;
  connect.connect_flags.will_retain = false;
  connect.connect_flags.will_QoS = 0;
  connect.connect_flags.will_flag = false;
  connect.connect_flags.clean_session = 1;
  connect.connect_flags.reserved = 0;


  connect.keep_alive_msb = 0;
  connect.kepp_alive_lsb = 10;

  jerry_value_t jbuff = iotjs_bufferwrap_create_buffer(sizeof(iotjs_mqtt_message_connect_t));
  iotjs_bufferwrap_t *buffer_wrap = iotjs_bufferwrap_from_jbuffer(jbuff);

  memcpy(buffer_wrap->buffer, &connect, sizeof(iotjs_mqtt_message_connect_t));

  return jbuff;
}

jerry_value_t InitMQTT() {
  jerry_value_t jMQTT = jerry_create_object();

  iotjs_jval_set_method(jMQTT, IOTJS_MAGIC_STRING_MQTTINIT, MqttInit);
  iotjs_jval_set_method(jMQTT, IOTJS_MAGIC_STRING_CONNECT, MqttConnect);

  return jMQTT;
}