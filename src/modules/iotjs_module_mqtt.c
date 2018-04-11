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

#include "iotjs_def.h"
#include "iotjs_module_mqtt.h"
#include "iotjs_module_tcp.h"


#include "iotjs_handlewrap.h"
#include "iotjs_reqwrap.h"

IOTJS_DEFINE_NATIVE_HANDLE_INFO_THIS_MODULE(mqtt);

JS_FUNCTION(MQTTInit) {
  DJS_CHECK_THIS();
  DJS_CHECK_ARGS(2, object, object);

  jerry_value_t context = JS_GET_ARG(0, object);
  jerry_value_t options = JS_GET_ARG(1, object);

  iotjs_mqtt_client_t client;
  client.client_id = iotjs_jval_get_property(options, "clientId");
  strcpy(client.protocol, "MQTT");
  client.protocol_level = 4;
  client.keep_alive = 60000;
  client.reconnect_period = 5000;
}

JS_FUNCTION(MQTTPreparePackage)

jerry_value_t InitMQTT() {
  jerry_value_t jMQTT = jerry_create_object();

  iotjs_jval_set_method(jMQTT, IOTJS_MAGIC_STRING_MQTTINIT, MQTTInit);
  iotjs_jval_set_method(
    jMQTT, IOTJS_MAGIC_STRING_MQTTPREPARE, MQTTPreparePackage);
}