/* Copyright 2015-present Samsung Electronics Co., Ltd. and other contributors
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

#ifndef IOTJS_MODULE_MQTT_H
#define IOTJS_MODULE_MQTT_H

#include "iotjs_def.h"

/*
 * The types of the control packet.
 * These values determine the aim of the message.
 */
enum {
  CONNECT =     0b0001,
  CONNACK =     0b0010,
  PUBLISH =     0b0011,
  PUBACK =      0b0100,
  PUBREC =      0b0101,
  PUBREL =      0b0110,
  PUBCOMP =     0b0111,
  SUBSCRIBE =   0b1000,
  SUBACK =      0b1001,
  UNSUBSCRIBE = 0b1010,
  UNSUBACK =    0b1011,
  PINGREQ =     0b1100,
  PINGRESP =    0b1101,
  DISCONNECT =  0b1110
} iotjs_mqtt_control_packet_type;

/*
 * The values of the Quality of Service.
 */
enum {
  QoS0 = 0b00, // At most once delivery.
  QoS1 = 0b01, // At least once delivery.
  QoS2 = 0b10  // Exactly once delivery.
} iotjs_mqtt_quality_of_service;

/*
 * First byte of the message's fixed header.
 * Contains:
 * - MQTT Control Packet type,
 * - Specific flags to each MQTT Control Packet.
 */
typedef struct {
  unsigned char packet_type : 4;
  uint8_t DUP : 1;          // Duplicate delivery of PUBLISH Control Packet.
  unsigned char QoS : 2; // PUBLISH Quality of Service.
  uint8_t RETAIN : 1;       // PUBLISH Retain flag.
} iotjs_mqtt_control_packet_t;

/*
 * The fixed header of the MQTT message structure.
 */
typedef struct {
  iotjs_mqtt_control_packet_t packet;
  unsigned char remaining_length;
} iotjs_mqtt_fixed_header_t;

/*
 * Type of the MQTT message with header only.
 * This type is used by PINGREQ, PINGRESP and DISCONNECT messages.
 */
typedef struct {
  iotjs_mqtt_fixed_header_t fixed_header;
} iotjs_mqtt_message_t;

/*
 * Type of the MQTT CONNECT message.
 */
typedef struct {
  iotjs_mqtt_fixed_header_t fixed_header;

  uint8_t length_msb; // always 0
  uint8_t length_lsb; // always 4
  unsigned char protocol[4]; // 3 - 6
  uint8_t protocol_level; // 7; value must be 4

  struct {
    uint8_t user_name : 1;
    uint8_t password  : 1;
    uint8_t will_retain : 1;
    uint8_t will_QoS : 2;
    uint8_t will_flag : 1;
    uint8_t clean_session : 1;

    uint8_t reserved : 1; // Reserved and it's value must be set to 0.
  } connect_flags;

  uint8_t keep_alive_msb;
  uint8_t kepp_alive_lsb;

  // Payload
  // unsigned char *client_identifier;
  // unsigned char *will_topic;
  // unsigned char *will_message;
  // unsigned char *user_name;
  // uint16_t password_length;
  // unsigned char *password; // uint16_t lenght needs to be before this field.
} iotjs_mqtt_message_connect_t;

/*
 * Type of the MQTT CONNACK message.
 */
typedef struct {
  iotjs_mqtt_fixed_header_t fixed_header;

  struct {
    uint8_t reserved : 7;
    bool session_present : 1;
  } acknowledge_flags;

  uint8_t return_code;
} iotjs_mqtt_message_connack_t;

/*
 * Type of the MQTT PUBLISH message.
 */
typedef struct {
  iotjs_mqtt_fixed_header_t fixed_header;


  uint16_t topic_length;
  unsigned char *topic_name; // uint16_t lenght needs to be before this field.
  uint16_t packet_identifier;

  // Payload
  uint16_t payload_length;
  unsigned char *message;
} iotjs_mqtt_message_publish_t;

/*
 * Type of the MQTT PUBLISH or UNSUBSCRIBE response message.
 * This type is used by PUBACK, PUBREC, PUBREL, PUBCOMP, UNSUBACK messages.
 */
typedef struct {
  iotjs_mqtt_fixed_header_t fixed_header;

  uint16_t packet_identifier;
} iotjs_mqtt_message_response_t;

/*
 * Type of the MQTT SUBSCRIBE message.
 */
typedef struct {
  iotjs_mqtt_fixed_header_t fixed_header;

  uint16_t packet_identifier;

  // Payload
  uint16_t payload_length;
  unsigned char *topic_filters; // uint16_t lenght needs to be before this field
  uint8_t requested_qoss[];
} iotjs_mqtt_message_subscribe_t;

/*
 * The type of the MQTT SUBACK message.
 */
typedef struct {
  iotjs_mqtt_fixed_header_t fixed_header;

  uint16_t packet_identifier;

  // Payload
  uint8_t return_codes[]; // Return codes for each requestet topic.
} iotjs_mqtt_message_suback_t;

/*
 * Type of the MQTT UNSUBSCRIBE message.
 */
typedef struct {
  iotjs_mqtt_fixed_header_t fixed_header;

  uint16_t packet_identifier;

  // Payload
  uint16_t payload_length;
  unsigned char *topic_filters; // uint16_t lenght needs to be before this field
} iotjs_mqtt_message_unsubscribe_t;

typedef struct {
  char *client_id;
  unsigned char protocol[4]; // value: 'MQTT'
  uint8_t protocol_level;    // value: 4
  uint16_t keep_alive;       // value: 60.000 (60 s)
  uint16_t reconnect_period; // value: 5.000 (5 s)
} iotjs_mqtt_client_t;

#endif /* IOTJS_MODULE_MQTT_H */
