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

var net = require('net');
var URL = require('url');
var util = require('util');
var eventEmitter = require('events').EventEmitter;

util.inherits(MQTTClient, EventEmitter);

function MQTTClient(path, options) {
  EventEmitter.call(this);

  path = URL.parse(path);
  this._clientOptions = Object.create(options, {
    host: path.hostname,
    port: Number(path.port) || 1883,
    protocol: path.protocol,
    clientId: defaultClientId()
  });

  this._isConnected = false;
  this._reconnecting = false;
  this._messageId = 0;
}

/*
 * Connect to an MQTT broker.
 */
MQTTClient.prototype.connect = function() {
  if(this._protocol === 'tls:') {
    var tls = require('tls');
    this._socket = tls.connect(this._clientOptions, this.onconnect);
  } else {
    this._socket = net.connect(this._clientOptions, this.onconnect);
  }

  this._socket.on('data', this.ondata);
  this._socket.on('error', this.ondisconnect);
  this._socket.on('end', this.ondisconnect);
}

MQTTClient.prototype.disconnect = function(error) {
  if(error) {
    this.emit('error', error);
  }

  this._isConnected = false;
  this._socket.end();
}

MQTTClient.prototype.reconnect = function() {
  if(this._reconnecting) {
    return;
  }

  this.disconnect();
  setTimeout(this.connect, this._options.reconnectPeriod);
}

MQTTClient.prototype.onconnect = function() {
  this._isConnected = true;
  native.MQTTInit(this, this._clientOptions);
}

MQTTClient.prototype.ondisconnect = function(error) {
  if(error) {
    this.emit('error', error);
  }
  // ... Native buffer releases.
  this._isConnected = false;
  this.emit('offline');
}

MQTTClient.prototype.ondata = function() {
  // ... Native handle.
}

MQTTClient.prototype.publish = function() {
  // ... Native handle.
}

MQTTClient.prototype.subscribe = function() {
  // ... Native handle.
}

MQTTClient.prototype.unsubscribe = function() {
  // ... Native handle.
}

/*
 * Returns an unique client ID based on current time.
 */
function defaultClientId() {
  return "iotjs_mqtt_client_" + Date.now();
}

var noop = function() {}

function getClient(path, connectionOptions) {
  return new MQTTClient(path, connectionOptions);
}

module.exports = getClient;
