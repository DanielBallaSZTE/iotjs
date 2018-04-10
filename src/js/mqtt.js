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

function MQTTClient(_path, options) {
  EventEmitter.call(this);

  var path = URL.parse(_path);
  this._host = path.hostname;
  this._port = Number(path.port) || 1883;
  this._protocol = path.protocol;

  this._options = Object.assign({
    username: null,
    password: null,
    clientId: defaultClientId(),
    keepalive: 60 * 1000,
    reconnectPeriod: 5000,
    connectTimeout: 30 * 1000,
    resubscribe: true,
    protocolId: 'MQTT',
    protocolVersion: 4,
  }, options);

  this._isConnected = false;
  this._reconnecting = false;
  this._reconnectingTimer = null;
  this._lastConnectTime = 0;
  this._messageId = 0;
  this._ttl = null;
}

/*
 * Connect to an MQTT broker.
 */
MQTTClient.prototype.connect = function() {
  var connectionOptions = Object.assign({
    port: this._port,
    host: this._host
  }, this._options);

  if(this._protocol === 'tls:') {
    var tls = require('tls');
    this._socket = tls.connect(connectionOptions, this._onConnect.bind(this));
  } else {
    this._socket = net.connect(connectionOptions, this._onConnect.bind(this));
  }

  this._socket.on('data', this._onData.bind(this));
  this._socket.on('error', this._onDisconnect.bind(this));
  this._socket.on('end', this._onDisconnect.bind(this));
  this._lastConnectTime = Date.now();
}

MQTTClient.prototype.disconnect = function(error) {
  if(error) {
    this.emit('error', error);
  }

  clearTimeout(this._ttl);
  clearTimeout(this._reconnectingTimer);

  this._isConnected = false;
  this._socket.end();
}

MQTTClient.prototype.reconnect = function() {
  if(this._reconnecting) {
    return;
  }

  this.disconnect();
  // Delay the connection.
  this.connect();
}

MQTTClient.prototype._onConnect = function() {
  this._isConnected = true;
  // ...
}

MQTTClient.prototype._onDisconnect = function(error) {
  if(error) {
    this.emit('error', error);
  }

  this._isConnected = false;
  this.emit('offline');

}

MQTTClient.prototype._onData = function() {

}

MQTTClient.prototype.publish = function() {

}

MQTTClient.prototype.subscribe = function() {

}

MQTTClient.prototype.unSubscribe = function() {
  
}

/*
 * Returns an unique client ID based on current time.
 */
function defaultClientId() {
  return "iotjs_mqtt_client_" + new Date().getTime();
}

var noop = function() {}

function getClient(path, connectionOptions) {
  return new MQTTClient(path, connectionOptions);
}

module.exports = getClient;
