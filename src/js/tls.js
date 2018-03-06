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

var net = require('net');
var util = require('util');
var EventEmitter = require('events').EventEmitter;

TLSSocket = function(opts) {
  if (!(this instanceof TLSSocket)) {
    return new TLSSocket(opts);
  }

  EventEmitter.call(this);
  this._socket = new net.Socket();

  this.encrypted = true;
  this.servername = opts.servername || opts.host;
  this._pendingRead = false;
  this._chunkSize = 8 * 1024;

  this._socket.on('connect', this.onsocket.bind(this));
  this._socket.on('end', this.onsocketend.bind(this));

  // Native handle
  opts.rejectUnauthorized = false;
  opts.servername = '127.0.0.1';
  this._tls = new native.TlsWrap(opts);
  this._tls.jsref = this;
  this._tls.onread = this.onread;
  this._tls.onwrite = this.onwrite;
  this._tls.onhandshakedone = this.onhandshakedone;
  this._tls.ondata = this.ondata;

};
util.inherits(TLSSocket, EventEmitter);

TLSSocket.prototype.connect = function (opts, callback) {
  this.once('connect', callback);
  return this._socket.connect(opts);
}

TLSSocket.prototype.onsocketend = function() {
  console.log('dummy');
};

TLSSocket.prototype.onsocket = function() {
  this.emit('socket', this._socket);
  this._tls.handshake();
};

TLSSocket.prototype.write = function(data) {
  if (!Buffer.isBuffer(data)) {
    data = new Buffer(data);
  }
  return this._tls.write(data);
}

TLSSocket.prototype.onhandshakedone = function(status) {
  var self = this._tls.jsref;
  self.authorized = true;
  self.emit('connect');
}

TLSSocket.prototype.onwrite = function(chunk) {
  var self = this.jsref;
  return self._socket.write(chunk);
};

TLSSocket.prototype.onread = function(size) {
  var buf = this.jsref._socket.read(size);
  return Buffer.isBuffer(buf) ? buf : null;
};

function connect(options, callback) {
  return TLSSocket({
    port: options.port,
    host: options.host,
  }).connect(options, callback);
};

createSecureContext = function(options) {
  this.pfx = options.pfx;
  this.key = options.key;
  this.passphrase = options.passphras;
  this.cert = options.cert;
  this.ca = options.ca;
  this.ciphers = options.ciphers;
  this.honorCipherOrder = false;
  this.ecdhCurve = options.ecdhCurve;
  this.clientCertEngine = options.clientCertEngine;
  this.crl = options.crl;
  if (options.dhparam && options.dhparam.length < 128) {
    throw new RangeError('Key length must be at least 1024 bits');
  }
  this.dhparam = options.dhparam;

};


exports.TLSSocket = TLSSocket;
exports.connect = connect;
