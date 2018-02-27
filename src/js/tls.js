var util = require('util');
var net = require('net');

function Tls() {

}

Tls.connect = function (options) {
  if (options.socket || options.path) {
    this._socket = options.socket || options.path;
  } else {
    this._socket = options.socket || new net.Socket;
    this.host = options.host || "localhost";
    this.port = options.port;

    // If no previous socket was defined we have to handle connecting
    // the socket to the host and port.
    //this._socket.connect(this.port, this.host);
    //this._socket.end('js socket end');
  }
  this.servername = options.servername || "default";
  this.session = options.session;
  this.minDHSize = options.minDHSize || 1024;
  // this.secureContext = options.secureContext || Tls.createSecureContext();


  var res = native.connect(this.port.toString(), this.host, this.servername);
  if (util.isString(res)) {
    throw new Error(res);
  }

  return this._socket;
}

Tls.createSecureContext = function (options) {
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
    throw new RangeError("Key length must be at least 1024 bits (128 characters)");
  }
  this.dhparam = options.dhparam;

}

module.exports = Tls;
