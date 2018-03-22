### Platform Support

The following chart shows the availability of each TLS module API function on each platform.

|  | Linux<br/>(Ubuntu) | Raspbian<br/>(Raspberry Pi) | Nuttx<br/>(STM32F4-Discovery) | TizenRT<br/>(Artik053) | Tizen<br/>(Artik 10) |
| :---: | :---: | :---: | :---: | :---: | :---: |
| tls.connect  | X | X | O | X | O |
| tls.write  | X | X | O | X | O |
| tls.pause | X | X | O | X | O |
| tls.end | X | X | O | X | O |
| tls.resume | X | X | O | X | O |
| tls.pause | X | X | O | X | O |

# TLS

Transport Layer Security makes secure communication over sockets possible. Currently only TLS Client is supported.

## Class: tls.TLSSocket
The `TLSSocket` is responsible for all TLS negotiations and data encryption on a `net.Socket`.

Just like `net.Socket` it uses a `Stream.duplex` interface.

### new tls.TLSSocket(socket[,options])
- `socket` {net.Socket | stream.Duplex}
- `options` {Object}
    - `isServer` Whether the TLSSocket should behave as a server or client. If `true`, the TLS socket will be instantiated as a server. Defaults to `false`.
    - `session` {Buffer} Optional, `Buffer` instance containing a TLS session.

Note: `tls.connect()` must be used to create the socket.

### tls.connect(options[,callback])
- `options` {Object}
    - `host` {string} Host the client should connect to, defaults to 'localhost'.
    - `port` {number} Port the client should connect to.
    - `socket` {stream.Duplex} Optional, typically an instance of `net.Socket`. If this options is specified, host and port are ignored. The user passing the options is responsible for it connecting to the server. `tls.connect` won't call `net.connect` on it.
    - `rejectUnauthorized` {boolean} Whether the server certificate should be verified against the list of supplied CAs. An `error` event is emitted if verifications fails; `err.code` contains the MbedTLS error code. Defaults to `false`.
    - `servername` {string} Server name for the SNI (Server name Indication) TLS extension.
- `callback` {Function} The callback function will be added as a listener for the `secureConnect` event.

Returns a `tls.TLSSocket` object.

**Example**
```js
var tls = require('tls');

var opts = {
    host: '127.0.0.1',
    port: 443,
    rejectUnauthorized: true
}

var socket = tls.connect(opts, function() {
    socket.write('Hello IoT.js');
    socket.end();
});
```

### tlsSocket.address()
Returns an object containing the bound address, family name, and port of the socket.`{port: 443, family: 'IPv4', address: '127.0.0.1'}`

### tlsSocket.authorizationError
Returns the reason why the peer's certificate has not been verified.

### tlsSocket.authorized
Returns `true` if the peer certificate was signed by one of the CAs specified when creating the `tls.TLSSocket` instance, otherwise false.

### tlsSocket.encrypted
Always returns `true`, can be used to distinguish TLS sockets from regular `net.Socket`s.

### tlsSocket.getProtocol()
Returns a string containing the negotiated SSL/TLS protocol version of the connection. If the handshaking has not been complete, `unknown` will be returned. The value `null` will be returned for server sockets or disconnected client sockets.

### Event: 'secureConnect'
The `'secureConnect'` event is emitted after the handshaking process has successfully completed. Regardless of wheter or not the server's certificate has been authorized, the listener callbakc will be called. It is the client's responsibility to check the tlsSocket.authorized property to determine if the server certificate was signed by one of the specified CAs.

## tls.createSercureContext(options)
 - `options` {Object}
    - `key` {string | Buffer} Optional private keys in PEM format. PEM allows the options of private keys being encrypted.
    - `cert` {string | Buffer} Optional cert chains in PEM format. One cert chain should be provided per private key. Each cert chain should consist of the PEM formatted certificate for a provided private `key`, followed by the PEM formatted intermediate certificates (if any), in order, and not including the root CA.
    - `ca` {string | Buffer} Optionally override the default trusted CA certificates. If this options is given, the default trusted CA certs will be completely ignored. Only one `ca` is currently supported.

## Class: tls.Server

### tls.createServer([options][,secureConnectionListener])
- `options` {Object}
    - `rejectUnauthorized` {boolean} If not `false` the server will reject any connection which is not authorized with the list of supplied CAs. Defaults to `true`.
- `secureConnectionListener` {Function}
Creates a new `tls.Server`. The `secureConnectionListener`, if provided, is set as a listener for the `secureConnection` event.

```js
var port = 8000;

var options = {
  key: fs.readFileSync('server-key.pem').toString(),
  cert: fs.readFileSync('server-cert.pem').toString(),
  rejectUnauthorized: false,
  isServer: true,
};

var server = tls.createServer(options, function(socket) {
    socket.write('Hello IoT.js');
    socket.end();
    server.close();
}).listen(port, function() {
  console.log('Listening on port: ' + port);
});

```

### Event: 'secureConnection'
The `'secureConnection'` event is emitted after the handshaking process for a new connection has successfully completed. The listener callback is passed a single argument when called:
 - `tlsSocket` {tls.TlsSocket} The estabilished TLS socket.
The `tlsSocket.authorized` property is a `boolean` indicating whether the client has been verified by one of the Certificate Authorities provided for the server.
The `tlsSocket.servername` property is a `string` containing the server name requested via SNI.

### Event: 'tlsClientError'
The `tlsClientError` event is emitted when an error occurs before the secure connection is established. The listener callback is passed two arguments if called:
 - `exception` {Error} The `Error` object describing the error.
 - `tlsSocket` {tls.tlsSocket} The `tls.TLSSocket` instance from which the error originated.
