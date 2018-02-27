var tls = require('tls');

options = {
  host: "127.0.0.1",
  port: 4443,
}

var connection = tls.connect(options);
if (!connection) {
  console.log("JS SIDE CONNECTION FAILED");
}
