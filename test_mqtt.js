var mqtt = require('mqtt');

var options = {
  host: '127.0.0.1',
  port: 1883,
}

var valami = mqtt.getClient(options);
valami.connect();