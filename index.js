#!/usr/bin/env node
// Platform Dependencies
const fetch = require('node-fetch');
const express = require('express');
const https = require('https');
const fs = require('fs');
const os = require('os');
const dayjs = require('dayjs');
const jwt = require('express-jwt');
const jwtAuthz = require ('express-jwt-authz');
const jwksRsa = require('jwks-rsa');
const Gpio = require('pigpio').Gpio;
const dht = require('pigpio-dht');


// Platform Configuration
require('dotenv').config();

const config = {
  platformName: process.env.PLATFORM_NAME,
  remoteApiDisplayName: process.env.REMOTEAPI_DISPLAYNAME,
  remoteApiURL: process.env.REMOTEAPI_URL,
  remoteApiRejectInvalidCert: Boolean(process.env.REMOTEAPI_REJECTINVALIDCERT),
  directConnectApiIPv4: process.env.DIRECTCONNECTAPI_IPV4,
  directConnectApiPort: Number(process.env.DIRECTCONNECTAPI_PORT),
  directConnectApiHttps: Boolean(process.env.DIRECTCONNECTAPI_HTTPS),
  directConnectApiHttpsKeyPath: process.env.DIRECTCONNECTAPI_HTTPSKEYPATH,
  directConnectApiHttpsCertPath: process.env.DIRECTCONNECTAPI_HTTPSCERTPATH,
  jwt: Boolean(process.env.JWT),
  jwtAudience: process.env.JWT_AUDIENCE,
  jwtIssuer: process.env.JWT_ISSUER,
  jwtClientID: process.env.JWT_CLIENTID,
  jwtClientSecret: process.env.JWT_CLIENTSECRET,
};

// Garage Door Opener - Friendly State
let garageDoorFriendlyState = {
  true: 'True',
  false: 'False',
  0:'Open',
  1:'Closed',
  2:'Opening',
  3:'Closing',
  4:'Stopped',
};

// JWT - Default State
let apiJWT = {
  'access_token': '',
  'token_type': '',
  'expires': 0,
  'scope': '',
  'valid': false,
};

//
// Configure Devices
//

// Device Configuration - Initial State

const deviceTypes = [
  'Garage Door Opener',
  'Lightbulb',
  'Temperature Sensor',
  'Humidity Sensor'
]

const defaultDeviceObjects = [
  {name: 'GarageDoor', uuid: '1111-2222-3333-0000', type: 'Garage Door Opener', characteristics: {CurrentDoorState: 1, TargetDoorState: 1, ObstructionDetected: false}, gpio: {activeHigh: false, output: 23}},
  {name: 'GarageLight', uuid: '1111-2222-3333-0001', type: 'Lightbulb', characteristics: {On: false}, gpio: {activeHigh: false, output: 24}},
  {name: 'SecurityLight1', uuid: '1111-2222-3333-0002', type: 'Lightbulb', characteristics: {On: false, Brightness: 100, ColorTemperature: 140, Hue: 180, Saturation: 50}, gpio: {activeHigh: true, output: 25}},
  {name: 'SecurityLight2', uuid: '1111-2222-3333-0003', type: 'Lightbulb', characteristics: {On: false, Brightness: 100}, gpio: {activeHigh: true, output: 22}},
  {name: 'GarageTempSensor', uuid: '1111-2222-3333-0006', type: 'Temperature Sensor', characteristics: {StatusActive: true, CurrentTemperature: 0}},
  {name: 'GarageHumiditySensor', uuid: '1111-2222-3333-0007', type: 'Humidity Sensor', characteristics: {StatusActive: true, CurrentRelativeHumidity: 0}},
];

// Validate Device Configuration and associate GPIO Output - Dynamic State
const outputDevice = [];
var validDevices = defaultDeviceObjects.map(function(obj) {

  if (validUUID(obj.uuid) && deviceTypes.includes(obj.type)) {
      if (obj.gpio) {
        outputDevice.push(new Gpio(obj.gpio.output, {mode: Gpio.OUTPUT}));
        log_device(`[Platform Initialisation] [Device Event]: Added New Output Device (${obj.name} | ${obj.type})`);
      }
      return {name: obj.name, uuid: obj.uuid, type: obj.type, characteristics: obj.characteristics, gpio: obj.gpio};

  } else if (!validUUID(obj.uuid)){
      log_device(`[Platform Initialisation] [Device Error]: ${obj.name} has an invalid UUID (${obj.uuid})`);
  } else if (!deviceTypes.includes(obj.type)) {
      log_device(`[Platform Initialisation] [Device Error]: ${obj.name} has an invalid type (${obj.type})`);
  }
});

// Remove Invalid Devices - Dynamic State
var deviceObjects = validDevices.filter((device) => {return device != null });

//
// Configure GPIO Input Devices
//

var inputDeviceID1 = -1;
var inputDeviceID2 = -1;

// Configure GPIO Input - Garage Door
inputDeviceID1 = deviceObjects.findIndex(device => device.uuid === '1111-2222-3333-0000');
if (inputDeviceID1 !== -1) {
  const inputDevice0 = new Gpio(5, {
    mode: Gpio.INPUT,
    pullUpDown: Gpio.PUD_UP,
    alert: true
  });

  inputDevice0.glitchFilter(10000);

  inputDevice0.on('alert', (level) => {
    if (level === 1) {
      inputDeviceID1 = deviceObjects.findIndex(device => device.uuid === '1111-2222-3333-0000');
      updateCharacteristics = {'uuid': deviceObjects[inputDeviceID1].uuid, 'characteristics': {'TargetDoorState': ((deviceObjects[inputDeviceID1].characteristics.CurrentDoorState === 0) ?  1 : 0)}};
      updateDevice('local', 'Local', updateCharacteristics, '');
    }
  });
  log_device(`[Platform Initialisation] [Device Event]: Added New Input Device (${deviceObjects[inputDeviceID1].name} | Switch)`);
}

// Configure GPIO Input - Garage Door Obstruction Sensor
inputDeviceID1 = deviceObjects.findIndex(device => device.uuid === '1111-2222-3333-0000');
if (inputDeviceID1 !== -1) {
  const inputDevice1 = new Gpio(4, {
    mode: Gpio.INPUT,
    pullUpDown: Gpio.PUD_DOWN,
    alert: true
  });

  inputDevice1.glitchFilter(10000);

  inputDevice1.on('alert', (level) => {
    inputDeviceID1 = deviceObjects.findIndex(device => device.uuid === '1111-2222-3333-0000');
    deviceObjects[inputDeviceID1].characteristics.ObstructionDetected = (level === 1)? true : false;
    const body = {'uuid': deviceObjects[inputDeviceID1].uuid, 'characteristics': {'ObstructionDetected': deviceObjects[inputDeviceID1].characteristics.ObstructionDetected}};
    log_device(`[Local] [Device Event]: (${deviceObjects[inputDeviceID1].name} | ObstructionDetected) set to (${garageDoorFriendlyState[deviceObjects[inputDeviceID1].characteristics.ObstructionDetected]})`);
    remoteAPI('PATCH', body);
  });
  log_device(`[Platform Initialisation] [Device Event]: Added New Input Device (${deviceObjects[inputDeviceID1].name} | Obstruction Sensor)`);
}

// Configure GPIO Input - Garage Light Switch
inputDeviceID1 = deviceObjects.findIndex(device => device.uuid === '1111-2222-3333-0001');
if (inputDeviceID1 !== -1) {
  const inputDevice2 = new Gpio(6, {
    mode: Gpio.INPUT,
    pullUpDown: Gpio.PUD_UP, 
    alert: true
  });

  inputDevice2.glitchFilter(10000);

  inputDevice2.on('alert', (level) => {
    if (level === 1) {
      inputDeviceID1 = deviceObjects.findIndex(device => device.uuid === '1111-2222-3333-0001');
      updateCharacteristics = {'uuid': deviceObjects[inputDeviceID1].uuid, 'characteristics': {'On': !deviceObjects[inputDeviceID1].characteristics.On}};
      updateDevice('local', 'Local', updateCharacteristics, '');
    }
  });
  log_device(`[Platform Initialisation] [Device Event]: Added New Input Device (${deviceObjects[inputDeviceID1].name} | Switch)`);
}

// Configure GPIO Input - Security1 Light Switch
inputDeviceID1 = deviceObjects.findIndex(device => device.uuid === '1111-2222-3333-0002');
if (inputDeviceID1 !== -1) {
  const inputDevice2 = new Gpio(13, {
    mode: Gpio.INPUT,
    pullUpDown: Gpio.PUD_UP, 
    alert: true
  });

  inputDevice2.glitchFilter(10000);

  inputDevice2.on('alert', (level) => {
    if (level === 1) {
      inputDeviceID1 = deviceObjects.findIndex(device => device.uuid === '1111-2222-3333-0002');
      updateCharacteristics = {'uuid': deviceObjects[inputDeviceID1].uuid, 'characteristics': {'On': !deviceObjects[inputDeviceID1].characteristics.On}};
      updateDevice('local', 'Local', updateCharacteristics, '');
    }
  });
  log_device(`[Platform Initialisation] [Device Event]: Added New Input Device (${deviceObjects[inputDeviceID1].name} | Switch)`);
}

// Configure GPIO Input - Security2 Light Switch
inputDeviceID1 = deviceObjects.findIndex(device => device.uuid === '1111-2222-3333-0003');
if (inputDeviceID1 !== -1) {
  const inputDevice2 = new Gpio(19, {
    mode: Gpio.INPUT,
    pullUpDown: Gpio.PUD_UP, 
    alert: true
  });

  inputDevice2.glitchFilter(10000);

  inputDevice2.on('alert', (level) => {
    if (level === 1) {
      inputDeviceID1 = deviceObjects.findIndex(device => device.uuid === '1111-2222-3333-0003');
      updateCharacteristics = {'uuid': deviceObjects[inputDeviceID1].uuid, 'characteristics': {'On': !deviceObjects[inputDeviceID1].characteristics.On}};
      updateDevice('local', 'Local', updateCharacteristics, '');
    }
  });
  log_device(`[Platform Initialisation] [Device Event]: Added New Input Device (${deviceObjects[inputDeviceID1].name} | Switch)`);
}

// Configure GPIO Input - Temperature & Humidity Sensors
inputDeviceID1 = deviceObjects.findIndex(device => device['uuid'] === '1111-2222-3333-0006');
inputDeviceID2 = deviceObjects.findIndex(device => device['uuid'] === '1111-2222-3333-0007');

if (inputDeviceID1 !== -1 && inputDeviceID2 !== -1) {
  const sensor = dht(21,11);
  setInterval(() => {sensor.read();}, 2500);
  sensor.on('result', data => {
    inputDeviceID1 = deviceObjects.findIndex(device => device['uuid'] === '1111-2222-3333-0006');
	  deviceObjects[inputDeviceID1].characteristics.CurrentTemperature = data.temperature;
    inputDeviceID2 = deviceObjects.findIndex(device => device['uuid'] === '1111-2222-3333-0007');
	  deviceObjects[inputDeviceID2].characteristics.CurrentRelativeHumidity = data.humidity;
  });
  sensor.on('badChecksum', () => {
    inputDeviceID1 = deviceObjects.findIndex(device => device['uuid'] === '1111-2222-3333-0006');
	  log_device(`[Device Error]: (${deviceObjects[inputDeviceID1].name} | Checksum Failed)`);
    inputDeviceID2 = deviceObjects.findIndex(device => device['uuid'] === '1111-2222-3333-0007');
    log_device(`[Device Error]: (${deviceObjects[inputDeviceID2].name} | Checksum Failed)`);
  });
  log_device(`[Platform Initialisation] [Device Event]: Added New Input Device (${deviceObjects[inputDeviceID1].name} | Temperature Sensor)`);
  log_device(`[Platform Initialisation] [Device Event]: Added New Input Device (${deviceObjects[inputDeviceID2].name} | Humidity Sensor)`);
}

//
// Initialise devices and update HomeKit
//
for (const device of deviceObjects) {

  let characteristics = {};
  let updateCharacteristics ={};

  Object.assign(characteristics, device.characteristics);
  updateCharacteristics.uuid = device.uuid;
  updateCharacteristics.characteristics = characteristics;

  updateDevice('init', 'Platform Initialisation', updateCharacteristics, '');

}

//
// Start Platform API Server
//
webServer(deviceObjects);


//
// Initialise or Update Devices
//
async function updateDevice(updateRequester, log, req, res) {

const id = deviceObjects.findIndex(device => device['uuid'] === req.uuid);

if (id !== -1) {

  let body = {};

  if (deviceObjects[id].gpio !== undefined) {
    var on = (deviceObjects[id].gpio.activeHigh)? 1 : 0
    var off = (deviceObjects[id].gpio.activeHigh)? 0 : 1
  }

  if (deviceObjects[id].type === 'Garage Door Opener') {
    log_device(`[${log}] [Device Event]: (${deviceObjects[id].name} | TargetDoorState) set to (${garageDoorFriendlyState[req.characteristics.TargetDoorState]})`);
    if (deviceObjects[id].characteristics.ObstructionDetected === true) {
      body = {'uuid': `${deviceObjects[id].uuid}`, 'characteristics': {'CurrentDoorState': 4}};
      await remoteAPI('PATCH', body);
      log_device(`[${log}] [Device Event]: (${deviceObjects[id].name} | CurrentDoorState) is (Stopped)`);
    
    } else if (deviceObjects[id].characteristics.CurrentDoorState !== req.characteristics.TargetDoorState) {
                
      outputDevice[id].digitalWrite(on);
      await sleep(500);
      outputDevice[id].digitalWrite(off)

      deviceObjects[id].characteristics.CurrentDoorState = (req.characteristics.TargetDoorState === 1) ?  3 : 2;
      log_device(`[${log}] [Device Event]: (${deviceObjects[id].name} | CurrentDoorState) is (${garageDoorFriendlyState[deviceObjects[id].characteristics.CurrentDoorState]})`);

      let body = {'uuid': `${deviceObjects[id].uuid}`, 'characteristics': {'CurrentDoorState': `${deviceObjects[id].characteristics.CurrentDoorState}`, 'TargetDoorState': `${req.characteristics.TargetDoorState}`}};
      remoteAPI('PATCH', body);    
      await sleep(5000);
      deviceObjects[id].characteristics.CurrentDoorState = req.characteristics.TargetDoorState;
      body = {'uuid': `${deviceObjects[id].uuid}`, 'characteristics': {'CurrentDoorState': `${deviceObjects[id].characteristics.CurrentDoorState}`}};
      remoteAPI('PATCH', body);
      log_device(`[${log}] [Device Event]: (${deviceObjects[id].name} | CurrentDoorState) is (${garageDoorFriendlyState[deviceObjects[id].characteristics.CurrentDoorState]})`);
    } else if (updateRequester === 'init'){
      log_device(`[${log}] [Device Event]: (${deviceObjects[id].name} | CurrentDoorState) is (${garageDoorFriendlyState[deviceObjects[id].characteristics.CurrentDoorState]})`);
      body = {'uuid': `${deviceObjects[id].uuid}`, 'characteristics': {'CurrentDoorState': `${deviceObjects[id].characteristics.CurrentDoorState}`}};
      remoteAPI('PATCH', body);

    } else if (deviceObjects[id].characteristics.CurrentDoorState === deviceObjects[id].characteristics.TargetDoorState){
      log_device(`[${log}] [Device Error]: (${deviceObjects[id].name} | Garage door already at target state)`);
    }

  } else if (deviceObjects[id].type === 'Lightbulb') {

    for(var characteristic in req.characteristics) {
      if (characteristic !== 'uuid') {
        deviceObjects[id].characteristics[characteristic] = req.characteristics[characteristic]; 

        if (characteristic === 'On') {
          if (req.characteristics[characteristic] === false) {
            outputDevice[id].digitalWrite(off);
          } else {
            outputDevice[id].digitalWrite(on);
          };
        };

        if (characteristic === 'Brightness' && deviceObjects[id].characteristics.On === true) {
          outputDevice[id].pwmWrite(Math.round(deviceObjects[id].characteristics.Brightness * 2.55));
        };

        log_device(`[${log}] [Device Event]: (${deviceObjects[id].name} | ${characteristic}) set to (${deviceObjects[id].characteristics[characteristic]})`);

      };      
    };
  };

if ((updateRequester === 'init' || updateRequester === 'local') && deviceObjects[id].type === 'Lightbulb') {
  remoteAPI('PATCH', req);
} else if (updateRequester === 'api') {
    res.status(200).send(JSON.stringify(req));
} 
} else {
  if (updateRequester === 'api') {
    res.status(404).send('Device Not Found');
  }
  log_device(`[${log}] [Device Error]: (Device with id:${id} not found)`);
}
return
}

async function getAuthToken() {
    
  const url = `${config.jwtIssuer}oauth/token`;
    
  // send POST request
  const response = await fetch(url, {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: `{"client_id":"${config.jwtClientID}","client_secret":"${config.jwtClientSecret}","audience":"${config.jwtAudience}","grant_type":"client_credentials"}`,
  })
    .then(res => {
      if (res.ok) { // res.status >= 200 && res.status < 300
        log_device(`[Platform Info]: Remote API JWT Fetch Success: ${res.status}`);
        return res;
      } else {
        throw new Error(`${res.status}`);
      }
    })
    .then(res => res.json())
    .then(res => {
      if (res === undefined) {
        apiJWT.valid = false; 
      } else {
        apiJWT = {
          'access_token': res.access_token,
          'token_type': res.token_type,
          'expires': Date.now() + (res.expires_in * 1000),
          'scope': res.scope,
          'valid': true,
        }
      } 
    })
    .catch(error => log_device(`[Platform Error]: Remote API JWT Fetch Failure: ${error}`));
}

//
// Direct Connect API
//
function webServer(devices) {

  const WebApp = express();
  WebApp.use(express.json());
  const options = {};
  let error = false;
  const directConnectApiIP = config.directConnectApiIP || getIPAddress();

  // Secure API - jwt
  const checkJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `${config.jwtIssuer}.well-known/jwks.json`,
    }),

    audience: `${config.jwtAudience}`,
    issuer: `${config.jwtIssuer}`,
    algorithms: ['RS256'],
  });

  const checkScopes = jwtAuthz([ 'write:api' ]);
    

  // Initialise Direct Connect API
  if (!isNaN(config.directConnectApiPort) && config.directConnectApiPort >= 1024 && config.directConnectApiPort <= 63335){
    if (config.directConnectApiHttps === true){

     try {
        fs.accessSync (`${config.directConnectApiHttpsCertPath}`, fs.constants.R_OK);
        const cert = fs.readFileSync(`${config.directConnectApiHttpsCertPath}`);
        options['cert'] = cert;
     } catch (err) {
       log_device(`[Platform Error]: Direct Connect API HTTPS Certificate file does not exist or unreadable: ${err}`);
        error = true;
     }

      try {
        fs.accessSync (`${this.config.directConnectApiHttpsKeyPath}`, fs.constants.R_OK);
        const key = fs.readFileSync(`${this.config.directConnectApiHttpsKeyPath}`);
        options['key'] = key;
      } catch (err) {
       log_device(`[Platform Error]: Direct Connect API HTTPS Private Key file does not exist or unreadable: ${err}`);
        error = true;
      }

      if (!error) {
        https.createServer(options, WebApp).listen(config.directConnectApiPort, directConnectApiIP, () => {
         log_device(`[Platform Info]: Direct Connect API service started at https://${directConnectApiIP}:${config.directConnectApiPort}`);
        });
      } 
    } else {
      WebApp.listen(config.directConnectApiPort, directConnectApiIP, () => {
        log_device(`[Platform Info]: Direct Connect API service started at http://${directConnectApiIP}:${config.directConnectApiPort}`);
      });
    }

    if (!error) {   
    
    // Create Direct Connect API GET / PATCH API Routes

      WebApp.get( '/api/', (req, res) => {
      getRoute1(res);
      });

      if (config.jwt === true){

      WebApp.get( '/api/devices/', checkJwt, checkScopes,(req, res) => {
       getRoute2(res);
      });
      WebApp.get( '/api/devices/:uuid', checkJwt, checkScopes,(req, res) => {
        getRoute3(req.params.uuid, res);
      });  
      WebApp.get( '/api/devices/:uuid/characteristics/:characteristic', checkJwt, checkScopes,(req, res) => {
        getRoute4 (req.params.uuid, req.params.characteristic, res);
      });
      WebApp.patch('/api/devices/:uuid', checkJwt, checkScopes, async (req, res) => {
        patchRoute1 (req.params.uuid, req.body, res)
      });
    
    } else {

      WebApp.get( '/api/devices/', (req, res) => {
        getRoute2(res);
      });
      WebApp.get( '/api/devices/:uuid', (req, res) => {
        getRoute3(req.params.uuid, res);
      });  
      WebApp.get( '/api/devices/:uuid/characteristics/:characteristic', (req, res) => {
        getRoute4 (req.params.uuid, req.params.characteristic, res);
      });
      WebApp.patch('/api/devices/:uuid', async (req, res) => {
        patchRoute1 (req.params.uuid, req.body, res)
      });

    }
      function getRoute1 (res) {
        res.send(`${config.platformName} Platform Direct Connect API Running`);
        log_device(`[${config.remoteApiDisplayName}] [Platform Info]: GET Direct Connect API Status`);
      }

      function getRoute2 (res) {
        res.send(JSON.stringify(devices));
        log_device(`[${config.remoteApiDisplayName}] [Platform Info]: GET all device information and Direct Connect API Status`);
      }

      function getRoute3 (uuid, res) {
      
        const id = deviceObjects.findIndex(device => device.uuid === uuid);

        if (id !== -1) {
          res.send(`${JSON.stringify(devices[id])}`);
          log_device(`[${config.remoteApiDisplayName}] [Platform Info]: GET device information and status`);
        } else {
          res.status(404).send('Device Not Found');
          log_device(`[${config.remoteApiDisplayName}] [Platform Error]: (uuid | ${uuid}) Device Not Found`);
        }
      }

      function getRoute4 (uuid, characteristic, res) {

        const id = deviceObjects.findIndex(device => device['uuid'] === uuid);

        if (id !== -1) {
          if (devices[id].characteristics[characteristic] !== undefined) {
            respondCharacteristic = {};
            respondCharacteristic[characteristic] = devices[id].characteristics[characteristic];
            res.send(`${JSON.stringify(respondCharacteristic)}`);
            if (devices[id].type  === 'Garage Door Opener') {
              log_device(`[${config.remoteApiDisplayName}] [Device Info]: (${devices[id].name} | ${characteristic}) is (${garageDoorFriendlyState[devices[id].characteristics[characteristic]]})`);
            } else if (deviceTypes.includes(devices[id].type)) {
              log_device(`[${config.remoteApiDisplayName}] [Device Info]: (${devices[id].name} | ${characteristic}) is (${devices[id].characteristics[characteristic]})`);
            }
          } else {
            res.status(404).send('Characteristic Not Found');
            log_device(`[${config.remoteApiDisplayName}] [Platform Error]: (${devices[id].name} | ${characteristic}) Characteristic Not Found`);
          }
        } else {
          res.status(404).send('Device Not Found');
          log_device(`[${config.remoteApiDisplayName}] [Platform Error]: (id | ${id}) Device Not Found`);
        }
      }

      function patchRoute1 (uuid, body, res) {

        let updateCharacteristics ={};

        updateCharacteristics.uuid = uuid;
        updateCharacteristics.characteristics = body;
        updateDevice('api', config.remoteApiDisplayName, updateCharacteristics, res);
    }

      // Create Platform Error Handler
      WebApp.use((err, req, res, next) => {
        if (!err) {
          return next();
        } else {
          res.status(err.status).send(`API Service: ${err}`);
          log_device(`[${config.remoteApiDisplayName}] [Platform Error]: ${err}`);
        }
      });
      return;
    }
  } else {
  log_device(`[Platform Error]: Invalid Direct Connect API Port - Should be between 1024 and 65535`);
  }
}

//
// Remote API
//
async function remoteAPI (method, body) {

  if (validURL(config.remoteApiURL)) {

    if (config.jwt && (apiJWT.valid === false || apiJWT.expires <= Date.now() + 60000)) {
      await getAuthToken(); 
    }
    if (apiJWT.valid === false && config.jwt === true) {
      log_device('No valid Remote API JWT to discover devices');

      const error = {'errno': 'No valid Remote API JWT to discover devices'};
      return error;

    } else {

      const url = (config.remoteApiURL.endsWith('/')) ? config.remoteApiURL : config.remoteApiURL + '/';
      const jwtHeader = {'content-type': 'application/json', 'authorization': `${apiJWT.token_type} ${apiJWT.access_token}`};
      const headers = (config.jwt) ? jwtHeader : {'content-type': 'application/json'};

      let options = {};

      if (config.remoteApiRejectInvalidCert === false && url.toLowerCase().includes('https')) {

        const agent = new https.Agent({
         rejectUnauthorized: false,
       });
        options = {
          method: method,
          headers: headers,
          agent,
        };
      } else {
        options = {
          method: method,
          headers: headers,
        };
      }

      if (method === 'POST' || method === 'PATCH') {
        options['body'] = JSON.stringify(body);
      }
      
      // send Method request
      const response = await fetch(url, options)
        .then(res => {
          if (res.ok) { // res.status >= 200 && res.status < 300
            return res;
          } else {
            throw new Error(`${res.status}`);
          }
        })
        .then(res => res.json())
        .then(res => {
         return res;
        })
        .catch(error => {
         log_device(`Remote API ${method} Failure: ${error}`);
          return error;
        });
      return response;
  } 
} else {
    log_device(`[Platform Error]: Invalid Remote API URL - ${config.remoteApiURL}`);
    const error = {'errno': `Invalid Remote API URL - ${config.remoteApiURL}`}; 
    return error;
  }
}

//
// Logging
//
function log_device(output) {
  var now = dayjs();
  console.log(`[${now.format('DD/MM/YYYY, HH:mm:ss')}] [${config.platformName}] ${output}`);
}

//
// Sleep
//
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

//
// Get IPv4 Address
//
function getIPAddress() {
  const interfaces = os.networkInterfaces();
  for (const deviceName in interfaces) {
    const iface = interfaces[deviceName];
    for (let i = 0; i < iface.length; i++) {
      const alias = iface[i];
      if (alias.family === 'IPv4' && alias.address !== '127.0.0.1' && !alias.internal) {
        return alias.address;
      }
    }
  }
  return '0.0.0.0';
}

//
// Validate URL
//
function validURL(str) {
  const pattern = new RegExp(
    '^(https?:\\/\\/)'+  //scheme
    '((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|'+  // IPv4
    '(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\\-]*[A-Za-z0-9]))'+  // hostname
    '(:([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))'+  // port
    '?(\\/[-a-zA-Z\\d%_.~+]*)*$');  // path
  return !!pattern.test(str);
}

//
// Validate UUID
//
function validUUID(str) {
  const pattern = new RegExp('([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{4}');  // aaaa-bbbb-cccc-dddd
  return !!pattern.test(str);
}

