# Raspberry-Garage

This is a Homebridge dynamic platform plugin which exposes remote light and garage door accessories through a remote API.  

### Features:

* Accessories are dynamically created when the platform is started
* Control remote accessories through API
* Support of dynamic updates from accessories to support garage door state monitoring and local garage door / light activation.


### Optional Features:

* HTTPS
* JSON Web Token Security (Auth0 Tested)
* Support of Self-Signed Certificate


## Install

The plugin can be installed by running the command:  sudo npm -g ??????


## Configuration

The configuration of the platform can be done via the .env file.

```
{
            PLATFORM_NAME = '<Platform Name>'
            REMOTEAPI_DISPLAYNAME = '<Remote API Display Name>'
            REMOTEAPI_URL = 'https://host:8001/API-Endpoint/'
            REMOTEAPI_REJECTINVALIDCERT = 'true'
            DIRECTCONNECTAPI_IPV4 = ''
            DIRECTCONNECTAPI_PORT = 8001
            DIRECTCONNECTAPI_HTTPS = ''
            DIRECTCONNECTAPI_HTTPSCERTPATH = '/<certificate path>/<certificate>'
            DIRECTCONNECTAPI_HTTPSKEYPATH = '"/<private key path>/<private key>'
            JWT = ''
            JWT_AUDIENCE = 'https://JWT-API-Application/'
            JWT_ISSUER = 'https://JWT-Issuer/'
            JWT_CLIENTID = '<JWT Client ID>'
            JWT_CLIENTSECRET = '<JWT Client Secret>'
        }

```

The configuration of the devices is done within the index.js file and editing the defaultDeviceObjects array.

```
const defaultDeviceObjects = [
  {name: 'GarageDoor', uuid: '1111-2222-3333-0000', type: 'Garage Door Opener', characteristics: {CurrentDoorState: 1, TargetDoorState: 1, ObstructionDetected: false}, gpio: {activeHigh: false, output: 23}},
  {name: 'GarageLight', uuid: '1111-2222-3333-0001', type: 'Lightbulb', characteristics: {On: false}, gpio: {activeHigh: false, output: 24}},
  {name: 'SecurityLight1', uuid: '1111-2222-3333-0002', type: 'Lightbulb', characteristics: {On: false, Brightness: 100, ColorTemperature: 140, Hue: 180, Saturation: 50}, gpio: {activeHigh: true, output: 25}},
  {name: 'SecurityLight2', uuid: '1111-2222-3333-0003', type: 'Lightbulb', characteristics: {On: false, Brightness: 100}, gpio: {activeHigh: true, output: 22}},
  {name: 'GarageTempSensor', uuid: '1111-2222-3333-0006', type: 'Temperature Sensor', characteristics: {StatusActive: true, CurrentTemperature: 0}},
  {name: 'GarageHumiditySensor', uuid: '1111-2222-3333-0007', type: 'Humidity Sensor', characteristics: {StatusActive: true, CurrentRelativeHumidity: 0}},
];

```
## DIRECT CONNECT API

* GET /API/ - Shows API state
* GET /API/DEVICES/ - Shows all devices and their current status and characteristics
* GET /API/DEVICES/{uuid:} - Shows current status and characteristics of device with UUID = {uuid:}
* GET /API/DEVICES/{uuid:}/CHARACTERISTICS/ - Shows characteristics of device with UUID = {uuid:}
* GET /API/DEVICES/{uuid:}/CHARACTERISTICS/{char:}/ - Shows characteristic {char:} of device with UUID = {uuid:}

* PATCH /API/DEVICES/{uuid:} - Updates status and characteristics of device with UUID = {uuid:}
* PATCH /API/DEVICES/{uuid:}/CHARACTERISTICS/ - Updates characteristics of device with UUID = {uuid:}
* PATCH /API/DEVICES/{uuid:}/CHARACTERISTICS/{char:}/ - Updates characteristic {char:} of device with UUID = {uuid:}


## REMOTE API

* GET / - Shows all devices configured on this Homebridge 

* PATCH /API/{uuid:}{char:} - Updates characteristic of accessory using the UUID field as the index


