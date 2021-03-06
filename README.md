# Raspberry-Garage

This is a platform which controls devices such garage door opener, lights, temperature and humidity sensors via local switches or through the Direct Connect API.  

### Features:

* Control and monitor status of devices through API
* Homebridge dynamic platform plugin compatible (https://github.com/IanW6374/homebridge-dynamicAPI)


### Optional Features:

* HTTPS
* JSON Web Token Security (Auth0 Tested)
* Support of Self-Signed Certificate


## Install

The platform can be installed by running the command:-

```
sudo npm -g raspberry-garage
```


## Run as a Service

Create file raspberry-service.service in /etc/systemd/system/

```
[Unit]
Description=Raspberry-Garage Application
After=network.target
[Service]
Type=simple
User=pi
ExecStart=sudo raspberry-garage
WorkingDirectory=/home/pi/raspberry-garage
Restart=always
[Install]
WantedBy=multi-user.target
```

To initiate service:-

```
sudo systemctl daemon-reload
sudo systemctl start raspberry-garage (Start the service)
sudo systemctl enable raspberry-garage (Run service at start-up)
```

Other service related commands: -

```
sudo systemctl stop raspberry-garage  (Stop the service)
sudo systemctl status raspberry-garage (Status of service)
journalctl -u raspberry-garage.service (Show logs relating to service)

```


## Configuration

The platform configuration options can be modified by editing the .env file (Must be saved in working directory)

```
{
            PLATFORM_NAME = '<Platform Name>'
            REMOTEAPI_DISPLAYNAME = '<Remote API Display Name>'
            REMOTEAPI_URL = 'https://host:8001/API-Endpoint/'
            REMOTEAPI_REJECTINVALIDCERT = 'true'
            DIRECTCONNECTAPI_IPV4 = ''
            DIRECTCONNECTAPI_PORT = 8001
            DIRECTCONNECTAPI_HTTPS = 'false'
            DIRECTCONNECTAPI_HTTPSCERTPATH = '/<certificate path>/<certificate>'
            DIRECTCONNECTAPI_HTTPSKEYPATH = '/<private key path>/<private key>'
            JWT = 'false'
            JWT_AUDIENCE = 'https://JWT-API-Application/'
            JWT_ISSUER = 'https://JWT-Issuer/'
            JWT_CLIENTID = '<JWT Client ID>'
            JWT_CLIENTSECRET = '<JWT Client Secret>'
}

```

The device configuration is contained within the index.js file and can be modified by editing the defaultDeviceObjects object.

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

The configuration of the GPIO startup state for individual pins can be changed by editing the "/boot/config.txt" file (Required for the 8 Relay Module)

```

gpio=23,24=op,dh

```



## DIRECT CONNECT API

* GET /API/ - Shows API state
* GET /API/DEVICES/ - Shows all devices and their current status and characteristics
* GET /API/DEVICES/{uuid:}/ - Shows current status and characteristics of device with UUID = {uuid:}
* GET /API/DEVICES/{uuid:}/CHARACTERISTICS/ - Shows characteristics of device with UUID = {uuid:}
* GET /API/DEVICES/{uuid:}/CHARACTERISTICS/{char:}/ - Shows characteristic {char:} of device with UUID = {uuid:}

* PATCH /API/DEVICES/{uuid:}/ - Updates status and characteristics of device with UUID = {uuid:}
* PATCH /API/DEVICES/{uuid:}/CHARACTERISTICS/ - Updates characteristics of device with UUID = {uuid:}
* PATCH /API/DEVICES/{uuid:}/CHARACTERISTICS/{char:}/ - Updates characteristic {char:} of device with UUID = {uuid:}


## REMOTE API

* GET / - Shows all devices configured on the Homebridge plugin.

* PATCH /API/{uuid:}/ - Updates characteristic of accessory using the UUID field as the index



## Test Circuit

The cicuit below shows the circuit configuration for the default devices included within the index.js 

<img width="1282" alt="image" src="https://user-images.githubusercontent.com/65277075/117337337-28097280-ae95-11eb-9906-ded9d46fa6c0.png">


## Uninstall

The platform can be uninstalled by running the commands:-

```
sudo systemctl stop raspberry-garage
sudo systemctl disable raspberry-garage
rm /etc/systemd/system/raspberry-service.service
sudo systemctl daemon-reload

sudo npm uninstall -g raspberry-garage
```
