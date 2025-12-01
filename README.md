what it is
----------
This program allows you to bridge a LoRa setup over a longer distance by using MQTT over e.g. an IP network.
Use-case: extending the reach of MeshCore by bridging it over HAM-Net.


## required

* an SX1272 radio connected to the SPI bus of a Raspberry Pi (tested with a Pi3 and a Pi5)
* WiringPi: https://github.com/WiringPi/WiringPi
* libmosquitto-dev


## configuration

* for it to work you must adjust config.h



-- written by Folkert van Heusden <folkert@vanheusden.com>
