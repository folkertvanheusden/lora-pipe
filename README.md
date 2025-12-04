what it is
----------
This program allows you to bridge a LoRa setup over a longer distance by using MQTT over e.g. an IP network.
Use-case: extending the reach of MeshCore by bridging it over HAM-Net.
It works transparently: you only need to know LoRa settings and then it should be able to bridge any protocol.


## required

* an SX1272 radio connected to the SPI bus of a Raspberry Pi (tested with a Pi3 and a Pi5, e.g. https://www.adafruit.com/product/3072 )
* WiringPi: https://github.com/WiringPi/WiringPi
* libmosquitto-dev
* libncurses-dev
* cmake


## configuration

* For it to work you must adjust config.h


## usage

* After configuring by adapting config.h and building the program (`cmake -B build && make -j -C build`) you can run the program from the commandline or (preferably) in a systemd service. the program will terminate if it detects any problems.


## license

MIT

Note that linked in to this project are:
* https://github.com/Nicolai-Electronics/meshcore-c/
* https://github.com/simoncocking/libLoRaPi



-- written by Folkert van Heusden <folkert@vanheusden.com>
