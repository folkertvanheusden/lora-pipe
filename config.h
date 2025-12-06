// (C) 2025 by Folkert van Heusden
// released under MIT license
#include "lora.h"


// on what pins is the SX1272 connected?
// this uses wiringpi numbers

#define SPI_BUS     1  // on older PIs this is probably 0
#define SPI_CHANNEL 0
#define SS_PIN      27  // CE2, GPIO16
#define DIO0_PIN    21  // GPIO5, interrupt
#define RST_PIN     6  // GPIO25


// LoRa settings
// these are for meshcore in NL

#define LR_FREQ		869618000
#define LR_TX_POWER	20
#define LR_SF           LoRa::SF_8
#define LR_BW		LoRa::BW_62k5
#define LR_CR           LoRa::CR_48
#define LR_SYNC_WORD	0x12
#define LR_HEADER	LoRa::HM_EXPLICIT
#define LR_PREAMBLE_LEN	16


// MQTT settings
// note that you need to swap FROM/TO on the other side

#define MQTT_HOST	"vps001.vanheusden.com"  // please use your own mqtt server
#define MQTT_PORT	1883
#define MQTT_TOPIC_FROM	"meshcore/fromwageningen"
#define MQTT_TOPIC_TO	"meshcore/towageningen"


// misceallaneous settings
#define HASH_TIMEOUT        1500  // ms
#define HASH_PURGE_INTERVAL 5  // seconds
#define DECODE_MESHCORE     1  // set to 0 when tunneling a different protocol
