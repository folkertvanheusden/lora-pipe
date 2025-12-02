// (C) 2025 by Folkert van Heusden
// released under MIT license
#include <cstdio>
#include <cstdlib>
#include <mosquitto.h>

#include "config.h"
#include "lora.h"
#include "packet.h"


static void on_message(mosquitto *, void *p, const mosquitto_message *msg, const mosquitto_property *)
{
	printf("from mqtt: %d\n", msg->payloadlen);

	LoRaPacket pkt(reinterpret_cast<unsigned char *>(msg->payload), msg->payloadlen);
	LoRa *l = reinterpret_cast<LoRa *>(p);
	size_t tx_size = l->transmitPacket(&pkt);
	printf("transmitted: %zu\n", tx_size);
}

static void on_connect(mosquitto *mqtt, void *p, int)
{
	printf("Subscribe to mqtt\n");
	if (int rc = mosquitto_subscribe(mqtt, nullptr, MQTT_TOPIC_FROM, 0); rc != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "Subscribe error: %s\n", mosquitto_strerror(rc));
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	printf("Setting up LoRa\n");
	LoRa lora(SPI_BUS, SPI_CHANNEL, SS_PIN, DIO0_PIN, RST_PIN);
	if (lora.begin() == false) {
		fprintf(stderr, "SX1272 radio not detected\n");
		return 1;
	}

	printf("LoRa setup successful: chipset version 0x%02x\n", lora.version());
	printf("Configuring radio\n");
	lora.setFrequency(LR_FREQ)
		->setTXPower(LR_TX_POWER)
		->setSpreadFactor(LR_SF)
		->setBandwidth(LR_BW)
		->setCodingRate(LR_CR)
		->setSyncWord(LR_SYNC_WORD)
		->setHeaderMode(LR_HEADER)
		->enableCRC()
		->setPreambleLength(LR_PREAMBLE_LEN);
	printf("  TX power     : %d dB\n", lora.getTXPower());
	printf("  Frequency    : %d Hz\n", lora.getFrequency());
	printf("  Spread factor: %d\n", lora.getSpreadFactor());
	printf("  Bandwidth    : %d Hz\n", lora.bw[lora.getBandwidth()]);
	printf("  Coding Rate  : 4/%d\n", lora.getCodingRate() + 4);
	printf("  Sync word    : 0x%02x\n", lora.getSyncWord());
	printf("  Header mode  : %s\n", lora.getHeaderMode() == LoRa::HM_IMPLICIT ? "Implicit" : "Explicit");

	mosquitto *mqtt = mosquitto_new(nullptr, true, &lora);
	if (int rc = mosquitto_connect(mqtt, MQTT_HOST, MQTT_PORT, 30); rc != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "Failed to connect to MQTT host: %s\n", mosquitto_strerror(rc));
		return 1;
	}
        mosquitto_connect_callback_set(mqtt, on_connect);
        mosquitto_message_v5_callback_set(mqtt, on_message);

	for(;;) {
		LoRaPacket p = lora.receivePacket(100);
		if (p.payloadLength()) {
			printf("Received packet\n");
			printf("  Bytes   : %d\n", p.payloadLength());
			printf("  RSSI    : %d dBm\n", p.getPacketRSSI());
			printf("  SNR     : %.1f dB\n", p.getSNR());
			printf("  Freq err: %d Hz\n", p.getFreqErr());
			printf("  Payload : \n");
			auto *pnt = p.getPayload();
			for(auto i=0; i<p.payloadLength(); i++)
				printf("%c", pnt[i] > 32 && pnt[i] < 127 ? pnt[i] : '.');
			printf("\n\n");

			if (int rc = mosquitto_publish(mqtt, nullptr, MQTT_TOPIC_TO, p.payloadLength(), p.getPayload(), 0, false); rc != MOSQ_ERR_SUCCESS) {
				fprintf(stderr, "Publish error: %s\n", mosquitto_strerror(rc));
				return 1;
			}
		}
		else {
			if (int rc = mosquitto_loop(mqtt, 1, 1); rc != MOSQ_ERR_SUCCESS) {
				fprintf(stderr, "Failed to process MQTT connection: %s\n", mosquitto_strerror(rc));
				return 1;
			}
		}
	}

	return 0;
}
