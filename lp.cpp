// (C) 2025 by Folkert van Heusden
// released under MIT license
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <mosquitto.h>

#include "config.h"
#include "libLoRaPi/src/include/lora.h"
#include "libLoRaPi/src/include/packet.h"
extern "C" {
#include "meshcore-c/crypto/aes.h"
#include "meshcore-c/crypto/hmac_sha256.h"
#include "meshcore-c/crypto/sha256.h"
#include "meshcore-c/meshcore/packet.h"
#include "meshcore-c/meshcore/payload/advert.h"
#include "meshcore-c/meshcore/payload/grp_txt.h"
}

// from https://github.com/Nicolai-Electronics/meshcore-c/ 
uint8_t key[16] = {0x8b, 0x33, 0x87, 0xe9, 0xc5, 0xcd, 0xea, 0x6a, 0xc9, 0xe5, 0xed, 0xba, 0xa1, 0x15, 0xcd, 0x72};

const char* type_to_string(meshcore_payload_type_t type) {
    switch (type) {
        case MESHCORE_PAYLOAD_TYPE_REQ:
            return "Request";
        case MESHCORE_PAYLOAD_TYPE_RESPONSE:
            return "Response";
        case MESHCORE_PAYLOAD_TYPE_TXT_MSG:
            return "Plain text message";
        case MESHCORE_PAYLOAD_TYPE_ACK:
            return "Acknowledgement";
        case MESHCORE_PAYLOAD_TYPE_ADVERT:
            return "Node advertisement";
        case MESHCORE_PAYLOAD_TYPE_GRP_TXT:
            return "Group text message (unverified)";
        case MESHCORE_PAYLOAD_TYPE_GRP_DATA:
            return "Group data message (unverified)";
        case MESHCORE_PAYLOAD_TYPE_ANON_REQ:
            return "Anonymous request";
        case MESHCORE_PAYLOAD_TYPE_PATH:
            return "Returned path";
        case MESHCORE_PAYLOAD_TYPE_TRACE:
            return "Trace";
        case MESHCORE_PAYLOAD_TYPE_MULTIPART:
            return "Multipart";
        case MESHCORE_PAYLOAD_TYPE_RAW_CUSTOM:
            return "Custom raw";
        default:
            return "UNKNOWN";
    }
}

const char* route_to_string(meshcore_route_type_t route) {
    switch (route) {
        case MESHCORE_ROUTE_TYPE_TRANSPORT_FLOOD:
            return "Transport flood";
        case MESHCORE_ROUTE_TYPE_FLOOD:
            return "Flood";
        case MESHCORE_ROUTE_TYPE_DIRECT:
            return "Direct";
        case MESHCORE_ROUTE_TYPE_TRANSPORT_DIRECT:
            return "Transport direct";
        default:
            return "Unknown";
    }
}

const char* role_to_string(meshcore_device_role_t role) {
    switch (role) {
        case MESHCORE_DEVICE_ROLE_CHAT_NODE:
            return "Chat Node";
        case MESHCORE_DEVICE_ROLE_REPEATER:
            return "Repeater";
        case MESHCORE_DEVICE_ROLE_ROOM_SERVER:
            return "Room Server";
        case MESHCORE_DEVICE_ROLE_SENSOR:
            return "Sensor";
        default:
            return "Unknown";
    }
}

static void dump(uint8_t *pnt, size_t len)
{
    meshcore_message_t message;
    if (meshcore_deserialize(pnt, len, &message) >= 0) {
        printf("Decoded message:\n");
        printf("Type: %s [%d]\n", type_to_string(message.type), message.type);
        printf("Route: %s [%d]\n", route_to_string(message.route), message.route);
        printf("Version: %d\n", message.version);
        printf("Path Length: %d\n", message.path_length);
        if (message.path_length > 0) {
            printf("Path: ");
            for (unsigned int i = 0; i < message.path_length; i++) {
                printf("0x%02x, ", message.path[i]);
            }
            printf("\n");
        }
        printf("Payload Length: %d\n", message.payload_length);
        if (message.payload_length > 0) {
            printf("Payload [%d]: ", message.payload_length);
            for (unsigned int i = 0; i < message.payload_length; i++) {
                printf("%02X", message.payload[i]);
            }
            printf("\n");
        }

        if (message.type == MESHCORE_PAYLOAD_TYPE_ADVERT) {
            meshcore_advert_t advert;
            if (meshcore_advert_deserialize(message.payload, message.payload_length, &advert) >= 0) {
                printf("Decoded node advertisement:\n");
                printf("Public Key: ");
                for (unsigned int i = 0; i < MESHCORE_PUB_KEY_SIZE; i++) {
                    printf("%02X", advert.pub_key[i]);
                }
                printf("\n");
                printf("Timestamp: %u\n", advert.timestamp);
                printf("Signature: ");
                for (unsigned int i = 0; i < MESHCORE_SIGNATURE_SIZE; i++) {
                    printf("%02X", advert.signature[i]);
                }
                printf("\n");
                printf("Role: %s\n", role_to_string(advert.role));
                if (advert.position_valid) {
                    printf("Position: lat=%d, lon=%d\n", advert.position_lat, advert.position_lon);
                } else {
                    printf("Position: (not available)\n");
                }
                if (advert.extra1_valid) {
                    printf("Extra1: %u\n", advert.extra1);
                } else {
                    printf("Extra1: (not available)\n");
                }
                if (advert.extra2_valid) {
                    printf("Extra2: %u\n", advert.extra2);
                } else {
                    printf("Extra2: (not available)\n");
                }
                if (advert.name_valid) {
                    printf("Name: %s\n", advert.name);
                } else {
                    printf("Name: (not available)\n");
                }

                if (meshcore_advert_serialize(&advert, message.payload, &message.payload_length) < 0) {
                    printf("Failed to serialize node advertisement payload.\n");
                    return;
                }

            } else {
                printf("Failed to decode node advertisement payload.\n");
                return;
            }
        } else if (message.type == MESHCORE_PAYLOAD_TYPE_GRP_TXT) {
            meshcore_grp_txt_t grp_txt;
            if (meshcore_grp_txt_deserialize(message.payload, message.payload_length, &grp_txt) >= 0) {
                printf("Decoded group text message:\n");
                printf("Channel Hash: %02X\n", grp_txt.channel_hash);
                printf("Data Length: %d\n", grp_txt.data_length);
                printf("Received MAC: ", grp_txt.data_length);

                for (unsigned int i = 0; i < MESHCORE_CIPHER_MAC_SIZE; i++) {
                    printf("%02X", grp_txt.mac[i]);
                }
                printf("\n");

                printf("Data [%d]: ", grp_txt.data_length);
                for (unsigned int i = 0; i < grp_txt.data_length; i++) {
                    printf("%02X", grp_txt.data[i]);
                }
                printf("\n");

                printf("Text: ", grp_txt.data_length);
                for (unsigned int i = 0; i < grp_txt.data_length; i++) {
                    printf("%c", grp_txt.data[i] > 32 && grp_txt.data[i] < 127 ? grp_txt.data[i] : '.');
                }
                printf("\n");

                // TO-DO: all of this MAC verification and decryption should be moved somewhere else

                uint8_t out[128];
                size_t  out_len =
                    hmac_sha256(key, sizeof(key), grp_txt.data, grp_txt.data_length, out, MESHCORE_CIPHER_MAC_SIZE);

                printf("Calculated MAC [%d]: ", out_len);
                for (unsigned int i = 0; i < out_len; i++) {
                    printf("%02X", out[i]);
                }
                printf("\n");

                if (memcmp(out, grp_txt.mac, MESHCORE_CIPHER_MAC_SIZE) == 0) {
                    printf("MAC verification: SUCCESS\n");

                    // Copy encrypted data to buffer for decryption, AES works in-place
                    grp_txt.decrypted.data_length = grp_txt.data_length;
                    memcpy(grp_txt.decrypted.data, grp_txt.data, grp_txt.data_length);

                    struct AES_ctx ctx;
                    AES_init_ctx(&ctx, key);
                    for (uint8_t i = 0; i < (grp_txt.decrypted.data_length / 16); i++) {
                        AES_ECB_decrypt(&ctx, &grp_txt.decrypted.data[i * 16]);
                    }

                    printf("Data [%d]: ", grp_txt.decrypted.data_length);
                    for (unsigned int i = 0; i < grp_txt.decrypted.data_length; i++) {
                        printf("%02X", grp_txt.decrypted.data[i]);
                    }
                    printf("\n");

                    uint8_t position = 0;
                    memcpy(&grp_txt.decrypted.timestamp, grp_txt.decrypted.data, sizeof(uint32_t));
                    position                            += sizeof(uint32_t);
                    grp_txt.decrypted.text_type          = grp_txt.decrypted.data[position];
                    position                            += sizeof(uint8_t);
                    size_t text_length                   = grp_txt.decrypted.data_length - position;
                    grp_txt.decrypted.text               = (char*)&grp_txt.decrypted.data[position];
                    grp_txt.decrypted.text[text_length]  = '\0';

                    printf("Timestamp: %" PRIu32 "\n", grp_txt.decrypted.timestamp);
                    printf("Text Type: %u\n", grp_txt.decrypted.text_type);
                    printf("Message: '%s'\n", grp_txt.decrypted.text);

                } else {
                    printf("MAC verification: FAILURE\n");
                }

                if (meshcore_grp_txt_serialize(&grp_txt, message.payload, &message.payload_length) < 0) {
                    printf("Failed to serialize group text message payload.\n");
                    return;
                }

            } else {
                printf("Failed to decode group text message payload.\n");
                return;
            }
        }
    } else {
        printf("Failed to decode message.\n");
        return;
    }
}
/////////////////////////////////////////////////////////

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
		LoRaPacket p = lora.receivePacket(50);
		if (p.payloadLength()) {
			printf("Received packet\n");
			printf("  Bytes   : %d\n", p.payloadLength());
			printf("  RSSI    : %d dBm\n", p.getPacketRSSI());
			printf("  SNR     : %.1f dB\n", p.getSNR());
			printf("  Freq err: %d Hz\n", p.getFreqErr());
			printf("  Payload : \n");
			dump(p.getPayload(), p.payloadLength());
			printf("\n");

			if (int rc = mosquitto_publish(mqtt, nullptr, MQTT_TOPIC_TO, p.payloadLength(), p.getPayload(), 0, false); rc != MOSQ_ERR_SUCCESS) {
				fprintf(stderr, "Publish error: %s\n", mosquitto_strerror(rc));
				return 1;
			}
		}
		else {
			if (int rc = mosquitto_loop(mqtt, 0, 1); rc != MOSQ_ERR_SUCCESS) {
				fprintf(stderr, "Failed to process MQTT connection: %s\n", mosquitto_strerror(rc));
				return 1;
			}
		}
	}

	return 0;
}
