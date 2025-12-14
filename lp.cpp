// (C) 2025 by Folkert van Heusden
// released under MIT license
#include <algorithm>
#include <atomic>
#include <cinttypes>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <locale.h>
#include <map>
#include <mosquitto.h>
#include <mutex>
#include <ncurses.h>
#include <queue>
#include <thread>
#include <unistd.h>
#include <sys/time.h>

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

#if DECODE_MESHCORE == 1
// from https://github.com/Nicolai-Electronics/meshcore-c/ 
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

void dump(uint8_t *pnt, size_t len, WINDOW *log_win)
{
	meshcore_message_t message;
	if (meshcore_deserialize(pnt, len, &message) >= 0) {
		wprintw(log_win, "type: %s, route: %s, pathlen: %d, version: %d\n", type_to_string(message.type), route_to_string(message.route), message.path_length, message.version);

		bool emitted_text = false;

		if (message.type == MESHCORE_PAYLOAD_TYPE_ADVERT) {
			meshcore_advert_t advert;
			if (meshcore_advert_deserialize(message.payload, message.payload_length, &advert) >= 0) {
				wprintw(log_win, "node advertisement, role: %s, timestamp: %u\n", role_to_string(advert.role), advert.timestamp);
				if (advert.position_valid)
					wprintw(log_win, "Position: lat=%d, lon=%d\n", advert.position_lat, advert.position_lon);
				if (advert.name_valid)
					wprintw(log_win, "Name: %s\n", advert.name);
			}
			else {
				wprintw(log_win, "Failed to decode node advertisement payload\n");
				return;
			}
		}
		else if (message.type == MESHCORE_PAYLOAD_TYPE_GRP_TXT) {
			uint8_t key[16] = {0x8b, 0x33, 0x87, 0xe9, 0xc5, 0xcd, 0xea, 0x6a, 0xc9, 0xe5, 0xed, 0xba, 0xa1, 0x15, 0xcd, 0x72};
			meshcore_grp_txt_t grp_txt;
			if (meshcore_grp_txt_deserialize(message.payload, message.payload_length, &grp_txt) >= 0) {
				// TO-DO: all of this MAC verification and decryption should be moved somewhere else

				uint8_t out[128];
				size_t  out_len =
					hmac_sha256(key, sizeof(key), grp_txt.data, grp_txt.data_length, out, MESHCORE_CIPHER_MAC_SIZE);

				if (memcmp(out, grp_txt.mac, MESHCORE_CIPHER_MAC_SIZE) == 0) {
					// Copy encrypted data to buffer for decryption, AES works in-place
					grp_txt.decrypted.data_length = grp_txt.data_length;
					memcpy(grp_txt.decrypted.data, grp_txt.data, grp_txt.data_length);

					struct AES_ctx ctx;
					AES_init_ctx(&ctx, key);
					for (uint8_t i = 0; i < (grp_txt.decrypted.data_length / 16); i++) {
						AES_ECB_decrypt(&ctx, &grp_txt.decrypted.data[i * 16]);
					}

					uint8_t position = 0;
					memcpy(&grp_txt.decrypted.timestamp, grp_txt.decrypted.data, sizeof(uint32_t));
					position                            += sizeof(uint32_t);
					grp_txt.decrypted.text_type          = grp_txt.decrypted.data[position];
					position                            += sizeof(uint8_t);
					size_t text_length                   = grp_txt.decrypted.data_length - position;
					grp_txt.decrypted.text               = (char*)&grp_txt.decrypted.data[position];
					grp_txt.decrypted.text[text_length]  = '\0';

					wprintw(log_win, "Timestamp: %" PRIu32 "\n", grp_txt.decrypted.timestamp);
					wprintw(log_win, "Text Type: %u\n", grp_txt.decrypted.text_type);
					wprintw(log_win, "Message: '%s'\n", grp_txt.decrypted.text);

					emitted_text = true;
				}
			}
		}

		if (emitted_text == false && message.payload_length > 0) {
			wprintw(log_win, "payload [%d]: ", message.payload_length);
			for(auto i=0; i<message.payload_length; i++)
				wprintw(log_win, "%c", message.payload[i] > 32 && message.payload[i] < 127 ? message.payload[i] : '.');
			wprintw(log_win, "\n");
		}
	}
	else {
		wprintw(log_win, "Failed to decode message\n");
	}
}
#else
void dump(uint8_t *pnt, size_t len, WINDOW *log_win)
{
}
#endif

std::mutex ncurses_lock;

struct pars {
	WINDOW *pw;
	LoRa   *lora;
};

class ts_queue
{
private:
	std::condition_variable cv;
	std::mutex              lock;
	std::queue<std::pair<uint8_t *, size_t> > data;

public:
	ts_queue() {
	}

	auto pop() {
		std::unique_lock<std::mutex> lck(lock);
		while(data.empty())
			cv.wait(lck);
		auto rc = data.front();
		data.pop();
		return rc;
	}

	void push(uint8_t *p, size_t l) {
		std::unique_lock<std::mutex> lck(lock);
		data.push({ p, l });
		cv.notify_one();
	}

	bool empty() {
		std::unique_lock<std::mutex> lck(lock);
		return data.empty();
	}
};

uint64_t get_ms()
{
	timeval tv { };
	gettimeofday(&tv, nullptr);
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

uint64_t running_since = get_ms();
ts_queue mqtt_to_rf;
ts_queue rf_to_mqtt;

// TODO keep track of send latency
std::atomic_uint32_t mqtt_msgs = 0;
std::atomic_uint32_t rf_msgs   = 0;

std::map<uint32_t, uint64_t> hashes;
std::mutex                   hash_lock;
std::atomic_uint32_t         hash_dedup_count = 0;

bool register_hash(const uint32_t h)
{
	std::unique_lock<std::mutex> lck(hash_lock);
	return hashes.insert({ h, get_ms() }).second;
}

void purge_hashes()
{
	uint64_t now = get_ms();

	std::unique_lock<std::mutex> lck(hash_lock);

	auto it = hashes.begin();
	while(it != hashes.end()) {
		if (now - it->second >= HASH_TIMEOUT)
			it = hashes.erase(it);
		else
			it++;
	}
}

// hash function
uint32_t adler32(const void *buf, size_t buflength)
{
	const uint8_t *buffer = reinterpret_cast<const uint8_t *>(buf);

	uint32_t s1 = 1;
	uint32_t s2 = 0;

	for (size_t n = 0; n < buflength; n++) {
		s1 = (s1 + buffer[n]) % 65521;
		s2 = (s2 + s1) % 65521;
	}

	return (s2 << 16) | s1;
}

uint32_t calculate_hash(uint8_t *p, size_t len)
{
	return adler32(p, len);
}

void purge_thread()
{
	for(;;) {
		sleep(HASH_PURGE_INTERVAL);
		purge_hashes();
	}
}

size_t get_hashmap_size()
{
	std::unique_lock<std::mutex> lck(hash_lock);
	return hashes.size();
}

uint8_t *duplicate(uint8_t *in, size_t len)
{
	uint8_t *out = new uint8_t[len];
	memcpy(out, in, len);
	return out;
}

void update_stats_win(WINDOW *stats_win, WINDOW *log_win)
{
	uint32_t time_diff = std::max(get_ms() - running_since, uint64_t(1));

	std::unique_lock<std::mutex> lck(ncurses_lock);
	mvwprintw(stats_win, 0, 0, "MQTT msgs: %u, per second: %.3f", uint32_t(mqtt_msgs), mqtt_msgs * 1000. / time_diff);
	mvwprintw(stats_win, 1, 0, "RF   msgs: %u, per second: %.3f", uint32_t(rf_msgs),   rf_msgs   * 1000. / time_diff);
	mvwprintw(stats_win, 2, 0, "de-dup map size: %zu, dedupped: %u", get_hashmap_size(), uint32_t(hash_dedup_count));
	wrefresh(stats_win);
}

void print_ts(WINDOW *log_win)
{
	uint64_t now   = get_ms();
	time_t   t_now = now / 1000;
	tm      *tm    = localtime(&t_now);
	wprintw(log_win, "%02d:%02d:%02d.%03d ", tm->tm_hour, tm->tm_min, tm->tm_sec, now % 1000);
}

void on_message(mosquitto *, void *p, const mosquitto_message *msg, const mosquitto_property *)
{
	pars *ps = reinterpret_cast<pars *>(p);

	uint32_t hash = calculate_hash(reinterpret_cast<uint8_t *>(msg->payload), msg->payloadlen);
	if (register_hash(hash)) {
		mqtt_to_rf.push(duplicate(reinterpret_cast<uint8_t *>(msg->payload), msg->payloadlen), msg->payloadlen);
		mqtt_msgs++;

		std::unique_lock<std::mutex> lck(ncurses_lock);
		wprintw(ps->pw, "\n");
		print_ts(ps->pw);
		wprintw(ps->pw, "from MQTT: %d\n", msg->payloadlen);
		dump(reinterpret_cast<uint8_t *>(msg->payload), msg->payloadlen, ps->pw);
	}
	else {
		hash_dedup_count++;
		std::unique_lock<std::mutex> lck(ncurses_lock);
		wprintw(ps->pw, "\n");
		print_ts(ps->pw);
		wprintw(ps->pw, "%08x from MQTT deduplicated\n", hash);
	}
	wrefresh(ps->pw);
}

void mqtt_thread(mosquitto *m, WINDOW *log_win)
{
	for(;;) {
		if (int rc = mosquitto_loop(m, 1, 1); rc != MOSQ_ERR_SUCCESS) {
			std::unique_lock<std::mutex> lck(ncurses_lock);
			wprintw(log_win, "Failed to process MQTT connection: %s\n", mosquitto_strerror(rc));
			lck.unlock();
			break;
		}

		if (rf_to_mqtt.empty() == false) {
			auto msg = rf_to_mqtt.pop();

			if (int rc = mosquitto_publish(m, nullptr, MQTT_TOPIC_TO, msg.second, msg.first, 0, false); rc != MOSQ_ERR_SUCCESS) {
				std::unique_lock<std::mutex> lck(ncurses_lock);
				wprintw(log_win, "Publish error: %s\n", mosquitto_strerror(rc));
				lck.unlock();
			}

			delete [] msg.first;
		}
	}
}

void on_connect(mosquitto *mqtt, void *p, int)
{
	pars *ps = reinterpret_cast<pars *>(p);

	std::unique_lock<std::mutex> lck(ncurses_lock);
	wprintw(ps->pw, "Subscribe to mqtt\n");
	lck.unlock();

	if (int rc = mosquitto_subscribe(mqtt, nullptr, MQTT_TOPIC_FROM, 0); rc != MOSQ_ERR_SUCCESS) {
		std::unique_lock<std::mutex> lck(ncurses_lock);
		fprintf(stderr, "Subscribe error: %s\n", mosquitto_strerror(rc));
		lck.unlock();
		exit(1);
	}

	wrefresh(ps->pw);
	doupdate();
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

	setlocale(LC_CTYPE, "");
	initscr();

	WINDOW *log_win   = newwin(15, 80,  0, 0);
	WINDOW *line_win  = newwin( 1, 80, 15, 0);
	WINDOW *stats_win = newwin(10, 80, 16, 0);

	char hostname[80] { };
	gethostname(hostname, sizeof hostname);
	mvwprintw(stats_win, 0, 80 - strlen(hostname), "%s", hostname);

	scrollok(log_win, TRUE);

	mvwprintw(line_win, 0, 0, "--------------------------------------------------------------------------------");
	wrefresh(line_win);

	pars pars_;
	pars_.pw = log_win;
	pars_.lora = &lora;

	mosquitto *mqtt = mosquitto_new(nullptr, true, &pars_);
	if (int rc = mosquitto_connect(mqtt, MQTT_HOST, MQTT_PORT, 30); rc != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "Failed to connect to MQTT host: %s\n", mosquitto_strerror(rc));
		return 1;
	}
        mosquitto_connect_callback_set   (mqtt, on_connect);
        mosquitto_message_v5_callback_set(mqtt, on_message);

	std::thread mqtt_thread_handle      (mqtt_thread, mqtt, log_win);
	std::thread hash_purge_thread_handle(purge_thread);

	for(;;) {
		bool do_stats = false;

		LoRaPacket p = lora.receivePacket(200);
		if (p.payloadLength()) {
			auto  *pnt = p.getPayload();
			size_t len = p.payloadLength();

			uint32_t hash = calculate_hash(pnt, len);
			if (register_hash(hash)) {
				rf_to_mqtt.push(duplicate(pnt, len), len);
				rf_msgs++;

				std::unique_lock<std::mutex> lck(ncurses_lock);
				wprintw(log_win, "\n");
				print_ts(log_win);
				wprintw(log_win, "length %d, RSSI: %d dBm, SNR: %.1f dB, freq.err.: %d Hz, hash %08x\n", len, p.getPacketRSSI(), p.getSNR(), p.getFreqErr(), hash);
				dump(pnt, len, log_win);
			}
			else {
				hash_dedup_count++;
				std::unique_lock<std::mutex> lck(ncurses_lock);
				wprintw(log_win, "\n");
				print_ts(log_win);
				wprintw(log_win, "%08x deduplicated\n", hash);
			}
			wrefresh(log_win);

			do_stats = true;
		}

		while(mqtt_to_rf.empty() == false) {
			auto msg = mqtt_to_rf.pop();

			LoRaPacket pkt(reinterpret_cast<unsigned char *>(msg.first), msg.second);
			size_t tx_size = lora.transmitPacket(&pkt);

			if (tx_size != msg.second) {
				std::unique_lock<std::mutex> lck(ncurses_lock);
				wprintw(log_win, "MQTT -> RF transmitted size: %zu, expected: %zu\n", tx_size, msg.second);
				wrefresh(log_win);
			}

			delete [] msg.first;

			do_stats = true;
		}

		if (do_stats) {
			update_stats_win(stats_win, log_win);
			std::unique_lock<std::mutex> lck(ncurses_lock);
			doupdate();
		}
	}

	delwin(stats_win);
	delwin(log_win);

	endwin();

	return 0;
}
