// (C) 2025 by Folkert van Heusden
// released under MIT license
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <locale.h>
#include <mosquitto.h>
#include <mutex>
#include <ncurses.h>
#include <queue>
#include <thread>
#include <sys/time.h>

#include "config.h"
#include "lora.h"
#include "packet.h"

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
	wrefresh(stats_win);
}

void on_message(mosquitto *, void *p, const mosquitto_message *msg, const mosquitto_property *)
{
	pars *ps = reinterpret_cast<pars *>(p);
	std::unique_lock<std::mutex> lck(ncurses_lock);
	wprintw(ps->pw, "from MQTT: %d\n\n", msg->payloadlen);
	wrefresh(ps->pw);
	lck.unlock();

	mqtt_to_rf.push(duplicate(reinterpret_cast<uint8_t *>(msg->payload), msg->payloadlen), msg->payloadlen);
	mqtt_msgs++;
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

	std::thread mqtt_thread_handle(mqtt_thread, mqtt, log_win);

	for(;;) {
		bool do_stats = false;

		LoRaPacket p = lora.receivePacket(50);
		if (p.payloadLength()) {
			rf_msgs++;

			auto  *pnt = p.getPayload();
			size_t len = p.payloadLength();
			rf_to_mqtt.push(duplicate(pnt, len), len);

			std::unique_lock<std::mutex> lck(ncurses_lock);
			wprintw(log_win, "length %d, RSSI: %d dBm, SNR: %.1f dB, freq.err.: %d Hz\n", len, p.getPacketRSSI(), p.getSNR(), p.getFreqErr());
			for(auto i=0; i<len; i++)
				wprintw(log_win, "%c", pnt[i] > 32 && pnt[i] < 127 ? pnt[i] : '.');
			wprintw(log_win, "\n\n");
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
