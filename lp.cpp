// (C) 2025 by Folkert van Heusden
// released under MIT license
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <locale.h>
#include <mosquitto.h>
#include <ncurses.h>
#include <sys/time.h>

#include "config.h"
#include "lora.h"
#include "packet.h"

struct pars {
	WINDOW *pw;
	LoRa   *lora;
};

std::atomic_uint32_t mqtt_msgs = 0;
std::atomic_uint32_t rf_msgs   = 0;

static uint64_t get_ms()
{
	timeval tv { };
	gettimeofday(&tv, nullptr);
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void on_message(mosquitto *, void *p, const mosquitto_message *msg, const mosquitto_property *)
{
	pars *ps = reinterpret_cast<pars *>(p);
	wprintw(ps->pw, "from MQTT: %d\n", msg->payloadlen);

	LoRaPacket pkt(reinterpret_cast<unsigned char *>(msg->payload), msg->payloadlen);
	LoRa *l = reinterpret_cast<LoRa *>(p);
	size_t tx_size = l->transmitPacket(&pkt);
	if (tx_size != msg->payloadlen)
		wprintw(ps->pw, ", transmitted: %zu\n", tx_size);
	else
		wprintw(ps->pw, "\n", tx_size);

	wrefresh(ps->pw);
	doupdate();

	mqtt_msgs++;
}

static void on_connect(mosquitto *mqtt, void *p, int)
{
	pars *ps = reinterpret_cast<pars *>(p);
	wprintw(ps->pw, "Subscribe to mqtt\n");

	if (int rc = mosquitto_subscribe(mqtt, nullptr, MQTT_TOPIC_FROM, 0); rc != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "Subscribe error: %s\n", mosquitto_strerror(rc));
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

	uint64_t running_since = get_ms();

	for(;;) {
		LoRaPacket p = lora.receivePacket(50);
		if (p.payloadLength()) {
			rf_msgs++;

			wprintw(log_win, "length %d, RSSI: %d dBm, SNR: %.1f dB, freq.err.: %d Hz\n", p.payloadLength(), p.getPacketRSSI(), p.getSNR(), p.getFreqErr());
			auto *pnt = p.getPayload();
			for(auto i=0; i<p.payloadLength(); i++)
				wprintw(log_win, "%c", pnt[i] > 32 && pnt[i] < 127 ? pnt[i] : '.');
			wprintw(log_win, "\n\n");

			if (int rc = mosquitto_publish(mqtt, nullptr, MQTT_TOPIC_TO, p.payloadLength(), p.getPayload(), 0, false); rc != MOSQ_ERR_SUCCESS) {
				fprintf(stderr, "Publish error: %s\n", mosquitto_strerror(rc));
				break;
			}

			uint32_t time_diff = std::max(get_ms() - running_since, uint64_t(1));

			mvwprintw(stats_win, 0, 0, "MQTT msgs: %u, per second: %.3f", uint32_t(mqtt_msgs), mqtt_msgs * 1000. / time_diff);
			mvwprintw(stats_win, 1, 0, "RF   msgs: %u, per second: %.3f", uint32_t(rf_msgs),   rf_msgs   * 1000. / time_diff);
			wrefresh(stats_win);
		}
		else {
			if (int rc = mosquitto_loop(mqtt, 0, 1); rc != MOSQ_ERR_SUCCESS) {
				fprintf(stderr, "Failed to process MQTT connection: %s\n", mosquitto_strerror(rc));
				break;
			}
		}

		wrefresh(log_win);
		doupdate();
	}

	delwin(stats_win);
	delwin(log_win);

	endwin();

	return 0;
}
