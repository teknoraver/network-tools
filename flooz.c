/*
 * flooz.c - simple zero-copy traffic generator
 * Copyright (C) 2018 Matteo Croce <mcroce@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <sys/mman.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "common.h"

#define c_buffer_sz 4096
#define c_buffer_nb 1

const char * const help_msg = "usage: %s [-v[v]] [-i interval[u|m|s]] [-c count[k|m|g]] [-s sendermac|rand] [-d destmac|rand] iface\n";

static const char prog[] = "|/-\\";

struct cfg {
	unsigned interval;
	int verbose;
	unsigned long count;
	int sock;
	char *ifname;
	int rand_daddr;
	int rand_saddr;
	struct desc *desc;
	struct ether_addr daddr;
	struct ether_addr saddr;
};

struct __attribute__ ((packed)) frame {
	struct ether_header ether;
	struct iphdr ip;
	struct udphdr udp;
	uint8_t data[0];
};

struct desc {
	volatile struct tpacket_hdr thdr;
	struct frame __attribute__ ((aligned(TPACKET_ALIGNMENT))) frame;
};

/* A? tim.it. */
static uint8_t dns[] = {
	0x9e, 0x97, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03, 0x74, 0x69, 0x6d,
	0x02, 0x69, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01,
};

static struct frame template = {
	.ether = {
		.ether_type = __constant_htons(ETHERTYPE_IP),
	},
	.ip = {
		.version = 4,
		.ihl = 5,
		.tot_len = __constant_htons(sizeof(template.ip) + sizeof(template.udp) + sizeof(dns)),
		.id = __constant_htons(0xcda3),
		.frag_off = 0x40,
		.ttl = 64,
		.protocol = IPPROTO_UDP,
		.check = __constant_htons(0x41c1),
		.saddr = ipv4_addr(192, 168, 85, 2),
		.daddr = ipv4_addr(192, 168, 85, 1),
	},
	.udp = {
		.source = __constant_htons(36674),
		.dest = __constant_htons(53),
		.len = __constant_htons(sizeof(template.udp) + sizeof(dns)),
		.check = __constant_htons(0xc1fc),
	},
};

static int setup(int argc, char *argv[], struct cfg *cfg)
{
	int enable = 1;
	const struct tpacket_req treq = {
		.tp_block_size = c_buffer_sz,
		.tp_block_nr = c_buffer_nb,
		.tp_frame_size = c_buffer_sz,
		.tp_frame_nr = c_buffer_nb,
	};
	const int size = treq.tp_block_size * treq.tp_block_nr;
	int c;

	while ((c = getopt(argc, argv, "i:c:s:d:vh")) != -1)
		switch (c) {
		case 'h':
			usage(argv[0], 0);
		case 'i':
			cfg->interval = timetoi(optarg);
			break;
		case 'c':
			cfg->count = atosi(optarg);
			break;
		case 'd':
			cfg->rand_daddr = !strcmp(optarg, "rand");
			if (cfg->rand_daddr) {
				if (ether_aton_r(optarg, &cfg->daddr))
					seed_mac(cfg->daddr.ether_addr_octet);
				else
					usage(argv[0], 1);
			}
			break;
		case 's':
			cfg->rand_saddr = !strcmp(optarg, "rand");
			if (cfg->rand_saddr) {
				if (ether_aton_r(optarg, &cfg->saddr))
					seed_mac(cfg->saddr.ether_addr_octet);
				else
					usage(argv[0], 1);
			}
			break;
		case 'v':
			cfg->verbose++;
			break;
		default:
			usage(argv[0], 1);
		}

	if (optind != argc - 1)
		usage(argv[0], 1);

	cfg->ifname = argv[optind];

	cfg->sock = boundsock(cfg->ifname, 0);
	if (cfg->sock == -1)
		return 1;

	if (setsockopt(cfg->sock, SOL_PACKET, PACKET_LOSS, (char *)&enable, sizeof(enable)) < 0) {
		perror("setsockopt(PACKET_LOSS)");
		return 1;
	}

	if (setsockopt(cfg->sock, SOL_PACKET, PACKET_QDISC_BYPASS, (char *)&enable, sizeof(enable)) < 0) {
		perror("setsockopt(PACKET_QDISC_BYPASS)");
		return 1;
	}

	if (setsockopt(cfg->sock, SOL_PACKET, PACKET_TX_RING, (char *)&treq, sizeof(treq)) < 0) {
		perror("setsockopt(PACKET_TX_RING)");
		return 1;
	}

	cfg->desc = mmap(0, size, PROT_WRITE, MAP_SHARED | MAP_LOCKED, cfg->sock, 0);
	if (cfg->desc == (void *)-1) {
		perror("mmap");
		return 1;
	}

	sched();

	return 0;
}

int main(int argc, char *argv[])
{
	struct cfg cfg = {
		.rand_daddr = 1,
		.rand_saddr = 1,
	};
	int ret = 0;
	unsigned long sent = 0;
	struct timespec last = { 0 };
	int p = 0;

	if (setup(argc, argv, &cfg))
		return 1;

	memcpy(&cfg.desc->frame, &template, sizeof(template));
	memcpy(cfg.desc->frame.ether.ether_dhost, cfg.daddr.ether_addr_octet, ETH_ALEN);
	memcpy(cfg.desc->frame.ether.ether_shost, cfg.saddr.ether_addr_octet, ETH_ALEN);
	memcpy(cfg.desc->frame.data, dns, sizeof(dns));

	if (cfg.verbose) {
		printf("sending to %s\n", cfg.ifname);
		if (cfg.count)
			printf("\tcount\t%lu\n", cfg.count);
		if (cfg.interval)
			printf("\tinterval: %u usec\n", cfg.interval);
		else
			puts("\tno interval");
	}

	if (cfg.verbose > 1)
		setvbuf(stdout, NULL, _IONBF, 0);

	while (!cfg.count || sent < cfg.count) {
		if (cfg.rand_daddr)
			rand_mac(cfg.desc->frame.ether.ether_dhost);
		if (cfg.rand_saddr)
			rand_mac(cfg.desc->frame.ether.ether_shost);

		cfg.desc->thdr.tp_len = sizeof(template) + sizeof(dns);
		cfg.desc->thdr.tp_status = TP_STATUS_SEND_REQUEST;
		ret = send(cfg.sock, NULL, 0, 0);
		if (ret == -1)
			break;
		sent++;

		if (cfg.interval)
			usleep(cfg.interval);
		if (cfg.verbose > 1) {
			struct timespec now;
			clock_gettime(CLOCK_MONOTONIC, &now);
			if (sent == cfg.count || interval(&last, &now) > 100000000) {
				if (cfg.count) {
					printf("\r%lu/%lu (%lu%%)", sent, cfg.count, sent * 100 / cfg.count);
				} else {
					putchar(prog[p++ % sizeof(prog)]);
					putchar('\r');
				}
				last = now;
			}
		}
	}

	if (cfg.verbose > 1)
		putchar('\n');

	return ret == -1;
}
