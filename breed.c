/*
 * breed.c - bridge end-to-end delay
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

#include <limits.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sched.h>
#include <sys/resource.h>

#include "common.h"

const char * const help_msg = "usage: %s [-v] [-i interval[u|m|s]] [-c count[k|m|g]] ifout ifin\n";

struct cfg {
	int sockout;
	int sockin;
	char *ifout;
	char *ifin;
	unsigned interval;
	unsigned count;
	unsigned long sum;
	unsigned rx;
	unsigned sent;
	unsigned min;
	unsigned max;
	int verbose;
	int rand_daddr;
	int rand_saddr;
	struct ether_addr daddr;
	struct ether_addr saddr;
};

struct __attribute__ ((packed)) frame {
	struct ether_header ether;
	struct iphdr ip;
	struct udphdr udp;
	uint64_t magic;
	struct timespec ts;
};

static void sched(void)
{
	struct sched_param param = {
		.sched_priority = sched_get_priority_max(SCHED_FIFO),
	};

	if (param.sched_priority == -1)
		perror("sched_get_priority_max(SCHED_FIFO)");
	else if (sched_setscheduler(0, SCHED_FIFO, &param) == -1)
		perror("sched_setscheduler(SCHED_FIFO)");

	if (setpriority(PRIO_PROCESS, 0, -19) == -1)
		perror("sched_priority(PRIO_PROCESS)");
}

static int setup(int argc, char *argv[], struct cfg *cfg)
{
	int c;
	int enable = 1;

	while ((c = getopt(argc, argv, "hi:c:s:d:v")) != -1)
		switch (c) {
		case 'h':
			usage(argv[0], 0);
		case 'i':
			cfg->interval = atoi(optarg);
			if (cfg->interval)
				switch (optarg[strlen(optarg) - 1]) {
				case 's':
					cfg->interval *= 1000;
				case 'm':
					cfg->interval *= 1000;
				}
			break;
		case 'c':
			cfg->count = atol(optarg);
			if (cfg->count)
				switch (optarg[strlen(optarg) - 1]) {
				case 'g':
					cfg->count *= 1000;
				case 'm':
					cfg->count *= 1000;
				case 'k':
					cfg->count *= 1000;
				}
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
			cfg->verbose = 1;
			break;
		default:
			usage(argv[0], 1);
		}

	if (optind != argc - 2)
		usage(argv[0], 1);

	cfg->ifout = argv[optind];
	cfg->ifin = argv[optind + 1];

	cfg->sockout = boundsock(cfg->ifout, 0);
	if (cfg->sockout == -1)
		return 1;

	if (setsockopt(cfg->sockout, SOL_PACKET, PACKET_QDISC_BYPASS, (char *)&enable, sizeof(enable)) < 0) {
		perror("setsockopt(PACKET_QDISC_BYPASS)");
		return 1;
	}

	cfg->sockin = boundsock(cfg->ifin, ETHERTYPE_IP);
	if (cfg->sockin == -1)
		return 1;

	if (setsockopt(cfg->sockin, SOL_SOCKET, SO_TIMESTAMPNS, (char *)&enable, sizeof(enable)) < 0) {
		perror("setsockopt(SO_TIMESTAMPNS)");
		return 1;
	}

	sched();

	return 0;
}

static struct frame template = {
	.ether = {
		.ether_type = __constant_htons(ETHERTYPE_IP),
	},
	.ip = {
		.version = 4,
		.ihl = 5,
		.tot_len = __constant_htons(sizeof(template.ip) + sizeof(template.udp) + sizeof(template.magic) + sizeof(template.ts)),
		.id = __constant_htons(0xcda3),
		.frag_off = 0x40,
		.ttl = 64,
		.protocol = IPPROTO_UDPLITE,
		.check = __constant_htons(0x414a),
		.saddr = ipv4_addr(192, 168, 85, 2),
		.daddr = ipv4_addr(192, 168, 85, 1),
	},
	.udp = {
		.source = __constant_htons(7),
		.dest = __constant_htons(7),
		/* no checksum */
		.len = __constant_htons(8),
		.check = __constant_htons(0xd47b),
	},
	.magic = __constant_cpu_to_be64(0x5274742043616C63),
};

static void result(struct cfg *cfg)
{
	printf("%u packets transmitted, %u received, %u%% packet loss\n",
		cfg->sent,
		cfg->rx,
		cfg->sent ? (cfg->sent - cfg->rx) * 100 / cfg->sent : 100);
	if (cfg->rx)
		printf("eed min/avg/max = %u/%u/%u us\n",
			cfg->min / 1000,
			(unsigned)(cfg->sum / (cfg->rx * 1000)),
			cfg->max / 1000);
}

static void* eed_calc(void *ptr)
{
	struct cfg *cfg = ptr;
	struct frame rx;
	unsigned eed;
	struct iovec msg_iov = {
		.iov_base = &rx,
		.iov_len = sizeof(rx),
	};
	char ctrl[CMSG_SPACE(sizeof(struct timespec))];
	struct cmsghdr *msg_control = (struct cmsghdr *)ctrl;
	struct cmsghdr *cmsg;

	while (1) {
		struct msghdr msg = {
			.msg_iov = &msg_iov,
			.msg_iovlen = 1,
			.msg_control = msg_control,
			.msg_controllen = sizeof(ctrl),
		};

		if (recvmsg(cfg->sockin, &msg, 0) == sizeof(template) && rx.magic == template.magic) {
			for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
				if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPNS) {
					struct timespec *rxts = (struct timespec *)CMSG_DATA(cmsg);

					eed = interval(&rx.ts, rxts);

					if (eed < cfg->min)
						cfg->min = eed;

					if (eed > cfg->max)
						cfg->max = eed;

					cfg->sum += eed;

					if (cfg->verbose)
						printf("eed: %u us\n", eed / 1000);

					cfg->rx++;
				}
			}
		}
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	struct cfg cfg = {
		.interval = 1000000,
		.min = UINT_MAX,
		.rand_daddr = 1,
		.rand_saddr = 1,
	};
	pthread_t th;

	if (setup(argc, argv, &cfg))
		return 1;

	memcpy(template.ether.ether_dhost, cfg.daddr.ether_addr_octet, ETH_ALEN);
	memcpy(template.ether.ether_shost, cfg.saddr.ether_addr_octet, ETH_ALEN);
	pthread_create(&th, NULL, eed_calc, &cfg);

	for (; !cfg.count || cfg.sent < cfg.count; cfg.sent++) {
		if (cfg.rand_daddr)
			rand_mac(template.ether.ether_dhost);
		if (cfg.rand_saddr)
			rand_mac(template.ether.ether_shost);

		clock_gettime(CLOCK_REALTIME, &template.ts);
		send(cfg.sockout, &template, sizeof(template), 0);

		usleep(cfg.interval);
	}
	result(&cfg);

	return 0;
}
