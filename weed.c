/*
 * weed.c - watch end-to-end delay
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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <signal.h>
#include <pthread.h>
#include <asm/byteorder.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <time.h>
#include <sched.h>
#include <sys/resource.h>

#define ipv4_addr(o1, o2, o3, o4) __constant_htonl( \
	(o1) << 24 | \
	(o2) << 16 | \
	(o3) <<  8 | \
	(o4))

static void __attribute__ ((noreturn)) usage(char *argv0, int ret)
{
	fprintf(stderr, "usage: %s [-v] [-d dstaddr] [-s srcaddr] [-i interval[u|m|s]] [-c count[k|m|g]] ifout ifin\n", argv0);
	exit(ret);
}

/**
 * in memory data structure for configuration
 */
static int sockout;
static int sockin;
static char *ifout;
static char *ifin;
static unsigned interval = 1000000;
static unsigned count;
static unsigned long long sum;
static unsigned long long sum2;
static unsigned rx;
static unsigned sent;
static unsigned min = UINT_MAX;
static unsigned max;
static int verbose;
static int rand_daddr = 1;
static int rand_saddr = 1;
static struct ether_addr daddr;
static struct ether_addr saddr;
static pthread_t th;

/**
 * structure which represents a probe packet
 */
struct __attribute__ ((packed)) frame {
	struct ether_header ether;
	struct iphdr ip;
	struct udphdr udp;
	uint64_t magic;
	struct timespec ts;
};

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

/**
 * fills the buffer with 6 pseudo random octects
 */
static void rand_mac(unsigned char *mac)
{
	nrand48((unsigned short *)mac);
	mac[0] &= 0xfe;
}

/**
 * seeds nrand48 with the current time, and fills
 * the buffer with 6 pseudo random octects
 */
static void seed_mac(unsigned char *mac)
{
	struct timespec now = { 0 };
	uint64_t ns;

	clock_gettime(CLOCK_MONOTONIC, &now);
	ns = now.tv_sec * now.tv_nsec;
	memcpy(mac, &ns, ETH_ALEN);
	rand_mac(mac);
}

/**
 * integer sqrt calculation through iteration
 */
static unsigned long llsqrt(unsigned long long a)
{
	unsigned long long prev = ULLONG_MAX;
	unsigned long long x = a;

	if (!x)
		return 0;

	while (x < prev) {
		prev = x;
		x = (x + a / x) / 2;
	}

	return (unsigned long)x;
}

/**
 * converts a duration specifier into useconds:
 * 1s => 1 second => 1.000.000 usecs
 * 1m => 1 millisecond => 1.000 usecs
 * 1 => 1 usec
 */
static long timetoi(char *s)
{
	long ret = atol(s);
	if (ret)
		switch (s[strlen(s) - 1]) {
		case 's':
			ret *= 1000;
		case 'm':
			ret *= 1000;
		}

	return ret;
}

/**
 * converts an SI specifier into bytes:
 * 1 => 1 byte
 * 1k => 1 kB => 1.000 bytes
 * 1m => 1 MB => 1.000.000 bytes
 * 1g => 1 GB => 1.000.000.000 bytes
 */
static long atosi(char *s)
{
	long ret = atol(s);
	if (ret)
		switch (s[strlen(s) - 1]) {
		case 'g':
			ret *= 1000;
		case 'm':
			ret *= 1000;
		case 'k':
			ret *= 1000;
		}

	return ret;
}

/**
 * subtracts two struct timespec
 */
static unsigned time_sub(struct timespec *since, struct timespec *to)
{
	if (to->tv_sec == since->tv_sec)
		return to->tv_nsec - since->tv_nsec;

	return (to->tv_sec - since->tv_sec) * 1000000000
		+ to->tv_nsec - since->tv_nsec;
}

/**
 * gather statistics and prints them
 */
static void result(int sig)
{
	pthread_cancel(th);
	pthread_join(th, NULL);

	printf("%u packets transmitted, %u received, %u%% packet loss\n",
		sent,
		rx,
		sent ? (sent - rx) * 100 / sent : 100);
	if (rx) {
		sum /= rx;
		sum2 /= rx;
		printf("eed min/avg/max/mdev = %.1f/%.1f/%.1f/%.1f us\n",
			(float)min / 1000,
			(float)sum / 1000,
			(float)max / 1000,
			(float)llsqrt(sum2 - sum * sum) / 1000
		);
	}
	exit(0);
}

/**
 * creates an AF_PACKET socket bound to an interface with a specific ether_type.
 * Set ether_type to disable rx
 */
static int bindsock(char *ifname, uint16_t ether_type)
{
	struct sockaddr_ll ll = {
		.sll_family = AF_PACKET,
		.sll_protocol = __constant_htons(ether_type),
		.sll_ifindex = if_nametoindex(ifname),
	};
	int sock;

	if (!ll.sll_ifindex) {
		perror("if_nametoindex");
		return -1;
	}

	sock = socket(AF_PACKET, SOCK_RAW, __constant_htons(ether_type));
	if (sock == -1) {
		perror("socket");
		return -1;
	}

	if (bind(sock, (struct sockaddr *)&ll, sizeof(ll)) < 0) {
		close(sock);
		perror("bind");
		return -1;
	}

	return sock;
}

/**
 * set the current thread to maximum priority and FIFO scheduler
 */
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

/**
 * parse cmdline and create in memory configuration
 */
static int setup(int argc, char *argv[])
{
	int c;
	int enable = 1;
	struct sigaction sa = {
		.sa_handler = result,
		.sa_flags = SA_RESTART,
	};

	while ((c = getopt(argc, argv, "hi:c:s:d:v")) != -1)
		switch (c) {
		case 'h':
			usage(argv[0], 0);
		case 'i':
			interval = timetoi(optarg);
			break;
		case 'c':
			count = atosi(optarg);
			break;
		case 'd':
			rand_daddr = !strcmp(optarg, "rand");
			if (rand_daddr)
				seed_mac(daddr.ether_addr_octet);
			else if (!ether_aton_r(optarg, &daddr))
					usage(argv[0], 1);
			break;
		case 's':
			rand_saddr = !strcmp(optarg, "rand");
			if (rand_saddr)
				seed_mac(saddr.ether_addr_octet);
			else if (!ether_aton_r(optarg, &saddr))
					usage(argv[0], 1);
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage(argv[0], 1);
		}

	if (optind != argc - 2)
		usage(argv[0], 1);

	ifout = argv[optind];
	ifin = argv[optind + 1];

	sockout = bindsock(ifout, 0);
	if (sockout == -1)
		return 1;

	if (setsockopt(sockout, SOL_PACKET, PACKET_QDISC_BYPASS, (char *)&enable, sizeof(enable)) < 0) {
		perror("setsockopt(PACKET_QDISC_BYPASS)");
		return 1;
	}

	sockin = bindsock(ifin, ETHERTYPE_IP);
	if (sockin == -1)
		return 1;

	if (setsockopt(sockin, SOL_SOCKET, SO_TIMESTAMPNS, (char *)&enable, sizeof(enable)) < 0) {
		perror("setsockopt(SO_TIMESTAMPNS)");
		return 1;
	}

	sched();

	sigaction(SIGINT, &sa, NULL);

	return 0;
}

/**
 * calculate the eed of incoming packets
 */
static void* eed_calc(void *ptr)
{
	struct frame rxf;
	unsigned long long eed;
	struct iovec msg_iov = {
		.iov_base = &rxf,
		.iov_len = sizeof(rxf),
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

		if (recvmsg(sockin, &msg, 0) == sizeof(template) && rxf.magic == template.magic) {
			for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
				if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPNS) {
					struct timespec *rxts = (struct timespec *)CMSG_DATA(cmsg);

					eed = time_sub(&rxf.ts, rxts);

					if (eed < min)
						min = eed;

					if (eed > max)
						max = eed;

					sum += eed;
					sum2 += eed * eed;

					if (verbose)
						printf("eed: %.1f us\n", (float)eed / 1000);

					rx++;
				}
			}
		}
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	if (setup(argc, argv))
		return 1;

	memcpy(template.ether.ether_dhost, daddr.ether_addr_octet, ETH_ALEN);
	memcpy(template.ether.ether_shost, saddr.ether_addr_octet, ETH_ALEN);
	pthread_create(&th, NULL, eed_calc, NULL);

	for (; !count || sent < count; sent++) {
		if (rand_daddr)
			rand_mac(template.ether.ether_dhost);
		if (rand_saddr)
			rand_mac(template.ether.ether_shost);

		clock_gettime(CLOCK_REALTIME, &template.ts);
		send(sockout, &template, sizeof(template), 0);

		usleep(interval);
	}
	if (rx < count)
		sleep(1);

	result(0);

	return 0;
}
