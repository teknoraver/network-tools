/*
 * xdperf.c - simple zero-copy traffic generator
 * Copyright (C) 2018-2020 Matteo Croce <mcroce@microsoft.com>
 *
 * AF_XDP support taken from kernel's samples/bpf/xdpsock_user.c
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
#include <errno.h>
#include <sys/mman.h>
#include <time.h>
#include <signal.h>
#include <asm/byteorder.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <sys/resource.h>

#ifndef XDP_RING_NEED_WAKEUP
#define XDP_RING_NEED_WAKEUP (1 << 0)
#endif

#ifndef XSK_UNALIGNED_BUF_OFFSET_SHIFT
/* Masks for unaligned chunks mode */
#define XSK_UNALIGNED_BUF_OFFSET_SHIFT 48
#endif

#ifndef XSK_UNALIGNED_BUF_ADDR_MASK
#define XSK_UNALIGNED_BUF_ADDR_MASK \
	((1ULL << XSK_UNALIGNED_BUF_OFFSET_SHIFT) - 1)
#endif

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>

#define NUM_FRAMES (4 * 1024)
#define BATCH_SIZE 64

#define ipv4_addr(o1, o2, o3, o4) __constant_htonl( \
	(o1) << 24 | \
	(o2) << 16 | \
	(o3) <<  8 | \
	(o4))

/**
 * structure which represents a packet
 */
struct __attribute__ ((packed)) frame {
	struct ether_header ether;
	struct iphdr ip;
	union {
		struct icmphdr icmp;
		struct udphdr udp;
	};
	char payload[ETH_DATA_LEN - sizeof(struct iphdr) - sizeof(struct udphdr)];
};

static struct frame template = {
	.ether = {
		.ether_type = __constant_htons(ETHERTYPE_IP),
	},
	.ip = {
		.version = 4,
		.ihl = 5,
		.id = __constant_htons(0xcda3),
		.frag_off = 0x40,
		.ttl = 64,
		.protocol = IPPROTO_UDP,
		.saddr = ipv4_addr(192, 168, 85, 2),
		.daddr = ipv4_addr(192, 168, 85, 1),
	},
	.udp = {
		.source = __constant_htons(36674),
		.dest = __constant_htons(9),
	},
};

enum {
	MODE_UDP,
	MODE_RAW,
	MODE_PING,
} mode = MODE_UDP;

static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
static struct xsk_ring_prod fq;
static struct xsk_ring_cons cq;
static struct xsk_umem *umem;
static void *buffer;

static struct xsk_ring_cons rx;
static struct xsk_ring_prod tx;
static struct xsk_socket *xsk;
static uint32_t outstanding_tx;

static bool rand_daddr = true;
static bool rand_saddr = true;
static struct ether_addr daddr;
static struct ether_addr saddr;
static int datalen = 18;

static const char *opt_if;
static int opt_ifindex;
static int opt_queue;

#define err(...) do { \
		fprintf(stderr, __VA_ARGS__); \
		exit(1); \
	} while (0)

static void __attribute__ ((noreturn)) usage(char *argv0, int ret)
{
	fprintf(stderr,
		"usage: %s [-g][-s src-mac][-d dest-mac][-S src-ip][-D dst-ip][-l len] <iface>\n"
		"\t\t-g: run in skb mode (XDP generic)\n"
		"\t\t-s: source mac|random\n"
		"\t\t-d: destination mac|random\n"
		"\t\t-S: source IP|random\n"
		"\t\t-D: destination IP|random\n"
		"\t\t-l: frame length\n"
		"\t\t-i: ICMP mode\n"
		"\t\t-n: send raw ethernet frames\n",
		argv0);
	exit(ret);
}

uint16_t ip_checksum(uint16_t *buf, size_t len)
{
	unsigned long sum = 0;
	int i;

	for (i = 0; i < len; i++) {
		sum += htons(buf[i]);
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
	}

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return htons(~sum);
}

static int xsk_configure_socket(void)
{
	struct xsk_socket_config cfg = {
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.xdp_flags = xdp_flags,
	};
	uint32_t idx;
	int ret;
	int i;

	ret = xsk_socket__create(&xsk, opt_if, opt_queue, umem, &rx, &tx, &cfg);
	if (ret)
		err("xsk_socket__create() %s (%d)\n", strerror(-ret), -ret);

	ret = xsk_ring_prod__reserve(&fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		err("%d != XSK_RING_PROD__DEFAULT_NUM_DESCS\n", ret);

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++, idx++)
		*xsk_ring_prod__fill_addr(&fq, idx * XSK_UMEM__DEFAULT_FRAME_SIZE) = i;

	xsk_ring_prod__submit(&fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

	return 0;
}

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
 * parse cmdline and create in memory configuration
 */
static int setup(int argc, char *argv[])
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	int c, i;
	int ret;

	while ((c = getopt(argc, argv, "s:d:S:D:l:nihg")) != -1)
		switch (c) {
		case 'd':
			rand_daddr = !strcmp(optarg, "rand");
			if (!rand_daddr && !ether_aton_r(optarg, &daddr))
				usage(argv[0], 1);
			break;
		case 's':
			rand_saddr = !strcmp(optarg, "rand");
			if (!rand_saddr && !ether_aton_r(optarg, &saddr))
				usage(argv[0], 1);
			break;
		case 'S':
			template.ip.saddr = inet_addr(optarg);
			break;
		case 'D':
			template.ip.daddr = inet_addr(optarg);
			break;
		case 'l':
			datalen = atoi(optarg);
			/* 4 extra byte for FCS */
			if (datalen < ETH_ZLEN || datalen > ETH_FRAME_LEN)
				err("datalen must be between %d and %d\n", ETH_ZLEN, ETH_FRAME_LEN);
			datalen -= sizeof(template.ether) + sizeof(template.ip) + sizeof(template.udp);
			break;
		case 'g':
			xdp_flags &= ~XDP_FLAGS_DRV_MODE;
			xdp_flags |= XDP_FLAGS_SKB_MODE;
			break;
		case 'i':
			mode = MODE_PING;
			srand(time(NULL));
			template.ip.protocol = IPPROTO_ICMP;
			template.icmp.type = ICMP_ECHO;
			template.icmp.code = 0;
			template.icmp.un.echo.id = rand();
			template.icmp.un.echo.sequence = htons(1);
			break;
		case 'n':
			mode = MODE_RAW;
			/* Frames with ethertypes lower than ETH_P_802_3_MIN (0x600) are
			 * interpreted as DIX frames, where the ethertype field really
			 * is the frame length. Linux tries to inspect these frames with
			 * the llc dissector which costs extra CPU power.
			 * An ethertype higher or equal to ETH_P_802_3_MIN is safe
			 * to use as 1536 is an invalid frame size.
			 */
			template.ether.ether_type = __constant_htons(ETH_P_802_3_MIN);
			memset(&template.ip, 0, sizeof(template) - ETH_HLEN);
			break;
		case 'h':
			usage(argv[0], 0);
		default:
			usage(argv[0], 1);
		}

	if (optind != argc - 1)
		usage(argv[0], 1);

	opt_if = argv[optind];
	opt_ifindex = if_nametoindex(opt_if);
	if (!opt_ifindex)
		err("if_nametoindex(): %s\n", strerror(errno));

	if (mode != MODE_RAW) {
		template.ip.tot_len = htons(datalen + sizeof(template.ip) + sizeof(template.udp));
		if (mode == MODE_UDP)
			template.udp.len = htons(datalen + sizeof(template.udp));
	}

	if (rand_daddr)
		seed_mac(template.ether.ether_dhost);
	else
		memcpy(template.ether.ether_dhost, daddr.ether_addr_octet, ETH_ALEN);
	if (rand_saddr)
		seed_mac(template.ether.ether_shost);
	else
		memcpy(template.ether.ether_shost, saddr.ether_addr_octet, ETH_ALEN);

	if (mode != MODE_RAW) {
		template.ip.check = 0;
		template.ip.check = ip_checksum((uint16_t *)&template.ip, template.ip.ihl * 2);

		for (i = 0; i < datalen; i++)
			template.payload[i] = i;
	}

	if (setrlimit(RLIMIT_MEMLOCK, &r))
		err("setrlimit(RLIMIT_MEMLOCK): %s\n", strerror(errno));

	ret = posix_memalign(&buffer, getpagesize(), NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
	if (ret)
		err("posix_memalign(): %d\n", ret);

	ret = xsk_umem__create(&umem, buffer, NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE, &fq, &cq, NULL);
	if (ret)
		err("xsk_umem__create(): %s\n", strerror(errno));

	ret = xsk_configure_socket();
	if (ret)
		err("xsk_umem__create(): %s\n", strerror(errno));

	for (i = 0; i < NUM_FRAMES; i++) {

		if (rand_daddr)
			rand_mac(template.ether.ether_dhost);

		if (rand_saddr)
			rand_mac(template.ether.ether_shost);

		memcpy(xsk_umem__get_data(buffer, i * XSK_UMEM__DEFAULT_FRAME_SIZE),
		       &template, sizeof(template.ether) + sizeof(template.ip) + sizeof(template.udp) + datalen);
		if (mode == MODE_PING) {
			template.icmp.un.echo.sequence = htons(ntohs(template.icmp.un.echo.sequence) + 1);
			template.icmp.checksum = 0;
			template.icmp.checksum = ip_checksum((uint16_t *)&template.icmp,
							     (sizeof(template.icmp) + datalen) / sizeof(uint16_t));
		}
	}

	return 0;
}

static void complete_tx_only(void)
{
	unsigned int rcvd;
	uint32_t idx;
	int ret;

	if (!outstanding_tx)
		return;

	ret = sendto(xsk_socket__fd(xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret < 0 && errno != ENOBUFS && errno != EAGAIN && errno != EBUSY)
		err("tx error: %s\n", strerror(errno));

	rcvd = xsk_ring_cons__peek(&cq, BATCH_SIZE, &idx);
	if (rcvd > 0) {
		xsk_ring_cons__release(&cq, rcvd);
		outstanding_tx -= rcvd;
	}
}

static void int_exit(int sig)
{
	bpf_xdp_detach(opt_ifindex, xdp_flags, NULL);

	exit(0);
}

int main(int argc, char *argv[])
{
	uint32_t idx, frame_nb = 0, i;

	if (setup(argc, argv))
		return 1;

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);

	while (1) {
		if (xsk_ring_prod__reserve(&tx, BATCH_SIZE, &idx) == BATCH_SIZE) {

			for (i = 0; i < BATCH_SIZE; i++) {
				xsk_ring_prod__tx_desc(&tx, idx + i)->addr = (frame_nb + i) << XSK_UMEM__DEFAULT_FRAME_SHIFT;
				xsk_ring_prod__tx_desc(&tx, idx + i)->len = sizeof(template.ether) + sizeof(template.ip) + sizeof(template.udp) + datalen;
			}

			xsk_ring_prod__submit(&tx, BATCH_SIZE);
			outstanding_tx += BATCH_SIZE;
			frame_nb += BATCH_SIZE;
			frame_nb %= NUM_FRAMES;
		}

		complete_tx_only();
	}

	return 1;
}
