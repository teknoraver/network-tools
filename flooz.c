/*
 * flooz.c - simple zero-copy traffic generator
 * Copyright (C) 2018 Matteo Croce <mcroce@redhat.com>
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
#include <netinet/udp.h>
#include <linux/if_link.h>
#include <sys/resource.h>
#include <bpf/xsk.h>

#define NUM_FRAMES (4 * 1024)
#define BATCH_SIZE 64
#define XDP_FLAGS (XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE)

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
	struct udphdr udp;
	uint8_t data[18];
};

static struct frame template = {
	.ether = {
		.ether_type = __constant_htons(ETHERTYPE_IP),
	},
	.ip = {
		.version = 4,
		.ihl = 5,
		.tot_len = __constant_htons(sizeof(template.ip) + sizeof(template.udp) + sizeof(template.data)),
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
		.len = __constant_htons(sizeof(template.udp) + sizeof(template.data)),
	},
	.data = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12,
	},
};

static struct xsk_ring_prod fq;
static struct xsk_ring_cons cq;
static struct xsk_umem *umem;
static void *buffer;

static struct xsk_ring_cons rx;
static struct xsk_ring_prod tx;
static struct xsk_socket *xsk;
static uint32_t outstanding_tx;

static int rand_daddr = 1;
static int rand_saddr = 1;
static struct ether_addr daddr;
static struct ether_addr saddr;

static const char *opt_if;
static int opt_ifindex;
static int opt_queue;
static uint32_t prog_id;

#define err(...) do { \
		fprintf(stderr, __VA_ARGS__); \
		exit(1); \
	} while (0)

static void __attribute__ ((noreturn)) usage(char *argv0, int ret)
{
	fprintf(stderr, "usage: %s [-s sendermac|rand] [-d destmac|rand] [-S srcip] [-D dstip] iface\n", argv0);
	exit(ret);
}

void ip_checksum(struct iphdr *iph)
{
	unsigned long sum = 0;
	uint16_t *ip1 = (uint16_t *)iph;
	int i;

	iph->check = 0;

	for (i = 0; i < iph->ihl * 2; i++) {
		sum += htons(ip1[i]);
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
	}

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	iph->check = htons(~sum);
}

static int xsk_configure_socket(void)
{
	struct xsk_socket_config cfg = {
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.xdp_flags = XDP_FLAGS,
	};
	uint32_t idx;
	int ret;
	int i;

	ret = xsk_socket__create(&xsk, opt_if, opt_queue, umem, &rx, &tx, &cfg);
	if (ret)
		err("xsk_socket__create() %s (%d)\n", strerror(-ret), -ret);

	ret = bpf_get_link_xdp_id(opt_ifindex, &prog_id, cfg.xdp_flags);
	if (ret)
		err("bpf_get_link_xdp_id() %s (%d)\n", strerror(errno), errno);

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

	while ((c = getopt(argc, argv, "s:d:S:D:h")) != -1)
		switch (c) {
		case 'h':
			usage(argv[0], 0);
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
		default:
			usage(argv[0], 1);
		}

	if (optind != argc - 1)
		usage(argv[0], 1);

	opt_if = argv[optind];
	opt_ifindex = if_nametoindex(opt_if);
	if (!opt_ifindex)
		err("if_nametoindex(): %s\n", strerror(errno));

	if (rand_daddr)
		seed_mac(template.ether.ether_dhost);
	else
		memcpy(template.ether.ether_dhost, daddr.ether_addr_octet, ETH_ALEN);
	if (rand_saddr)
		seed_mac(template.ether.ether_shost);
	else
		memcpy(template.ether.ether_shost, saddr.ether_addr_octet, ETH_ALEN);

	ip_checksum(&template.ip);

	if (setrlimit(RLIMIT_MEMLOCK, &r))
		err("setrlimit(RLIMIT_MEMLOCK): %s\n", strerror(errno));

	ret = posix_memalign(&buffer, getpagesize(), NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
	if (ret)
		err("posix_memalign(): %d\n", ret);

	ret = xsk_umem__create(&umem, buffer, NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE, &fq, &cq, NULL);
	if (ret)
		return 1;

	if (xsk_configure_socket())
		return 1;

	for (i = 0; i < NUM_FRAMES; i++) {
		if (rand_daddr)
			rand_mac(template.ether.ether_dhost);

		if (rand_saddr)
			rand_mac(template.ether.ether_shost);

		memcpy(xsk_umem__get_data(buffer, i * XSK_UMEM__DEFAULT_FRAME_SIZE), &template, sizeof(template));
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
	bpf_set_link_xdp_fd(opt_ifindex, -1, XDP_FLAGS);

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
				xsk_ring_prod__tx_desc(&tx, idx + i)->len = sizeof(template);
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
