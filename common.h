
#ifndef _COMMON_H
#define _COMMON_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <asm/byteorder.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>

#define ipv4_addr(o1, o2, o3, o4) __constant_htonl( \
	(o1) << 24 | \
	(o2) << 16 | \
	(o3) <<  8 | \
	(o4))

static void rand_mac(unsigned char *mac)
{
	nrand48((unsigned short *)mac);
	mac[0] &= 0xfe;
}

static void seed_mac(unsigned char *mac)
{
	struct timespec now = { 0 };
	uint64_t ns;

	clock_gettime(CLOCK_MONOTONIC, &now);
	ns = now.tv_sec * now.tv_nsec;
	memcpy(mac, &ns, ETH_ALEN);
	rand_mac(mac);
}

static unsigned interval(struct timespec *since, struct timespec *to)
{
	if (to->tv_sec == since->tv_sec)
		return to->tv_nsec - since->tv_nsec;

	return (to->tv_sec - since->tv_sec) * 1000000000
		+ to->tv_nsec - since->tv_nsec;
}

static int boundsock(char *ifname, uint16_t ether_type)
{
	struct sockaddr_ll ll = {
		.sll_family = AF_PACKET,
	};
	struct ifreq ifr = { 0 };
	int sock;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	sock = socket(AF_PACKET, SOCK_RAW, __constant_htons(ether_type));
	if (sock == -1) {
		perror("socket");
		return -1;
	}

	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
		close(sock);
		perror("SIOCGIFINDEX");
		return -1;
	}
	ll.sll_ifindex = ifr.ifr_ifindex;

	if (bind(sock, (struct sockaddr *)&ll, sizeof(ll)) < 0) {
		close(sock);
		perror("bind");
		return -1;
	}

	return sock;
}

extern const char * const help_msg;

static void __attribute__ ((noreturn)) usage(char *argv0, int ret)
{
	fprintf(stderr, help_msg, argv0);
	exit(ret);
}

#endif
