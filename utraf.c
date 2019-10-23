/*
 * utraf.c - micro traffic statistics collector
 * Copyright (C) 2019 Matteo Croce <mcroce@redhat.com>
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
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <unistd.h>

#define B 1000000000

static int ifindex;
static int fd;
static char buf[4096];

static void __attribute__ ((noreturn)) usage(char *argv0, int ret)
{
	fprintf(stderr, "usage: %s [-i interval] iface\n", argv0);
	exit(ret);
}

static uint64_t time_sub(struct timespec *since, struct timespec *to)
{
	if (to->tv_sec == since->tv_sec)
		return to->tv_nsec - since->tv_nsec;

	return (to->tv_sec - since->tv_sec) * B + to->tv_nsec - since->tv_nsec;
}

static int get_link_stats(struct rtnl_link_stats64 *stats, struct timespec *ts)
{
	/* request */
	static const struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
	};
	static struct {
		const struct nlmsghdr nlh;
		struct ifinfomsg ifi;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = RTM_GETLINK,
			.nlmsg_flags = NLM_F_REQUEST,
			.nlmsg_seq = 100,
		},
		.ifi = {
			.ifi_family = ARPHRD_ETHER,
		},
	};

	/* response */
	const struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	const struct ifinfomsg *ifi = NLMSG_DATA(nlh);
	const struct rtattr *rta = IFLA_RTA(ifi);
	int rtalist_len;
	int readed;

	req.ifi.ifi_index = ifindex;

	readed = sendto(fd, &req, sizeof(req), 0, (struct sockaddr *)&sa, sizeof(sa));

	if (readed < 0) {
		perror("sendto");
		return 1;
	}

	readed = recv(fd, buf, sizeof(buf), 0);
	clock_gettime(CLOCK_MONOTONIC, ts);

	if (readed < 0) {
		perror("recv");
		return 1;
	}

	if (readed == sizeof(buf) && recv(fd, buf, 1, 0) == 1) {
		fprintf(stderr, "oversized response!");
		return 1;
	}

	if (!NLMSG_OK(nlh, readed)) {
		fprintf(stderr, "netlink error\n");
		return 1;
	}

	if (nlh->nlmsg_type != RTM_NEWLINK) {
		fprintf(stderr, "invalid nlmsg_type: %d\n", nlh->nlmsg_type);
		return 1;
	}

	for (rtalist_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	     RTA_OK(rta, rtalist_len);
	     rta = RTA_NEXT(rta, rtalist_len)) {
		if (rta->rta_type == IFLA_STATS64) {
			struct rtnl_link_stats64 *st = RTA_DATA(rta);
			*stats = *st;
			return 0;
		}
	}

	return 1;
}

int main(int argc, char *argv[])
{
	uint64_t deltat, txpps, rxpps, txbps, rxbps;
	struct rtnl_link_stats64 olds, news;
	struct timespec oldt, newt;
	int interval = 1000000, c;

	while ((c = getopt(argc, argv, "hi:")) != -1)
		switch (c) {
		case 'h':
			usage(argv[0], 0);
		case 'i':
			interval = atof(optarg) * 1000000;
			break;
		}

	if (optind != argc - 1)
		usage(argv[0], 1);

	ifindex = if_nametoindex(argv[optind]);
	if (!ifindex) {
		perror("if_nametoindex");
		return 1;
	}

	fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (fd < 0) {
		perror("sock");
		return 1;
	}

	if (get_link_stats(&olds, &oldt))
		return 1;

	while (1) {
		usleep(interval);

		if (get_link_stats(&news, &newt))
			return 1;

		deltat = time_sub(&oldt, &newt);
		txpps = (news.tx_packets - olds.tx_packets) * B / deltat;
		rxpps = (news.rx_packets - olds.rx_packets) * B / deltat;
		txbps = (news.tx_bytes - olds.tx_bytes) * 8 * B / deltat;
		rxbps = (news.rx_bytes - olds.rx_bytes) * 8 * B / deltat;

		printf("tx: %lu bps %lu pps tx %lu bps pps: %lu\n",
		       txbps, txpps, rxbps, rxpps);

		olds = news;
		oldt = newt;
	}

	return 0;
}
