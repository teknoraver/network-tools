/*
 * bptraf - eBPF traffic analyzer
 * inspired by Linux kernel xdp1 example
 * Copyright (C) 2018-2020 Matteo Croce <mcroce@microsoft.com>
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
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "common.h"

#include "kernel_traf.skel.h"
#include "kernel_drop.skel.h"

static int ifindex;

#define B 1000000000

#define human(x) decimals(x), rounded(x), suffix(x)
#define H ".*f %s"

static double rounded(uint64_t n)
{
	if (n >= 9999500000)
		return n / 1000000000.0;
	if (n >= 9999500)
		return n / 1000000.0;
	if (n > 9999)
		return n / 1000.0;
	return n;
}

static int decimals(uint64_t n)
{
	if (n >= 999950000000)
		return 0;
	if (n >= 99995000000)
		return 1;
	if (n >= 9999500000)
		return 2;
	if (n >= 999950000)
		return 0;
	if (n >= 99995000)
		return 1;
	if (n >= 9999500)
		return 2;
	if (n >= 999950)
		return 0;
	if (n >= 99995)
		return 1;
	if (n > 9999)
		return 2;
	return 0;
}

static char* suffix(uint64_t n)
{
	if (n >= 9999500000)
		return "G";
	if (n >= 9999500)
		return "M";
	if (n > 9999)
		return "K";
	return "";
}

static void int_exit(int sig)
{
        LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
	bpf_xdp_detach(ifindex, 0, &opts);
	exit(0);
}

static char *protocols[] = {
	[ALL] = "all",
	[BROADCAST] = "broadcast",
	[IPV4] = "IPv4",
	[IPV6] = "IPv6",
	[PPPOE] = "PPPoE",
	[ARP] = "ARP",
	[ICMP] = "ICMP",
	[TCP] = "TCP",
	[UDP] = "UDP",
	[SCTP] = "SCTP",
};

static uint64_t time_sub(struct timespec *since, struct timespec *to)
{
	if (to->tv_sec == since->tv_sec)
		return to->tv_nsec - since->tv_nsec;

	return (to->tv_sec - since->tv_sec) * B + to->tv_nsec - since->tv_nsec;
}

static void stats(int fd, useconds_t interval)
{
	unsigned int nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
	struct trafdata values[nr_cpus], tot[_MAX_PROTO] = { 0 };
	uint64_t deltat;
	int i;

	struct timespec oldts, newts;

	clock_gettime(CLOCK_MONOTONIC, &oldts);

	while (1) {
		unsigned key = 0;
                unsigned next_key = 0;

		usleep(interval);
		clock_gettime(CLOCK_MONOTONIC, &newts);
		deltat = time_sub(&oldts, &newts);

		while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
			struct trafdata sum = { 0 };

			bpf_map_lookup_elem(fd, &key, values);

			for (i = 0; i < nr_cpus; i++) {
				sum.packets += values[i].packets;
				sum.bytes += values[i].bytes;
			}
			if (sum.packets > tot[key].packets) {
				uint64_t pkts = (sum.packets - tot[key].packets) * B / deltat;
				uint64_t bytes = (sum.bytes - tot[key].bytes) * 8 * B / deltat;
				printf("%10s: %"H"pps %"H"bps\n",
				       protocols[key], human(pkts), human(bytes));
			}
			tot[key] = sum;
                        key = next_key;
		}
		oldts = newts;
	}
}

static void __attribute__ ((noreturn)) usage(char *argv0, int ret)
{
	fprintf(ret ? stderr : stdout, "usage: %s [-d] [-i interval] iface\n", argv0);
	exit(ret);
}

int main(int argc, char *argv[])
{
        LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
        struct kernel_drop *skel_drop = NULL;
        struct kernel_traf *skel_traf = NULL;
	int interval = 1000000, c;
	int fd;

	while ((c = getopt(argc, argv, "hi:d")) != -1)
		switch (c) {
		case 'h':
			usage(argv[0], 0);
			break;
		case 'i':
			interval = atof(optarg) * 1000000;
			break;
		case 'd':
                        skel_drop = kernel_drop__open_and_load();
                        if (!skel_drop) {
                                fprintf(stderr, "failed to open BPF object\n");
                                return 1;
                        }
			break;
		}

        if (!skel_drop) {
                skel_traf = kernel_traf__open_and_load();
                if (!skel_traf) {
                        fprintf(stderr, "failed to open BPF object\n");
                        return 1;
                }
        }

	if (optind != argc - 1)
		usage(argv[0], 1);

	ifindex = if_nametoindex(argv[optind]);
	if (!ifindex) {
		perror("if_nametoindex");
                return 1;
	}

	if (bpf_xdp_attach(ifindex,
                           bpf_program__fd(skel_drop ? skel_drop->progs.xdp_main : skel_traf->progs.xdp_main),
                           XDP_FLAGS_REPLACE, &opts) < 0) {
		printf("link set xdp fd failed\n");
		return 1;
	}

        fd = bpf_map__fd(skel_drop ? skel_drop->maps.traf : skel_traf->maps.traf);

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	stats(fd, interval);

	return 0;
}
