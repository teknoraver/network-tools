/*
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

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"

#define ETH_P_ARP       0x0806
#define ETH_P_IP        0x0800
#define ETH_P_IPV6      0x86DD
#define ETH_P_PPP_DISC  0x8863
#define ETH_P_PPP_SES   0x8864
#define IPPROTO_ICMP    1
#define IPPROTO_ICMPV6  58

/*
 * Sample XDP program, create statistics about interface traffic.
 * compile it with:
 * 	clang -g -O2 -Wall -ggdb3 -c kernel_traf.c -o - -emit-llvm | \
 * 		llc - -o kernel_traf.o -march=bpf -filetype=obj
 * attach it to a device with:
 * 	ip link set dev lo xdp object kernel.o verbose
 */

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, unsigned int);
	__type(value, struct trafdata);
	__uint(max_entries, _MAX_PROTO);
} traf SEC(".maps");

static void inc_stats(unsigned int key, int len)
{
	struct trafdata *val = bpf_map_lookup_elem(&traf, &key);

	if (val) {
		val->packets++;
		val->bytes += len;
	}
}

static enum protocols parse_eth(u16 type)
{
	switch (type) {
	case bpf_ntohs(ETH_P_ARP):
		return ARP;
	case bpf_ntohs(ETH_P_IP):
		return IPV4;
	case bpf_ntohs(ETH_P_IPV6):
		return IPV6;
	case bpf_ntohs(ETH_P_PPP_DISC):
	case bpf_ntohs(ETH_P_PPP_SES):
		return PPPOE;
	}

	return INVALID;
}

static enum protocols parse_ip(u8 proto)
{
	switch (proto) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		return ICMP;
	case IPPROTO_TCP:
		return TCP;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		return UDP;
	case IPPROTO_SCTP:
		return SCTP;
	}

	return INVALID;
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	void *data_end = (void *)(uintptr_t)ctx->data_end;
	void *data = (void *)(uintptr_t)ctx->data;
	enum protocols proto, ipproto = INVALID;
	size_t plen = data_end - data + 1;
	struct ethhdr *eth = data;
	u16 ethproto;

	/* sanity check needed by the eBPF verifier */
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	ethproto = eth->h_proto;

	inc_stats(ALL, plen);
	if (eth->h_dest[0] & 1)
		inc_stats(BROADCAST, plen);

	plen -= sizeof(*eth);

	proto = parse_eth(ethproto);
	if (proto != INVALID)
		inc_stats(proto, plen);

	switch (proto) {
	case IPV4: {
		struct iphdr *iph = (struct iphdr *)(eth + 1);

		if ((void *)(iph + 1) > data_end)
			break;

		ipproto = parse_ip(iph->protocol);
		plen -= sizeof(*iph);
		break;
	}
	case IPV6: {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);

		if ((void *)(ip6h + 1) > data_end)
			break;

		ipproto = parse_ip(ip6h->nexthdr);
		plen -= sizeof(*ip6h);
		break;
	}
	default:
		   break;
	}

	if (ipproto != INVALID)
		inc_stats(ipproto, plen);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
