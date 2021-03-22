/*
 * drop all packets
 */

#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("prog")
int xdp_main(struct xdp_md *ctx)
{
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
