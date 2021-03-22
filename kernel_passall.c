/*
 * pass all packets
 */

#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("prog")
int xdp_main(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
