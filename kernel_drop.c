/*
 * Sample XDP program, create statistics about interface traffic.
 * compile it with:
 * 	clang -g -O2 -Wall -ggdb3 -c kernel_drop.c -o - -emit-llvm | \
 * 		llc - -o kernel_drop.o -march=bpf -filetype=obj
 * attach it to a device with:
 * 	ip link set dev lo xdp object kernel.o verbose
 */

#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "common.h"

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

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	void *data_end = (void *)(uintptr_t) ctx->data_end;
	void *data = (void *)(uintptr_t) ctx->data;

	inc_stats(ALL, data_end - data + 1);

	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
