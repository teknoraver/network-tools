/*
 * Sample XDP program, create statistics about interface traffic.
 * compile it with:
 * 	clang -O2 -Wall -ggdb3 -c kernel_drop.c -o - -emit-llvm | \
 * 		llc - -o kernel_drop.o -march=bpf -filetype=obj
 * attach it to a device with:
 * 	ip link set dev lo xdp object kernel.o verbose
 */

#include <stdint.h>
#include <linux/bpf.h>

#include "common.h"

#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
};

struct bpf_elf_map SEC("maps") traf = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.size_key = sizeof(unsigned int),
	.size_value = sizeof(struct trafdata),
	.max_elem = _MAX_PROTO,
};

static void *(*bpf_map_lookup_elem)(void *map, void *key) =
	(void *) BPF_FUNC_map_lookup_elem;

static void inc_stats(unsigned int key, int len)
{
	struct trafdata *val = bpf_map_lookup_elem(&traf, &key);

	if (val) {
		val->packets++;
		val->bytes += len;
	}
}

SEC("prog")
int xdp_main(struct xdp_md *ctx)
{
	void *data_end = (void *)(uintptr_t)ctx->data_end;
	void *data = (void *)(uintptr_t)ctx->data;

	inc_stats(ALL, data_end - data + 1);

	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
