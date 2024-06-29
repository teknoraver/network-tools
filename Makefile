BPFS := kernel_traf.o kernel_drop.o
TOOLS := weed utraf bptraf xdperf
CFLAGS := -pipe -Wall -Wno-address-of-packed-member $(if $(DEBUG),-O0 -ggdb3,-O3)

all:: $(TOOLS) $(BPFS)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

kernel_%.o: kernel_%.c vmlinux.h
	clang -pipe -Wall -O2 -g -target bpf -c $< -o $@

kernel_%.skel.h: kernel_%.o
	bpftool gen skeleton $< > $@

weed: CFLAGS += -pthread

xdperf: LDLIBS += -lxdp -lbpf

bptraf: bptraf.c kernel_traf.skel.h kernel_drop.skel.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS) -lbpf

clean::
	$(RM) $(TOOLS) *.o vmlinux.h kernel_*_skel.h
