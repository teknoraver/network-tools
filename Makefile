BPFS := kernel_traf.o kernel_drop.o kernel_dropall.o kernel_passall.o
TOOLS := weed utraf bptraf xdperf
CFLAGS := -pipe -Wall -Wno-address-of-packed-member $(if $(DEBUG),-O0 -ggdb3,-O3)

all: $(TOOLS) $(BPFS)

weed: CFLAGS += -pthread

xdperf: LDLIBS += -lbpf -lelf -lz

bptraf: LDLIBS += -lbpf -lelf -lz

kernel_%.o: kernel_%.c
	clang -g -O2 -Wall -c $< -o - -emit-llvm |llc - -o $@ -march=bpf -filetype=obj

clean::
	$(RM) $(TOOLS) $(BPFS)
