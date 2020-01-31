KDIR ?= /lib/modules/$(shell uname -r)/build
BPFS := kernel_traf.o kernel_drop.o
TOOLS := weed utraf bptraf flooz
CFLAGS := -pipe -Wall -Wno-address-of-packed-member $(if $(DEBUG),-O0 -ggdb3,-O3)

all: $(TOOLS) $(BPFS)

$(KDIR)/tools/lib/bpf/libbpf.a:
	$(MAKE) -C $(KDIR)/tools/lib/bpf/

weed: CFLAGS += -pthread

flooz: CPPFLAGS += -I$(KDIR)/tools/lib
flooz: LDLIBS += -lelf -lz
flooz: $(KDIR)/tools/lib/bpf/libbpf.a

bptraf: CPPFLAGS += -I $(KDIR)/tools/lib
bptraf: LDLIBS += -lelf -lz
bptraf: $(KDIR)/tools/lib/bpf/libbpf.a

kernel_%.o: kernel_%.c
	clang -O2 -Wall -g3 -c $< -o - -emit-llvm |llc - -o $@ -march=bpf -filetype=obj

clean::
	$(RM) $(TOOLS) $(BPFS)
