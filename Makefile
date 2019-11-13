KDIR ?= /lib/modules/$(shell uname -r)/build
TOOLS := weed utraf flooz
CFLAGS := -pipe -Wall -Wno-address-of-packed-member $(if $(DEBUG),-O0 -ggdb3,-O3)

all: $(TOOLS)

$(KDIR)/tools/lib/bpf/libbpf.a:
	$(MAKE) -C $(KDIR)/tools/lib/bpf/

weed: CFLAGS += -pthread

flooz: CPPFLAGS += -I$(KDIR)/tools/lib
flooz: LDLIBS += -lelf
flooz: $(KDIR)/tools/lib/bpf/libbpf.a

clean::
	$(RM) $(TOOLS)
